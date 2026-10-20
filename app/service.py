"""Scan orchestration shared by the HTTP server, the scheduler and the JSON API."""
import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import compare
import db
import gitsrc
import metrics
from analyzer import AnalysisError, analyse_chart_dir

APP_VERSION = "10"
BUILD = dict(version=APP_VERSION, gitSha=os.environ.get("GIT_SHA", "dev")[:12], buildDate=os.environ.get("BUILD_DATE", ""))
GRAFANA_URL = os.environ.get("GRAFANA_URL", "")
SCHEDULER = os.environ.get("SCHEDULER", "on") != "off"


def _helm_version():
    try:
        out = subprocess.run([os.environ.get("HELM_BIN", "helm"), "version", "--short"], capture_output=True, text=True, timeout=10).stdout
        return out.strip().split("+")[0] or "unknown"
    except Exception:
        return "unknown"


HELM_VERSION = _helm_version()


class Pick(Exception):
    """Several charts in the repo: the caller must choose one."""
    def __init__(self, charts, source):
        super().__init__("pick a chart")
        self.charts, self.source = charts, source


def git_analysis(url, ref="", path="", token="", **opts):
    """Fetch + analyse a chart from Git. Raises Pick when the repo has several charts."""
    work = Path(tempfile.mkdtemp(prefix="chart-"))
    try:
        clone, ref, path, display = gitsrc.parse_url(url, ref, path)
        try:
            repo = gitsrc.fetch(clone, ref, token)
            metrics.inc("helmviz_git_fetch_total", result="ok")
        except gitsrc.GitError:
            metrics.inc("helmviz_git_fetch_total", result="error")
            raise
        source = dict(type="git", repo=display, url=url, clone=clone, ref=repo["ref"], commit=repo["commit"], path=path)
        target = gitsrc.resolve_chart(repo["dir"], path)
        if not (target / "Chart.yaml").exists():
            charts = gitsrc.find_charts(target)
            if not charts:
                raise gitsrc.GitError(f"no Chart.yaml found in {display}{'/' + path if path else ''}")
            if len(charts) > 1:
                prefix = (path + "/") if path else ""
                raise Pick([prefix + c if c != "." else path for c in charts], source)
            path = ((path + "/") if path else "") + charts[0]
            source["path"] = path
            target = gitsrc.resolve_chart(repo["dir"], path)
        # repo-root exceptions file applies to every chart in the repo
        root_exc = Path(repo["dir"]) / ".helm-visualiser.yaml"
        repo_exc = root_exc.read_text(errors="replace") if root_exc.is_file() and path else None
        # never analyse inside the cache: copy. Charts with file:// dependencies need their siblings too.
        if "file://" in (target / "Chart.yaml").read_text(errors="replace"):
            shutil.copytree(repo["dir"], work / "repo")
            chart_dir = work / "repo" / path if path else work / "repo"
        else:
            chart_dir = work / (target.name or "chart")
            shutil.copytree(target, chart_dir)
        result = analyse_chart_dir(chart_dir, repo_exceptions=repo_exc, **opts)
        result["source"] = source
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)


def record(result, source, trigger, no_record=False):
    """Metrics always; DB row unless opted out. Adds scanId/recorded to the result."""
    status = "render_failed" if result.get("renderError") else "ok"
    metrics.inc("helmviz_scans_total", status=status, source=source.get("type", "?"), trigger=trigger)
    metrics.observe("helmviz_scan_duration_seconds", (result.get("durationMs") or 0) / 1000)
    for sev, n in (result.get("counts") or {}).items():
        if n:
            metrics.inc("helmviz_findings_total", n, severity=sev)
    for rid in {f.get("rule") for f in result.get("findings", []) if f.get("rule") and not f.get("accepted")}:
        metrics.inc("helmviz_rule_scans_total", rule=rid)
    result["recorded"] = False
    if no_record or not db.STORE.enabled:
        return None
    sid = db.STORE.record(db.summarize(result, source, trigger, APP_VERSION, HELM_VERSION))
    metrics.inc("helmviz_db_writes_total", result="ok" if sid else "error")
    result["scanId"], result["recorded"] = sid, bool(sid)
    return sid


def record_error(source, trigger, err, no_record=False):
    metrics.inc("helmviz_scans_total", status="error", source=source.get("type", "?"), trigger=trigger)
    if not no_record and db.STORE.enabled:
        db.STORE.record(db.error_row(source, trigger, err, APP_VERSION, HELM_VERSION))


def source_of(url):
    try:
        _, _, path, display = gitsrc.parse_url(url)
        return dict(type="git", repo=display, path=path)
    except gitsrc.GitError:
        return dict(type="git", repo="(invalid address)")


def git_compare(url, base, head, path="", token="", **opts):
    """Analyse the same chart at two refs and diff them."""
    b = git_analysis(url, base, path, token, **opts)
    h = git_analysis(url, head, b["source"]["path"], token, **opts)
    d = compare.diff(b, h)
    d["baseRef"], d["headRef"] = dict(ref=b["source"]["ref"], commit=b["source"]["commit"]), dict(ref=h["source"]["ref"], commit=h["source"]["commit"])
    d["path"] = b["source"]["path"]
    d["markdown"] = compare.markdown(d, f"{b['chart'].get('name')}: {b['source']['ref']} → {h['source']['ref']}",
                                     h["source"]["ref"], b["source"]["ref"])
    return d


def api_summary(result):
    """Compact JSON for the API / CI: no file contents."""
    res = {r["id"]: f"{r['kind']}/{r['name']}" for r in result.get("resources", [])}
    return dict(
        chart=result.get("chart"), source=result.get("source"), score=result.get("score"), counts=result.get("counts"),
        accepted=result.get("accepted"), renderError=result.get("renderError") or None, ruleset=result.get("ruleset"),
        kubeTarget=result.get("kubeTarget"), scanId=result.get("scanId"),
        findings=[dict(rule=f.get("rule"), severity=f["sev"], title=f["title"], resource=res.get(f.get("resource")),
                       file=(f.get("tpl") or {}).get("file"), line=(f.get("tpl") or {}).get("line"),
                       accepted=bool(f.get("accepted"))) for f in result.get("findings", [])],
        externals=[dict(category=x["category"], label=x["label"]) for x in result.get("externals", [])],
        resources=sorted(res.values()),
    )


# ------------------------------------------------------------------------------------------- scheduler
def _scheduler_loop():
    while True:
        time.sleep(30)
        if not db.STORE.enabled:
            continue
        try:
            job = db.STORE.claim_due()
        except Exception:
            continue
        if not job:
            continue
        src = source_of(job["url"])
        try:
            r = git_analysis(job["url"], job["ref"], job["path"], "", kube_target=job.get("kube_target"))
            sid = record(r, r["source"], "schedule")
            db.STORE.finish_repo(job["id"], sid, "render_failed" if r.get("renderError") else "ok", r.get("score"),
                                 db.classify(r.get("renderError")) if r.get("renderError") else None)
            metrics.inc("helmviz_scheduled_runs_total", result="ok")
        except Pick as p:
            db.STORE.finish_repo(job["id"], None, "error", None, "needs-chart-path")
            metrics.inc("helmviz_scheduled_runs_total", result="error")
        except Exception as e:
            record_error(src, "schedule", e)
            try:
                db.STORE.finish_repo(job["id"], None, "error", None, db.classify(str(e)))
            except Exception:
                pass
            metrics.inc("helmviz_scheduled_runs_total", result="error")


def start_background():
    if db.STORE.enabled:
        ok = db.STORE.migrate()
        print(f"scan history: {'connected' if ok else 'unavailable: ' + db.STORE.last_error}", flush=True)
    else:
        print(f"scan history: off ({db.STORE.last_error})", flush=True)
    if SCHEDULER:
        threading.Thread(target=_scheduler_loop, name="scheduler", daemon=True).start()


def gauges():
    g = [("helmviz_build_info", "Build information", 1, dict(version=APP_VERSION, git_sha=BUILD["gitSha"], helm=HELM_VERSION,
                                                                  ruleset=__import__("rules").RULESET["version"])),
         ("helmviz_db_up", "1 if the scan-history database is reachable", 1 if db.STORE.up else 0, {})]
    if db.STORE.enabled:
        try:
            g.append(("helmviz_watched_repos", "Registered repositories", len([r for r in db.STORE.repos() if r["enabled"]]), {}))
        except Exception:
            pass
    return g
