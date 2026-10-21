"""Helm Chart Visualiser - HTTP server (stdlib only; PyYAML + pg8000 elsewhere).

UI / analysis
  GET  /                                  static UI
  POST /api/analyze                       body = .tgz/.tar.gz/.zip/.tar (X-Filename)
  GET  /api/sample                        bundled sample chart
  GET  /api/local, /api/local/analyze     charts in the mounted folder
  GET  /api/git?url=&ref=&path=           chart from a Git web address (X-Git-Token for private repos)
  GET  /api/compare?url=&path=&base=&head=   same chart at two refs: new / fixed findings
Common request headers: X-Release, X-Namespace, X-Kube-Version, X-Values (b64), X-Value-Files, X-Set (b64),
  X-Bypass: 1, X-No-Record: 1 (don't store this scan)

Catalog / history
  GET  /api/rules                         rules catalog + ruleset version + fail rates
  GET  /api/info                          build, Helm version, DB status, Grafana link
  GET  /api/history?limit=&repo=          recent scans (summaries only)
  GET  /api/stats                         totals + top failing rules (30 days)
  GET/POST /api/repos, POST /api/repos/<id>, POST /api/repos/<id>/run, DELETE /api/repos/<id>

Automation
  POST /api/scan    JSON {url, ref, path, kubeTarget, base, values, noRecord} -> compact summary (+ compare)
  GET  /metrics     Prometheus
  GET  /healthz
"""
import base64
import json
import os
import re
import shutil
import tempfile
import urllib.parse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

import db
import fixes
import deprecations
import gitsrc
import metrics
import rules
import service
from analyzer import analyse_chart_dir, extract_archive, AnalysisError

ROOT = Path(__file__).parent
STATIC = ROOT / "static"
SAMPLE = Path(os.environ.get("SAMPLE_CHART", ROOT.parent / "sample-chart"))
MAX_UPLOAD = int(os.environ.get("MAX_UPLOAD_MB", "20")) * 1024 * 1024
MAX_JSON = 256 * 1024
PORT = int(os.environ.get("PORT", "8080"))
CHARTS_DIR = Path(os.environ.get("CHARTS_DIR", "/charts"))
APP_VERSION = service.APP_VERSION


def list_local_charts():
    out = []
    if not CHARTS_DIR.is_dir():
        return out
    base = CHARTS_DIR.resolve()
    for dirpath, dirnames, filenames in os.walk(base):
        rel = Path(dirpath).relative_to(base)
        dirnames[:] = [d for d in sorted(dirnames) if not d.startswith(".") and d != "node_modules"]
        if len(rel.parts) >= 4:
            dirnames[:] = []
        if "Chart.yaml" in filenames:
            out.append({"path": rel.as_posix() or ".", "type": "folder"})
            dirnames[:] = []
            continue
        for f in sorted(filenames):
            if f.endswith((".tgz", ".tar.gz", ".zip", ".tar")):
                out.append({"path": (rel / f).as_posix(), "type": "archive"})
    return out[:500]


def resolve_local(p):
    base = CHARTS_DIR.resolve()
    target = (base / p).resolve()
    if target != base and not str(target).startswith(str(base) + os.sep):
        raise AnalysisError("path outside the charts folder")
    if not target.exists():
        raise AnalysisError(f"not found: {p}")
    return target


class Handler(SimpleHTTPRequestHandler):
    server_version = "helm-visualiser"
    sys_version = ""

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(STATIC), **kw)

    # --- helpers -------------------------------------------------------
    def _json(self, code, payload):
        body = json.dumps(payload, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, code, body, ctype="text/plain; version=0.0.4"):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store" if self.path.startswith(("/api", "/metrics")) else "no-cache")
        super().end_headers()

    def _q(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        return lambda k, d="": (q.get(k) or [d])[0][:2048]

    def _opts(self):
        """Analysis options from request headers."""
        h = self.headers
        try:
            ov = base64.b64decode(h.get("X-Values") or "").decode("utf-8")[:65536]
            sets = base64.b64decode(h.get("X-Set") or "").decode("utf-8").split("\n")
        except Exception:
            raise AnalysisError("could not decode values override")
        return dict(
            release=(h.get("X-Release") or "demo").strip()[:53] or "demo",
            namespace=(h.get("X-Namespace") or "default").strip()[:63] or "default",
            overrides=ov, value_files=[v for v in (h.get("X-Value-Files") or "").split(",") if v.strip()][:20],
            set_lines=[s.strip() for s in sets if s.strip()][:100], bypass=h.get("X-Bypass") == "1",
            kube_target=(h.get("X-Kube-Version") or "").strip() or None,
        )

    def _no_record(self):
        return self.headers.get("X-No-Record") == "1"

    def _body_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_JSON:
            raise AnalysisError("expected a JSON body")
        try:
            return json.loads(self.rfile.read(n))
        except ValueError:
            raise AnalysisError("invalid JSON")

    def _analyse(self, fn, source, trigger="ui"):
        """Run an analysis, record it, reply. `fn` returns the result dict."""
        try:
            result = fn()
            service.record(result, result.get("source") or source, trigger, self._no_record())
            return self._json(200, result)
        except service.Pick as p:
            return self._json(200, dict(pick=p.charts, source=p.source))
        except (gitsrc.GitError, AnalysisError) as e:
            service.record_error(source, trigger, e, self._no_record())
            return self._json(400, {"error": str(e)})
        except Exception as e:
            service.record_error(source, trigger, e, self._no_record())
            return self._json(500, {"error": f"unexpected error: {e}"})

    # --- GET -----------------------------------------------------------
    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        arg = self._q()
        if p == "/healthz":
            return self._json(200, {"ok": True})
        if p == "/metrics":
            return self._text(200, metrics.render(service.gauges()))
        if p == "/api/info":
            return self._json(200, self._info())
        if p == "/api/local":
            return self._json(200, dict(self._info(), dir=str(CHARTS_DIR), mounted=CHARTS_DIR.is_dir(), charts=list_local_charts()))
        if p == "/api/rules":
            out = dict(rules.catalog(), fixability={r["id"]: fixes.fixability(r["id"]) for r in rules._R}, info=self._info(), stats=None, statsError=None, live=metrics.snapshot())
            if db.STORE.enabled:
                try:
                    out["stats"] = db.STORE.stats()
                except Exception as e:
                    out["statsError"] = str(e)[:240]
            else:
                out["statsError"] = db.STORE.last_error or "scan history is off"
            return self._json(200, out)
        if p in ("/api/history", "/api/stats", "/api/repos"):
            if not db.STORE.enabled:
                return self._json(503, {"error": "scan history is off (no DATABASE_URL)"})
            try:
                if p == "/api/history":
                    return self._json(200, db.STORE.history(arg("limit", "50") or 50, arg("repo") or None))
                if p == "/api/stats":
                    return self._json(200, db.STORE.stats())
                return self._json(200, db.STORE.repos())
            except Exception as e:
                return self._json(503, {"error": f"database unavailable: {str(e)[:160]}"})
        if p == "/api/local/analyze":
            return self._local(arg("path"))
        if p == "/api/git":
            token = (self.headers.get("X-Git-Token") or "").strip()[:500]
            opts = self._opts()
            return self._analyse(lambda: service.git_analysis(arg("url"), arg("ref"), arg("path"), token, **opts),
                                 service.source_of(arg("url")))
        if p == "/api/compare":
            token = (self.headers.get("X-Git-Token") or "").strip()[:500]
            try:
                return self._json(200, service.git_compare(arg("url"), arg("base"), arg("head"), arg("path"), token, **self._opts()))
            except service.Pick as e:
                return self._json(400, {"error": "several charts in this repo: give a path"})
            except (gitsrc.GitError, AnalysisError) as e:
                return self._json(400, {"error": str(e)})
        if p == "/api/sample":
            opts = self._opts()
            return self._analyse(lambda: analyse_chart_dir(SAMPLE, **opts), dict(type="sample", repo="sample"))
        return super().do_GET()

    def _info(self):
        return dict(version=APP_VERSION, build=service.BUILD, helm=service.HELM_VERSION, ruleset=rules.RULESET,
                    kubeTargets=deprecations.TARGETS, kubeDefault=deprecations.DEFAULT_TARGET,
                    db=dict(enabled=db.STORE.enabled, up=db.STORE.up, retentionDays=db.RETENTION_DAYS,
                            error=(db.STORE.last_error if db.STORE.enabled and not db.STORE.up else "")),
                    grafana=service.GRAFANA_URL, gitHosts=gitsrc.ALLOWED_HOSTS, gitServerToken=bool(gitsrc.SERVER_TOKEN),
                    frequencies=list(db.FREQUENCIES), scheduler=service.SCHEDULER)

    def _local(self, path):
        opts = self._opts()

        def run():
            work = Path(tempfile.mkdtemp(prefix="chart-"))
            try:
                target = resolve_local(path)
                if target.is_dir():
                    chart_dir = work / target.name
                    shutil.copytree(target, chart_dir, ignore=shutil.ignore_patterns(".git", "node_modules"))
                else:
                    chart_dir = extract_archive(target.read_bytes(), target.name, work)
                r = analyse_chart_dir(chart_dir, **opts)
                r["source"] = dict(type="local", repo="local", path=None)
                return r
            finally:
                shutil.rmtree(work, ignore_errors=True)
        return self._analyse(run, dict(type="local", repo="local"))

    # --- POST / DELETE -------------------------------------------------
    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path
        if p == "/api/analyze":
            return self._upload()
        if p == "/api/scan":
            return self._api_scan()
        if p == "/api/fixplan":
            return self._fixplan()
        m = re.fullmatch(r"/api/repos(?:/(\d+))?(/run)?", p)
        if m:
            return self._repos_write(m.group(1), bool(m.group(2)))
        return self._json(404, {"error": "not found"})

    def do_DELETE(self):
        m = re.fullmatch(r"/api/repos/(\d+)", urllib.parse.urlparse(self.path).path)
        if not m:
            return self._json(404, {"error": "not found"})
        try:
            db.STORE.delete_repo(m.group(1))
            return self._json(200, {"ok": True})
        except Exception as e:
            return self._json(503, {"error": str(e)[:200]})

    def _upload(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return self._json(400, {"error": "empty upload"})
        if length > MAX_UPLOAD:
            return self._json(413, {"error": f"upload larger than {MAX_UPLOAD // 1048576} MB"})
        data = self.rfile.read(length)
        name = self.headers.get("X-Filename") or "chart.tgz"
        opts = self._opts()

        def run():
            work = Path(tempfile.mkdtemp(prefix="chart-"))
            try:
                r = analyse_chart_dir(extract_archive(data, name, work), **opts)
                r["source"] = dict(type="upload", repo="upload", path=None)   # never the file name
                return r
            finally:
                shutil.rmtree(work, ignore_errors=True)
        return self._analyse(run, dict(type="upload", repo="upload"))

    def _api_scan(self):
        """JSON API: scan a Git chart (optionally compare with a base ref) and return a compact summary."""
        try:
            b = self._body_json()
            url = str(b.get("url") or "")
            token = (self.headers.get("X-Git-Token") or "").strip()[:500]
            opts = dict(release=str(b.get("release") or "demo")[:53], namespace=str(b.get("namespace") or "default")[:63],
                        overrides=str(b.get("values") or "")[:65536], set_lines=[str(x) for x in (b.get("set") or [])][:100],
                        value_files=[str(x) for x in (b.get("valueFiles") or [])][:20], bypass=bool(b.get("bypass")),
                        kube_target=b.get("kubeTarget"))
            r = service.git_analysis(url, str(b.get("ref") or ""), str(b.get("path") or ""), token, **opts)
            service.record(r, r["source"], "api", bool(b.get("noRecord")))
            out = service.api_summary(r)
            if b.get("base"):
                out["compare"] = service.git_compare(url, str(b["base"]), str(b.get("ref") or ""), r["source"]["path"], token, **opts)
            if b.get("failUnder") is not None:
                out["pass"] = (r.get("score") or 0) >= int(b["failUnder"]) and not r.get("renderError")
            return self._json(200, out)
        except service.Pick as p:
            return self._json(400, {"error": "several charts in this repo: set `path`", "charts": p.charts})
        except (gitsrc.GitError, AnalysisError, ValueError) as e:
            return self._json(400, {"error": str(e)})
        except Exception as e:
            return self._json(500, {"error": f"unexpected error: {e}"})

    def _fixplan(self):
        """Fix planner: preview selected fixes on the rendered chart + build the Claude prompt."""
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_UPLOAD + 5 * 1024 * 1024:
            return self._json(413, {"error": "plan request too large"})
        try:
            b = json.loads(self.rfile.read(n))
            files = {str(k): str(v) for k, v in (b.get("files") or {}).items() if isinstance(v, str)}
            rule_ids = [str(x) for x in (b.get("rules") or [])][:80]
            if not rule_ids:
                return self._json(400, {"error": "pick at least one rule"})
            out = fixes.plan(files, str(b.get("rendered") or ""), rule_ids, str(b.get("release") or "demo")[:53],
                             str(b.get("namespace") or "default")[:63], b.get("kubeTarget"), b.get("source"))
            metrics.inc("helmviz_fixplans_total", rules=str(len(rule_ids)))
            return self._json(200, out)
        except (AnalysisError, ValueError) as e:
            return self._json(400, {"error": str(e)})
        except Exception as e:
            return self._json(500, {"error": f"unexpected error: {e}"})

    def _repos_write(self, rid, run):
        if not db.STORE.enabled:
            return self._json(503, {"error": "watching repos needs the scan-history database"})
        try:
            if rid and run:
                db.STORE.run_now(rid)
                return self._json(200, {"ok": True, "queued": True})
            b = self._body_json()
            if rid:
                db.STORE.update_repo(rid, b.get("frequency"), b.get("enabled"))
                return self._json(200, {"ok": True})
            url = str(b.get("url") or "")
            gitsrc.parse_url(url, str(b.get("ref") or ""), str(b.get("path") or ""))   # validate early
            new_id = db.STORE.add_repo(url, str(b.get("ref") or ""), str(b.get("path") or ""), str(b.get("frequency") or "daily"),
                                       b.get("kubeTarget"))
            return self._json(200, {"ok": True, "id": new_id})
        except (gitsrc.GitError, AnalysisError, ValueError) as e:
            return self._json(400, {"error": str(e)})
        except Exception as e:
            return self._json(503, {"error": f"database unavailable: {str(e)[:160]}"})

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)


if __name__ == "__main__":
    service.start_background()
    print(f"Helm visualiser v{APP_VERSION} listening on :{PORT} (helm {service.HELM_VERSION}, ruleset {rules.RULESET['version']})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
