"""Command-line scanner for CI / pull requests (runs inside the same image: helm + git + rules).

  python /app/app/cli.py scan --head ./pr --base ./main [--charts-dir charts] [--kube 1.36]
         [--format markdown|json] [--out comment.md] [--fail-under 70] [--fail-on-new high]

--head / --base are checkouts of the PR and its base branch. Every chart under --charts-dir (default: whole
repo) is scanned in both and diffed. Exit code 1 if a threshold is broken, 0 otherwise.
"""
import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import compare  # noqa: E402
import gitsrc  # noqa: E402
from analyzer import AnalysisError, analyse_chart_dir  # noqa: E402

SEVS = ["critical", "high", "medium", "low", "info"]


def _scan(root, rel, kube, repo_exc):
    d = Path(root) / rel
    if not (d / "Chart.yaml").is_file():
        return None
    work = Path(tempfile.mkdtemp(prefix="cli-"))
    try:
        if "file://" in (d / "Chart.yaml").read_text(errors="replace"):
            shutil.copytree(root, work / "repo", ignore=shutil.ignore_patterns(".git"))
            target = work / "repo" / rel
        else:
            target = work / (d.name or "chart")
            shutil.copytree(d, target, ignore=shutil.ignore_patterns(".git"))
        return analyse_chart_dir(target, kube_target=kube, repo_exceptions=repo_exc)
    except AnalysisError as e:
        return dict(renderError=str(e), findings=[], resources=[], score=0, counts={}, chart={"name": rel})
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="helm-visualiser")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--head", required=True, help="checkout of the branch to check (PR head)")
    s.add_argument("--base", help="checkout of the base branch to compare against")
    s.add_argument("--charts-dir", default=".", help="where to look for charts, relative to the checkout")
    s.add_argument("--kube", default=None, help="target Kubernetes version for the deprecated-API check")
    s.add_argument("--format", choices=["markdown", "json"], default="markdown")
    s.add_argument("--out", help="write the report here as well as stdout")
    s.add_argument("--fail-under", type=int, help="fail if any chart scores below this")
    s.add_argument("--fail-on-new", choices=SEVS, help="fail if the PR introduces findings at or above this severity")
    a = ap.parse_args(argv)

    head = Path(a.head).resolve()
    rels = sorted({os.path.normpath(os.path.join(a.charts_dir, c)) for c in gitsrc.find_charts(head / a.charts_dir)})
    if not rels:
        print("No charts found.", file=sys.stderr)
        return 0
    exc = lambda root: (Path(root) / ".helm-visualiser.yaml").read_text() if (Path(root) / ".helm-visualiser.yaml").is_file() else None

    report, failed, md = [], [], []
    for rel in rels:
        h = _scan(head, rel, a.kube, exc(head))
        b = _scan(Path(a.base).resolve(), rel, a.kube, exc(a.base)) if a.base else None
        name = (h.get("chart") or {}).get("name") or rel
        if b is None:  # new chart: compare with nothing
            b = dict(findings=[], resources=[], score=h.get("score"), counts={}, renderError=None)
        d = compare.diff(b, h)
        entry = dict(chart=name, path=rel, score=h.get("score"), counts=h.get("counts"), renderError=bool(h.get("renderError")),
                     ruleset=h.get("ruleset"), new=d["new"], fixed=d["fixed"], scoreDelta=d["scoreDelta"], baseScore=d["base"]["score"])
        report.append(entry)
        md.append(compare.markdown(d, f"`{rel}`: {name}", "this PR", "base" if a.base else "(new chart)"))
        if a.fail_under is not None and ((h.get("score") or 0) < a.fail_under or h.get("renderError")):
            failed.append(f"{rel}: score {h.get('score')} < {a.fail_under}" + (" (render failed)" if h.get("renderError") else ""))
        if a.fail_on_new:
            lim = SEVS.index(a.fail_on_new)
            bad = [f for f in d["new"] if f["sev"] in SEVS and SEVS.index(f["sev"]) <= lim]
            if bad:
                failed.append(f"{rel}: {len(bad)} new finding(s) at {a.fail_on_new} or above")

    if a.format == "json":
        text = json.dumps(dict(charts=report, failed=failed), indent=2)
    else:
        rs = report[0].get("ruleset") if report else ""
        text = "## 🔍 Helm chart check\n\n" + "\n---\n".join(md) + \
               (f"\n**❌ Check failed:**\n" + "\n".join(f"- {x}" for x in failed) + "\n" if failed else "\n✅ All thresholds met.\n") + \
               f"\n<sub>helm-visualiser · ruleset {rs} · accepted exceptions come from `.helm-visualiser.yaml`</sub>\n"
    print(text)
    if a.out:
        Path(a.out).write_text(text)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
