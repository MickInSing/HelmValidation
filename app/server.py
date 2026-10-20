"""Helm Chart Visualiser - tiny HTTP server.

Endpoints
  GET  /                -> static UI
  POST /api/analyze     -> body = raw .tgz / .tar.gz / .zip chart archive
                           headers: X-Filename, X-Release, X-Namespace
  GET  /api/sample      -> analyse the bundled sample chart
  GET  /healthz         -> ok

Stdlib only (plus PyYAML in analyzer.py) so the image stays small.
"""
import base64
import json
import os
import urllib.parse
import shutil
import tempfile
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

from analyzer import analyse_chart_dir, extract_archive, AnalysisError

ROOT = Path(__file__).parent
STATIC = ROOT / "static"
SAMPLE = Path(os.environ.get("SAMPLE_CHART", ROOT.parent / "sample-chart"))
MAX_UPLOAD = int(os.environ.get("MAX_UPLOAD_MB", "20")) * 1024 * 1024
PORT = int(os.environ.get("PORT", "8080"))
CHARTS_DIR = Path(os.environ.get("CHARTS_DIR", "/charts"))
APP_VERSION = "6"


def list_local_charts():
    """Chart folders (containing Chart.yaml) and chart archives under CHARTS_DIR, up to 4 levels deep."""
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
            dirnames[:] = []  # don't list a chart's own sub-charts separately
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
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def end_headers(self):
        # A little defence-in-depth for the UI itself.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-cache")  # always pick up a rebuilt UI
        super().end_headers()

    def _opts(self):
        rel = (self.headers.get("X-Release") or "demo").strip()[:53] or "demo"
        ns = (self.headers.get("X-Namespace") or "default").strip()[:63] or "default"
        return rel, ns

    def _values(self):
        """Overrides travel base64-encoded in headers so the body can stay the raw archive."""
        try:
            ov = base64.b64decode(self.headers.get("X-Values") or "").decode("utf-8")[:65536]
        except Exception:
            raise AnalysisError("could not decode values override")
        vf = [v for v in (self.headers.get("X-Value-Files") or "").split(",") if v.strip()][:20]
        try:
            sets = base64.b64decode(self.headers.get("X-Set") or "").decode("utf-8").split("\n")
        except Exception:
            sets = []
        sets = [s.strip() for s in sets if s.strip()][:100]
        return dict(overrides=ov, value_files=vf, set_lines=sets, bypass=self.headers.get("X-Bypass") == "1")

    # --- routes --------------------------------------------------------
    def do_GET(self):
        if self.path == "/healthz":
            return self._json(200, {"ok": True})
        if self.path == "/api/local":
            return self._json(200, {"dir": str(CHARTS_DIR), "mounted": CHARTS_DIR.is_dir(),
                                    "charts": list_local_charts(), "version": APP_VERSION})
        if self.path.startswith("/api/local/analyze"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            rel, ns = self._opts()
            work = Path(tempfile.mkdtemp(prefix="chart-"))
            try:
                target = resolve_local((q.get("path") or [""])[0])
                if target.is_dir():
                    # copy so helm dependency build never writes into the read-only mount
                    chart_dir = work / target.name
                    shutil.copytree(target, chart_dir, ignore=shutil.ignore_patterns(".git", "node_modules"))
                else:
                    chart_dir = extract_archive(target.read_bytes(), target.name, work)
                return self._json(200, analyse_chart_dir(chart_dir, rel, ns, **self._values()))
            except AnalysisError as e:
                return self._json(400, {"error": str(e)})
            except Exception as e:
                return self._json(500, {"error": f"unexpected error: {e}"})
            finally:
                shutil.rmtree(work, ignore_errors=True)
        if self.path.startswith("/api/sample"):
            rel, ns = self._opts()
            try:
                return self._json(200, analyse_chart_dir(SAMPLE, rel, ns, **self._values()))
            except AnalysisError as e:
                return self._json(400, {"error": str(e)})
        return super().do_GET()

    def do_POST(self):
        if self.path != "/api/analyze":
            return self._json(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return self._json(400, {"error": "empty upload"})
        if length > MAX_UPLOAD:
            return self._json(413, {"error": f"upload larger than {MAX_UPLOAD // 1048576} MB"})
        data = self.rfile.read(length)
        name = self.headers.get("X-Filename") or "chart.tgz"
        rel, ns = self._opts()
        work = Path(tempfile.mkdtemp(prefix="chart-"))
        try:
            chart_dir = extract_archive(data, name, work)
            return self._json(200, analyse_chart_dir(chart_dir, rel, ns, **self._values()))
        except AnalysisError as e:
            return self._json(400, {"error": str(e)})
        except Exception as e:  # pragma: no cover - surface unexpected errors to the UI
            return self._json(500, {"error": f"unexpected error: {e}"})
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)


if __name__ == "__main__":
    print(f"Helm visualiser listening on :{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
