"""Prometheus metrics (text exposition format, no client library needed)."""
import threading
import time

_lock = threading.Lock()
_counters = {}     # (name, labels-tuple) -> value
_hist = {}         # (name, labels-tuple) -> [bucket counts..., sum, count]
BUCKETS = (0.25, 0.5, 1, 2, 5, 10, 20, 30, 60, 120)
START = time.time()

HELP = {
    "helmviz_scans_total": ("counter", "Chart scans by status, source and trigger"),
    "helmviz_findings_total": ("counter", "Findings reported, by severity (accepted findings excluded)"),
    "helmviz_git_fetch_total": ("counter", "Git fetches by result"),
    "helmviz_db_writes_total": ("counter", "Scan-history writes by result"),
    "helmviz_scheduled_runs_total": ("counter", "Scheduled rescans by result"),
    "helmviz_scan_duration_seconds": ("histogram", "Time to analyse a chart"),
}


def inc(name, value=1, **labels):
    key = (name, tuple(sorted(labels.items())))
    with _lock:
        _counters[key] = _counters.get(key, 0) + value


def observe(name, seconds, **labels):
    key = (name, tuple(sorted(labels.items())))
    with _lock:
        h = _hist.setdefault(key, [0] * len(BUCKETS) + [0.0, 0])
        for i, b in enumerate(BUCKETS):
            if seconds <= b:
                h[i] += 1
        h[-2] += seconds
        h[-1] += 1


def _lbl(pairs, extra=()):
    items = list(pairs) + list(extra)
    if not items:
        return ""
    esc = lambda v: str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
    return "{" + ",".join(f'{k}="{esc(v)}"' for k, v in items) + "}"


def render(gauges):
    """gauges: list of (name, help, value, labels-dict)."""
    out, seen = [], set()
    with _lock:
        for (name, labels), v in sorted(_counters.items()):
            if name not in seen:
                t, h = HELP.get(name, ("counter", name))
                out += [f"# HELP {name} {h}", f"# TYPE {name} {t}"]
                seen.add(name)
            out.append(f"{name}{_lbl(labels)} {v}")
        for (name, labels), h in sorted(_hist.items()):
            if name not in seen:
                out += [f"# HELP {name} {HELP.get(name, ('', name))[1]}", f"# TYPE {name} histogram"]
                seen.add(name)
            for i, b in enumerate(BUCKETS):
                out.append(f"{name}_bucket{_lbl(labels, [('le', b)])} {h[i]}")
            out.append(f"{name}_bucket{_lbl(labels, [('le', '+Inf')])} {h[-1]}")
            out.append(f"{name}_sum{_lbl(labels)} {round(h[-2], 4)}")
            out.append(f"{name}_count{_lbl(labels)} {h[-1]}")
    for name, help_, value, labels in gauges:
        out += [f"# HELP {name} {help_}", f"# TYPE {name} gauge", f"{name}{_lbl(sorted(labels.items()))} {value}"]
    out += ["# HELP helmviz_uptime_seconds Seconds since start", "# TYPE helmviz_uptime_seconds gauge",
            f"helmviz_uptime_seconds {int(time.time() - START)}"]
    return "\n".join(out) + "\n"
