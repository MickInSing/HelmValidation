"""Scan history in Postgres (optional: everything works without DATABASE_URL).

PRIVACY: only summaries are stored. Never file contents, values, rendered YAML, resource names,
hostnames, env vars, tokens or raw error text (Helm errors can echo values back). Errors are reduced
to a class. Uploads are recorded as "upload" with the chart name only.
"""
import os
import re
import ssl
import threading
import time
import urllib.parse

try:
    import pg8000.native as pg
except ImportError:  # local dev without the driver
    pg = None

DATABASE_URL = os.environ.get("DATABASE_URL", "")
RETENTION_DAYS = int(os.environ.get("SCAN_RETENTION_DAYS", "180"))
FREQUENCIES = {"hourly": "1 hour", "6h": "6 hours", "daily": "1 day", "weekly": "7 days"}

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS schema_version (version int PRIMARY KEY, applied_at timestamptz DEFAULT now())""",
    """CREATE TABLE IF NOT EXISTS scans (
        id bigserial PRIMARY KEY,
        scanned_at timestamptz NOT NULL DEFAULT now(),
        trigger text NOT NULL,              -- ui | api | schedule | pr
        source_type text NOT NULL,          -- git | upload | local | sample
        repo text NOT NULL,                 -- host/org/repo, or 'upload' / 'local' / 'sample'
        ref text, commit text, chart_path text,
        chart_name text, chart_version text, app_version text,
        status text NOT NULL,               -- ok | render_failed | error
        error_class text,
        duration_ms int,
        resources int, score int,
        n_critical int DEFAULT 0, n_high int DEFAULT 0, n_medium int DEFAULT 0, n_low int DEFAULT 0, n_info int DEFAULT 0,
        n_accepted int DEFAULT 0,
        used_placeholders boolean DEFAULT false,
        kube_target text, ruleset_version text, tool_version text, helm_version text
    )""",
    "CREATE INDEX IF NOT EXISTS scans_repo_time ON scans (repo, scanned_at DESC)",
    "CREATE INDEX IF NOT EXISTS scans_time ON scans (scanned_at DESC)",
    """CREATE TABLE IF NOT EXISTS scan_rules (
        scan_id bigint REFERENCES scans(id) ON DELETE CASCADE,
        rule_id text NOT NULL, category text, severity text, resource_kind text, accepted boolean DEFAULT false, count int NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS scan_rules_scan ON scan_rules (scan_id)",
    "CREATE INDEX IF NOT EXISTS scan_rules_rule ON scan_rules (rule_id)",
    """CREATE TABLE IF NOT EXISTS scan_dependencies (
        scan_id bigint REFERENCES scans(id) ON DELETE CASCADE, category text, label text
    )""",
    """CREATE TABLE IF NOT EXISTS scan_apis (
        scan_id bigint REFERENCES scans(id) ON DELETE CASCADE, api_version text, kind text, count int
    )""",
    """CREATE TABLE IF NOT EXISTS repos (
        id serial PRIMARY KEY,
        url text NOT NULL, ref text DEFAULT '', path text DEFAULT '',
        frequency text NOT NULL DEFAULT 'daily', enabled boolean NOT NULL DEFAULT true,
        kube_target text,
        created_at timestamptz DEFAULT now(),
        next_run_at timestamptz DEFAULT now(),
        last_scan_at timestamptz, last_scan_id bigint, last_status text, last_score int, last_error_class text,
        UNIQUE (url, ref, path)
    )""",
    "INSERT INTO schema_version (version) VALUES (1) ON CONFLICT DO NOTHING",
]


# ----------------------------------------------------------------------------------------------- errors
ERROR_CLASSES = [
    ("needs-values", r"\bfail\b|required|must be set|execution error at"),
    ("missing-dependency", r"found in Chart\.yaml, but missing in charts/|dependency|chart\(s\) not found|no repository definition"),
    ("yaml-error", r"YAML parse error|yaml: |error converting YAML|mapping values are not allowed"),
    ("template-error", r"parse error|function .* not defined|template: |nil pointer|can't evaluate field|wrong type"),
    ("schema-error", r"values don't meet the specifications of the schema"),
    ("git-auth", r"Authentication failed|could not read Username|\b40[13]\b|private"),
    ("git-not-found", r"couldn't find remote ref|not found|isn't a folder|no Chart\.yaml"),
    ("timeout", r"timed out"),
    ("too-large", r"larger than|too large"),
    ("bad-input", r"not a \.tgz|unsafe path|isn't allowed|only https|invalid "),
]


def classify(text):
    t = text or ""
    for cls, rx in ERROR_CLASSES:
        if re.search(rx, t, re.I):
            return cls
    return "other" if t else None


# ----------------------------------------------------------------------------------------------- summary
def summarize(result, source, trigger, tool_version="", helm_version=""):
    """Turn an analysis result into a privacy-safe row. `source` is dict(type, repo, ref, commit, path)."""
    st = "render_failed" if result.get("renderError") else "ok"
    c = result.get("counts") or {}
    rules_agg = {}
    kinds = {r["id"]: r["kind"] for r in result.get("resources", [])}
    for f in result.get("findings", []):
        if not f.get("rule"):
            continue
        k = (f["rule"], f.get("category"), f["sev"], kinds.get(f.get("resource")), bool(f.get("accepted")))
        rules_agg[k] = rules_agg.get(k, 0) + 1
    apis = {}
    for r in result.get("resources", []):
        k = (r.get("apiVersion"), r["kind"])
        apis[k] = apis.get(k, 0) + 1
    ch = result.get("chart") or {}
    return dict(
        trigger=trigger, source_type=source.get("type", "upload"), repo=source.get("repo") or source.get("type", "upload"),
        ref=source.get("ref") or None, commit=source.get("commit") or None, chart_path=source.get("path") or None,
        chart_name=_s(ch.get("name")), chart_version=_s(ch.get("version")), app_version=_s(ch.get("appVersion")),
        status=st, error_class=classify(result.get("renderError")) if st != "ok" else None,
        duration_ms=result.get("durationMs"), resources=len(result.get("resources", [])), score=result.get("score"),
        n_critical=c.get("critical", 0), n_high=c.get("high", 0), n_medium=c.get("medium", 0), n_low=c.get("low", 0), n_info=c.get("info", 0),
        n_accepted=result.get("accepted", 0), used_placeholders=bool(result.get("bypass")),
        kube_target=result.get("kubeTarget"), ruleset_version=result.get("ruleset"), tool_version=tool_version, helm_version=helm_version,
        _rules=[dict(rule_id=k[0], category=k[1], severity=k[2], resource_kind=k[3], accepted=k[4], count=v) for k, v in rules_agg.items()],
        _deps=[dict(category=x["category"], label=_dep_label(x)) for x in result.get("externals", [])],
        _apis=[dict(api_version=k[0], kind=k[1], count=v) for k, v in apis.items()],
    )


def error_row(source, trigger, err, tool_version="", helm_version=""):
    return dict(trigger=trigger, source_type=source.get("type", "upload"), repo=source.get("repo") or source.get("type", "upload"),
                ref=source.get("ref") or None, commit=source.get("commit") or None, chart_path=source.get("path") or None,
                status="error", error_class=classify(str(err)), tool_version=tool_version, helm_version=helm_version,
                _rules=[], _deps=[], _apis=[])


def _s(v):
    return None if v is None else str(v)[:120]


def _dep_label(x):
    # "Secret strudel-creds" -> "Secret (pre-existing)": no resource names in the DB
    if x["category"] == "existing":
        return x["label"].split(" ")[0] + " (pre-existing)"
    return x["label"][:80]


# ----------------------------------------------------------------------------------------------- store
class Store:
    def __init__(self, url=DATABASE_URL):
        self.url = url
        self.enabled = bool(url) and pg is not None
        self.lock = threading.Lock()
        self.con = None
        self.up = False
        self.last_error = "" if self.enabled else ("DATABASE_URL not set" if not url else "pg8000 not installed")
        self._last_cleanup = 0

    # connection ---------------------------------------------------------------------------
    def _connect(self):
        u = urllib.parse.urlparse(self.url)
        q = urllib.parse.parse_qs(u.query)
        sslmode = (q.get("sslmode") or ["prefer"])[0]
        ctx = None
        if sslmode in ("require", "verify-ca", "verify-full"):
            ctx = ssl.create_default_context()
            if sslmode == "require":
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
        return pg.Connection(user=urllib.parse.unquote(u.username or ""), password=urllib.parse.unquote(u.password or ""),
                             host=u.hostname or "localhost", port=u.port or 5432, database=(u.path or "/").lstrip("/") or None,
                             ssl_context=ctx, timeout=10, application_name="helm-visualiser")

    def _run(self, sql, **params):
        if not self.enabled:
            raise RuntimeError(self.last_error)
        with self.lock:
            for attempt in (1, 2):
                try:
                    if self.con is None:
                        self.con = self._connect()
                    rows = self.con.run(sql, **params)
                    cols = [c["name"] for c in (self.con.columns or [])]
                    self.up, self.last_error = True, ""
                    return [dict(zip(cols, r)) for r in rows] if cols else rows
                except Exception as e:  # reconnect once
                    self.up, self.last_error = False, str(e)[:200]
                    try:
                        self.con and self.con.close()
                    except Exception:
                        pass
                    self.con = None
                    if attempt == 2:
                        raise

    def migrate(self):
        if not self.enabled:
            return False
        try:
            for stmt in SCHEMA:
                self._run(stmt)
            return True
        except Exception as e:
            self.last_error = str(e)[:200]
            return False

    # writes ---------------------------------------------------------------------------------
    def record(self, row):
        """Insert a summary row. Never raises: a broken DB must not break scanning."""
        if not self.enabled:
            return None
        try:
            cols = [k for k in row if not k.startswith("_")]
            sql = f"INSERT INTO scans ({', '.join(cols)}) VALUES ({', '.join(':' + c for c in cols)}) RETURNING id"
            sid = self._run(sql, **{c: row[c] for c in cols})[0]["id"]
            for r in row["_rules"]:
                self._run("INSERT INTO scan_rules (scan_id, rule_id, category, severity, resource_kind, accepted, count) "
                          "VALUES (:s, :rule_id, :category, :severity, :resource_kind, :accepted, :count)", s=sid, **r)
            for d in row["_deps"]:
                self._run("INSERT INTO scan_dependencies (scan_id, category, label) VALUES (:s, :category, :label)", s=sid, **d)
            for a in row["_apis"]:
                self._run("INSERT INTO scan_apis (scan_id, api_version, kind, count) VALUES (:s, :api_version, :kind, :count)", s=sid, **a)
            self._cleanup()
            return sid
        except Exception as e:
            self.last_error = str(e)[:200]
            return None

    def _cleanup(self):
        if time.time() - self._last_cleanup < 3600:
            return
        self._last_cleanup = time.time()
        self._run("DELETE FROM scans WHERE scanned_at < now() - CAST(:d AS integer) * interval '1 day'", d=RETENTION_DAYS)

    # reads ----------------------------------------------------------------------------------
    def history(self, limit=50, repo=None):
        sql = ("SELECT id, scanned_at, trigger, source_type, repo, ref, commit, chart_path, chart_name, chart_version, status, "
               "error_class, score, n_critical, n_high, n_medium, n_low, n_info, n_accepted, ruleset_version, kube_target, duration_ms "
               "FROM scans " + ("WHERE repo = :repo " if repo else "") + "ORDER BY scanned_at DESC LIMIT :limit")
        rows = self._run(sql, limit=min(int(limit), 500), **({"repo": repo} if repo else {}))
        for r in rows:
            r["scanned_at"] = r["scanned_at"].isoformat()
        return rows

    def stats(self):
        tot = self._run("SELECT count(*) AS scans, count(DISTINCT repo) AS repos, max(scanned_at) AS last, "
                        "round(avg(score)) AS avg_score FROM scans WHERE scanned_at > now() - interval '30 days'")[0]
        top = self._run("SELECT r.rule_id, r.category, count(DISTINCT r.scan_id) AS scans "
                        "FROM scan_rules r JOIN scans s ON s.id = r.scan_id "
                        "WHERE s.scanned_at > now() - interval '30 days' AND NOT r.accepted "
                        "GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 10")
        rates = self._run("WITH s AS (SELECT id FROM scans WHERE scanned_at > now() - interval '30 days' AND status <> 'error') "
                          "SELECT r.rule_id, round(100.0 * count(DISTINCT r.scan_id) / greatest((SELECT count(*) FROM s), 1)) AS pct "
                          "FROM scan_rules r WHERE r.scan_id IN (SELECT id FROM s) AND NOT r.accepted GROUP BY 1")
        if tot.get("last"):
            tot["last"] = tot["last"].isoformat()
        tot["avg_score"] = int(tot["avg_score"]) if tot.get("avg_score") is not None else None
        return dict(totals=tot, topRules=top, failRate={r["rule_id"]: int(r["pct"]) for r in rates})

    # watched repos ---------------------------------------------------------------------------
    def repos(self):
        rows = self._run("SELECT id, url, ref, path, frequency, enabled, kube_target, created_at, next_run_at, last_scan_at, "
                         "last_status, last_score, last_error_class FROM repos ORDER BY url, path")
        for r in rows:
            for k in ("created_at", "next_run_at", "last_scan_at"):
                r[k] = r[k].isoformat() if r[k] else None
        return rows

    def add_repo(self, url, ref, path, frequency, kube_target=None):
        if frequency not in FREQUENCIES:
            raise ValueError(f"frequency must be one of {', '.join(FREQUENCIES)}")
        return self._run("INSERT INTO repos (url, ref, path, frequency, kube_target) VALUES (:u, :r, :p, :f, :k) "
                         "ON CONFLICT (url, ref, path) DO UPDATE SET frequency = EXCLUDED.frequency, enabled = true, "
                         "kube_target = EXCLUDED.kube_target, next_run_at = now() RETURNING id",
                         u=url, r=ref or "", p=path or "", f=frequency, k=kube_target)[0]["id"]

    def update_repo(self, rid, frequency=None, enabled=None):
        if frequency is not None:
            if frequency not in FREQUENCIES:
                raise ValueError("bad frequency")
            self._run("UPDATE repos SET frequency = :f WHERE id = :i", f=frequency, i=int(rid))
        if enabled is not None:
            self._run("UPDATE repos SET enabled = :e, next_run_at = CASE WHEN :e THEN now() ELSE next_run_at END WHERE id = :i",
                      e=bool(enabled), i=int(rid))

    def delete_repo(self, rid):
        self._run("DELETE FROM repos WHERE id = :i", i=int(rid))

    def run_now(self, rid):
        self._run("UPDATE repos SET next_run_at = now() WHERE id = :i", i=int(rid))

    def claim_due(self):
        """Atomically claim one due repo (safe with several replicas: FOR UPDATE SKIP LOCKED)."""
        with self.lock:
            if self.con is None:
                self.con = self._connect()
            c = self.con
            try:
                c.run("BEGIN")
                rows = c.run("SELECT id, url, ref, path, frequency, kube_target FROM repos WHERE enabled AND next_run_at <= now() "
                             "ORDER BY next_run_at LIMIT 1 FOR UPDATE SKIP LOCKED")
                cols = [x["name"] for x in c.columns or []]
                job = dict(zip(cols, rows[0])) if rows else None
                if job:
                    c.run("UPDATE repos SET next_run_at = now() + CAST(:iv AS interval) WHERE id = :i",
                          iv=FREQUENCIES.get(job["frequency"], "1 day"), i=job["id"])
                c.run("COMMIT")
                return job
            except Exception:
                try:
                    c.run("ROLLBACK")
                except Exception:
                    self.con = None
                raise

    def finish_repo(self, rid, scan_id, status, score, error_class):
        self._run("UPDATE repos SET last_scan_at = now(), last_scan_id = :s, last_status = :st, last_score = :sc, "
                  "last_error_class = :e WHERE id = :i", s=scan_id, st=status, sc=score, e=error_class, i=int(rid))


STORE = Store()
