"""`.helm-visualiser.yaml`: accepted findings (with a reason and an expiry) and free-text notes.

Put it in the chart folder (or the repository root for Git scans):

    notes: |
      Runs as a node agent, so it needs host networking. Reviewed with the platform team.
    exceptions:
      - rule: CKS-HOST-001            # rule ID from the Best practices page
        resource: DaemonSet/node-agent  # optional: Kind/name (or just Kind); omit = whole chart
        container: agent              # optional
        reason: Needs the host network to collect node metrics
        expires: 2027-03-31           # required: accepted risk is reviewed, not forgotten
        owner: platform-team          # optional

Accepted findings are shown (struck through, with the reason) but don't count towards the score.
Expired or malformed exceptions are reported and ignored.
"""
import datetime as dt

import yaml

FILENAME = ".helm-visualiser.yaml"
MAX_DAYS = 400   # longer than this is "forever"; ask for a review date instead


def load(files, repo_text=None):
    """Merge repo-root config (if any) with the chart's own file. Returns (cfg, problems)."""
    cfg, problems = {"notes": "", "exceptions": []}, []
    for origin, text in (("repository root", repo_text), ("chart", files.get(FILENAME))):
        if not text:
            continue
        try:
            d = yaml.safe_load(text) or {}
        except yaml.YAMLError as e:
            problems.append(f"{FILENAME} ({origin}) isn't valid YAML: {str(e)[:160]}")
            continue
        if not isinstance(d, dict):
            problems.append(f"{FILENAME} ({origin}) must be a mapping")
            continue
        if d.get("notes"):
            cfg["notes"] += ("\n\n" if cfg["notes"] else "") + str(d["notes"]).strip()
        for i, e in enumerate(d.get("exceptions") or []):
            if not isinstance(e, dict) or not e.get("rule"):
                problems.append(f"exception #{i + 1} ({origin}) has no `rule`")
                continue
            e = dict(e, origin=origin, index=i + 1)
            cfg["exceptions"].append(e)
    return cfg, problems


def _date(v):
    if isinstance(v, dt.date):
        return v
    try:
        return dt.date.fromisoformat(str(v))
    except (TypeError, ValueError):
        return None


def _matches(e, f, resources_by_id):
    if str(e["rule"]).upper() != str(f.get("rule", "")).upper():
        return False
    res = str(e.get("resource") or "")
    if res:
        r = resources_by_id.get(f.get("resource"))
        if not r:
            return False
        kind, _, name = res.partition("/")
        if r["kind"].lower() != kind.lower() or (name and r["name"] != name):
            return False
    c = e.get("container")
    if c and not str(f.get("title", "")).startswith(f"[{c}]"):
        return False
    return True


def apply(findings, cfg, resources, today=None):
    """Mark matching findings as accepted. Returns a list of status rows for the UI."""
    today = today or dt.date.today()
    by_id = {r["id"]: r for r in resources}
    rows = []
    for e in cfg["exceptions"]:
        exp = _date(e.get("expires"))
        reason = str(e.get("reason") or "").strip()
        state, why = "active", ""
        if not reason:
            state, why = "invalid", "missing `reason`"
        elif not exp:
            state, why = "invalid", "missing or bad `expires` (YYYY-MM-DD)"
        elif exp < today:
            state, why = "expired", f"expired {exp.isoformat()}"
        elif (exp - today).days > MAX_DAYS:
            state, why = "invalid", f"expiry more than {MAX_DAYS} days away; set a review date"
        hits = [f for f in findings if _matches(e, f, by_id)]
        if state == "active":
            for f in hits:
                f["accepted"] = dict(reason=reason, expires=exp.isoformat(), owner=e.get("owner") or "", origin=e["origin"])
        elif state == "expired":
            for f in hits:
                f["exceptionExpired"] = exp.isoformat()
        rows.append(dict(rule=e["rule"], resource=e.get("resource") or "(whole chart)", container=e.get("container") or "",
                         reason=reason, expires=exp.isoformat() if exp else "", owner=e.get("owner") or "",
                         state=state, why=why, matched=len(hits), origin=e["origin"]))
    return rows
