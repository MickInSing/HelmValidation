"""Compare two analyses of the same chart (two refs, or base vs PR head)."""
import re

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _container(title):
    m = re.match(r"\[([^\]]+)\]", title or "")
    return m.group(1) if m else ""


def keyed(result, accepted=False):
    """Stable identity for a finding across versions: rule + resource kind/name + container."""
    res = {r["id"]: f"{r['kind']}/{r['name']}" for r in result.get("resources", [])}
    out = {}
    for f in result.get("findings", []):
        if bool(f.get("accepted")) != accepted:
            continue
        k = (f.get("rule") or f.get("key"), res.get(f.get("resource"), "(chart)"), _container(f.get("title")))
        out.setdefault(k, f)
    return out, res


def slim(f, res):
    return dict(rule=f.get("rule"), sev=f["sev"], title=f["title"], resource=res.get(f.get("resource"), ""),
                file=(f.get("tpl") or {}).get("file"), line=(f.get("tpl") or {}).get("line"))


def diff(base, head):
    a, ra = keyed(base)
    b, rb = keyed(head)
    b_acc, _ = keyed(head, accepted=True)
    new = [slim(b[k], rb) for k in b if k not in a]
    accepted = [dict(slim(b_acc[k], rb), reason=b_acc[k]["accepted"]["reason"], expires=b_acc[k]["accepted"]["expires"])
                for k in a if k in b_acc]
    fixed = [slim(a[k], ra) for k in a if k not in b and k not in b_acc]
    order = lambda f: (SEV_ORDER.index(f["sev"]) if f["sev"] in SEV_ORDER else 9, f["rule"] or "")
    new.sort(key=order)
    fixed.sort(key=order)
    cb, ch = base.get("counts") or {}, head.get("counts") or {}
    ka = {f"{r['kind']}/{r['name']}" for r in base.get("resources", [])}
    kb = {f"{r['kind']}/{r['name']}" for r in head.get("resources", [])}
    return dict(
        base=dict(score=base.get("score"), counts=cb, resources=len(ka), renderError=bool(base.get("renderError"))),
        head=dict(score=head.get("score"), counts=ch, resources=len(kb), renderError=bool(head.get("renderError"))),
        scoreDelta=(head.get("score") or 0) - (base.get("score") or 0),
        new=new, fixed=fixed, accepted=accepted, unchanged=len(set(a) & set(b)),
        addedResources=sorted(kb - ka), removedResources=sorted(ka - kb),
    )


def markdown(d, title="Helm chart check", head_label="this PR", base_label="base"):
    """PR-comment friendly summary."""
    arrow = "▲" if d["scoreDelta"] > 0 else "▼" if d["scoreDelta"] < 0 else "="
    hb, bb = d["head"], d["base"]
    sev_cell = lambda c: " · ".join(f"{c.get(s, 0)} {s}" for s in SEV_ORDER[:4] if c.get(s))
    lines = [f"### {title}", "",
             f"| | score | findings | resources |", "|---|---|---|---|",
             f"| {base_label} | {bb['score']} | {sev_cell(bb['counts']) or 'none'} | {bb['resources']} |",
             f"| **{head_label}** | **{hb['score']}** {arrow} {d['scoreDelta']:+d} | {sev_cell(hb['counts']) or 'none'} | {hb['resources']} |", ""]
    if hb["renderError"]:
        lines += ["> ⚠ The chart **failed to render** on this branch.", ""]
    if d["new"]:
        lines += [f"**New findings ({len(d['new'])})**", ""] + [
            f"- `{f['sev']}` **{f['rule']}** {f['title']}" + (f" · `{f['file']}:{f['line']}`" if f.get("file") else "") for f in d["new"][:30]] + [""]
    if d["fixed"]:
        lines += [f"**Fixed ({len(d['fixed'])})** 🎉", ""] + [f"- ~~{f['rule']}~~ {f['title']}" for f in d["fixed"][:30]] + [""]
    if d.get("accepted"):
        lines += [f"**Newly accepted ({len(d['accepted'])})**, via `.helm-visualiser.yaml`", ""] + [
            f"- {f['rule']} {f['title']}: _{f['reason']}_ (until {f['expires']})" for f in d["accepted"][:30]] + [""]
    if not d["new"] and not d["fixed"] and not d.get("accepted"):
        lines += ["No change in findings.", ""]
    if d["addedResources"] or d["removedResources"]:
        lines += ["<details><summary>Resource changes</summary>", ""] + [f"- ➕ {r}" for r in d["addedResources"]] + \
                 [f"- ➖ {r}" for r in d["removedResources"]] + ["", "</details>", ""]
    return "\n".join(lines)
