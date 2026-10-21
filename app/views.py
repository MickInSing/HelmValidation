"""Two extra lenses on the same analysis:

* helm_concepts(): one step per Chart Template Guide topic, with where this chart uses it.
* infrastructure(): resources regrouped by concern (network, identity, storage, logging...),
  including what the platform must provide and what is only inferred.

Both return walkthrough steps in the same shape the UI already uses
({id, title, group, pointers, explain, findings}) plus a few extras (badge, rows, nodes).
"""
import re

R = "__rendered__"
DOCS = "https://helm.sh/docs/chart_template_guide/"
WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "ReplicaSet"}


def _p(file, line, label, tone="info"):
    return dict(file=file, start=line, end=line, label=label, tone=tone)


def _tpl_files(files):
    return {p: t for p, t in files.items()
            if (p.startswith("templates/") or "/templates/" in p) and not p.startswith("(")}


def _scan(files, pattern, flags=0, limit=60):
    """All (file, line, match) for a regex across template files."""
    out = []
    rx = re.compile(pattern, flags)
    for p, t in _tpl_files(files).items():
        for i, ln in enumerate(t.split("\n"), 1):
            for m in rx.finditer(ln):
                out.append((p, i, m))
                if len(out) >= limit * 4:
                    return out
    return out


def _actions(files):
    """Text inside {{ }} per (file, line) - functions only count inside template actions."""
    out = []
    for p, t in _tpl_files(files).items():
        for i, ln in enumerate(t.split("\n"), 1):
            for m in re.finditer(r"\{\{-?(.*?)-?\}\}", ln):
                body = m.group(1)
                if body.strip().startswith("/*"):
                    continue
                out.append((p, i, body))
    return out


FUNC_GROUPS = {
    "string": "quote squote upper lower title trim trimSuffix trimPrefix trunc replace contains hasPrefix hasSuffix printf print println repeat substr nospace abbrev indent nindent wrap camelcase kebabcase snakecase splitList join regexMatch regexReplaceAll",
    "logic & defaults": "default empty coalesce ternary eq ne lt le gt ge and or not required fail",
    "lists & dicts": "list append prepend first last rest initial uniq has without compact dict get set unset hasKey pluck keys values merge mergeOverwrite deepCopy dig pick omit until untilStep seq",
    "encoding & yaml": "b64enc b64dec toYaml fromYaml toJson fromJson toPrettyJson toToml fromYamlArray",
    "type conversion": "int int64 float64 toString toStrings atoi kindIs kindOf typeOf typeIs",
    "crypto & random": "sha256sum sha1sum randAlphaNum randAlpha randNumeric genCA genSelfSignedCert genSignedCert genPrivateKey htpasswd encryptAES derivePassword uuidv4",
    "dates": "now date dateModify toDate unixEpoch ago",
    "template & cluster": "include template tpl lookup",
}
FUNC_TO_GROUP = {f: g for g, fs in FUNC_GROUPS.items() for f in fs.split()}
NONDETERMINISTIC = {"randAlphaNum", "randAlpha", "randNumeric", "genCA", "genSelfSignedCert", "genSignedCert",
                    "genPrivateKey", "uuidv4", "now", "lookup"}


# ---------------------------------------------------------------------------
# Helm concepts
# ---------------------------------------------------------------------------
def helm_concepts(files, chart, resources, lint, render_error, values_index, used_value_files, has_overrides):
    tf = _tpl_files(files)
    acts = _actions(files)
    steps = []

    def step(key, title, doc, nodes, what, items, unused="", count=None, extra_ptrs=()):
        ptrs = list(extra_ptrs)
        for it in items:
            if it.get("file"):
                ptrs.append(_p(it["file"], it["line"], it["label"]))
        c = count if count is not None else len(items)
        steps.append(dict(
            id=f"h-{key}", title=title, group="Chart Template Guide", node=None, nodes=nodes,
            doc=DOCS + doc, count=c, badge=dict(text=f"{c}×" if c else "–", cls="used" if c else ""),
            dim=not c, pointers=ptrs[:60], findings=[],
            items=[dict(label=it["label"], hint=it.get("hint", ""), file=it.get("file"), line=it.get("line")) for it in items[:40]],
            explain=what + (f"\n\n{unused}" if unused else ""),
        ))

    # 1 built-in objects
    items, objs = [], {}
    for p, i, m in _scan(files, r"(?<![\w$])\.(Release|Chart|Values|Files|Capabilities|Template)\b(\.[A-Za-z_][\w]*)?"):
        key = "." + m.group(1) + (m.group(2) or "" if m.group(1) in ("Release", "Chart", "Capabilities", "Template") else "")
        objs.setdefault(key, []).append((p, i))
    for k in sorted(objs, key=lambda k: (-len(objs[k]), k)):
        p, i = objs[k][0]
        items.append(dict(label=f"{k} ×{len(objs[k])}", file=p, line=i))
    missing = [o for o in (".Release", ".Chart", ".Values", ".Files", ".Capabilities", ".Template") if not any(k.startswith(o) for k in objs)]
    step("builtin", "Built-in objects", "builtin_objects", ["builtin"],
         "Objects Helm passes into every template: `.Release` (name, namespace, revision, service), `.Values` (merged values), "
         "`.Chart` (Chart.yaml), `.Files` (non-template files), `.Capabilities` (cluster API versions and Kubernetes version) and `.Template` (current file).",
         items, f"Not used here: {', '.join('`'+m+'`' for m in missing)}." if missing else "")

    # 2 values files
    refs = {}
    for p, i, m in _scan(files, r"\.Values\.([A-Za-z0-9_\.]+)"):
        refs.setdefault(m.group(1).rstrip("."), (p, i))
    top_defined = [k for k in values_index if "." not in k]
    top_used = {r.split(".")[0] for r in refs}
    unused_top = [k for k in top_defined if k not in top_used and k != "global"]
    vitems = [dict(label=f"values.yaml: {len(top_defined)} top-level keys", file="values.yaml", line=1)] if "values.yaml" in files else []
    for k in sorted(refs)[:25]:
        if k in values_index:
            vitems.append(dict(label=k, file="values.yaml", line=values_index[k], hint="default"))
    for vf in used_value_files:
        vitems.append(dict(label=f"-f {vf}", file=vf, line=1, hint="values file"))
    if has_overrides:
        vitems.append(dict(label="your overrides / Argo values", hint="applied last"))
    step("values", "Values files", "values_files", ["values", "overrides", "builtin"],
         "`values.yaml` holds the defaults. They're overridden, last one wins, by `-f` files, `--set` and, in ArgoCD, the Application's "
         f"`valueFiles`/`values`/`parameters`. Templates read the merged result through `.Values`. This chart references **{len(refs)}** distinct value paths.",
         vitems, (f"Defined in values.yaml but never referenced by a template: {', '.join('`'+k+'`' for k in unused_top[:10])}. "
                  "These may be dead config, or used only by a subchart." if unused_top else ""),
         count=len(refs))

    # 3 functions & pipelines
    fn_use, pipes = {}, []
    for p, i, body in acts:
        if "|" in body:
            pipes.append((p, i))
        for w in re.findall(r"(?<![\w.$\"])([a-z][A-Za-z0-9]*)\b", re.sub(r'"[^"]*"', '""', body)):
            if w in FUNC_TO_GROUP:
                fn_use.setdefault(w, []).append((p, i))
    fitems = [dict(label=f"{f} ×{len(v)}", file=v[0][0], line=v[0][1]) for f, v in sorted(fn_use.items(), key=lambda kv: -len(kv[1]))]
    step("functions", "Functions & pipelines", "functions_and_pipelines", ["engine"],
         "Functions transform data: `quote .Values.x`. A **pipeline** `|` passes the result of one into the next, left to right: "
         "`.Values.x | default \"a\" | quote`. Helm ships Go's template functions plus the Sprig library."
         f" This chart uses **{len(fn_use)}** different functions and **{len(pipes)}** pipelines.",
         fitems + ([dict(label=f"pipelines ×{len(pipes)}", file=pipes[0][0], line=pipes[0][1])] if pipes else []),
         count=sum(len(v) for v in fn_use.values()))

    # 4 function list (by category, risky ones called out)
    gitems = []
    for g in FUNC_GROUPS:
        used = [f for f in fn_use if FUNC_TO_GROUP[f] == g]
        if used:
            f0 = fn_use[used[0]][0]
            gitems.append(dict(label=f"{g}: {', '.join(sorted(used))}", file=f0[0], line=f0[1]))
    risky = [f for f in fn_use if f in NONDETERMINISTIC]
    step("function_list", "Template function list", "function_list", ["engine"],
         "The full catalogue groups functions into strings, logic, lists/dicts, encoding, type conversion, crypto, dates and cluster access. "
         "Below are the categories this chart touches.",
         gitems,
         ("**Watch out:** " + ", ".join(f"`{f}`" for f in risky) +
          " give a different result on every render (or need a live cluster). In ArgoCD that shows up as a permanent diff, and offline previews won't match reality."
          if risky else "No non-deterministic functions (`rand*`, `gen*`, `now`, `lookup`): renders are repeatable, which is good for GitOps."),
         count=len(gitems))

    # 5 flow control
    ctl = {"if": [], "else": [], "with": [], "range": []}
    for p, i, body in acts:
        m = re.match(r"\s*(if|else if|else|with|range)\b", body)
        if m:
            ctl["else" if m.group(1).startswith("else") else m.group(1)].append((p, i, body.strip()[:60]))
    citems = []
    for k, v in ctl.items():
        for p, i, b in v[:8]:
            citems.append(dict(label=b, file=p, line=i, hint=k))
    step("flow", "Flow control", "control_structures", ["engine", "templates"],
         "`if`/`else` include or drop blocks, `with` narrows the scope of `.`, and `range` loops over lists and maps. "
         "These decide which resources and fields exist at all, which is why changing one value can make whole objects appear or disappear. "
         + " · ".join(f"**{k}** ×{len(v)}" for k, v in ctl.items()),
         citems, count=sum(len(v) for v in ctl.values()))

    # 6 variables
    vitems = [dict(label=m.group(0).strip(), file=p, line=i) for p, i, m in _scan(files, r"\$[A-Za-z_]\w*\s*:?=")]
    root = _scan(files, r"\$\.(Values|Release|Chart)")
    if root:
        vitems.append(dict(label=f"$.{root[0][2].group(1)} (root context) ×{len(root)}", file=root[0][0], line=root[0][1]))
    step("variables", "Variables", "variables", ["engine"],
         "`$name := value` stores a value for later; `$` on its own always points at the **root** context, which you need inside "
         "`with`/`range` (where `.` has changed) to reach `.Values` or `.Release`.",
         vitems, "" if vitems else "Not used in this chart.")

    # 7 named templates
    defs, incs = [], {}
    for p, t in files.items():
        if p.endswith(".tpl") or "/templates/" in "/" + p:
            for i, ln in enumerate(t.split("\n"), 1):
                m = re.search(r'define\s+"([^"]+)"', ln)
                if m:
                    defs.append((m.group(1), p, i))
    for p, i, m in _scan(files, r'(?:include|template)\s+"([^"]+)"'):
        incs.setdefault(m.group(1), []).append((p, i))
    nitems = [dict(label=n, file=p, line=i, hint=f"used ×{len(incs.get(n, []))}") for n, p, i in defs]
    unused_defs = [n for n, _, _ in defs if n not in incs]
    bad_prefix = [n for n, _, _ in defs if chart.get("name") and not n.startswith(str(chart.get("name")) + ".")]
    note = []
    if unused_defs:
        note.append(f"Defined but never included: {', '.join('`'+n+'`' for n in unused_defs[:6])}.")
    if bad_prefix:
        note.append(f"Best practice is to prefix names with the chart name (`{chart.get('name')}.…`) so subcharts don't collide: {', '.join('`'+n+'`' for n in bad_prefix[:4])}.")
    step("named", "Named templates", "named_templates", ["helpers", "templates"],
         "`define` creates a reusable snippet, by convention in `_helpers.tpl`. `include` renders it and, unlike `template`, can be piped "
         "(`include \"x\" . | nindent 4`). Files starting with `_` aren't rendered on their own."
         f" **{len(defs)}** defined, **{sum(len(v) for v in incs.values())}** includes.",
         nitems, " ".join(note), count=len(defs))

    # 8 accessing files
    fitems = [dict(label=m.group(0), file=p, line=i) for p, i, m in _scan(files, r"\.Files\.(Get|Glob|Lines|AsConfig|AsSecrets|GetBytes)\b")]
    extra = [p for p in files if not p.startswith(("templates/", "charts/", "(")) and p not in ("Chart.yaml", "values.yaml", "Chart.lock", ".helmignore", "README.md", "values.schema.json") and not re.match(r"values.*\.ya?ml$", p)]
    step("files", "Accessing files", "accessing_files", ["builtin"],
         "`.Files.Get`, `.Files.Glob`, `.AsConfig` and `.AsSecrets` pull non-template files (config files, scripts, certs) into ConfigMaps or Secrets. "
         "`templates/` and anything in `.helmignore` aren't accessible.",
         fitems + [dict(label=p, file=p, line=1, hint="bundled file") for p in extra[:10]],
         "" if fitems else ("Bundled files exist but no template reads them." if extra else "Not used. Config comes from values instead."),
         count=len(fitems))

    # 9 NOTES.txt
    notes = next((p for p in files if p.endswith("templates/NOTES.txt")), None)
    step("notes", "NOTES.txt", "notes_files", ["notes"],
         "Rendered after `helm install`/`upgrade` and printed to the user. Because it's a template it can print the right URL or "
         "port-forward command. ArgoCD doesn't show it.",
         [dict(label=notes, file=notes, line=1)] if notes else [],
         "" if notes else "No NOTES.txt. Consider adding one so users know how to reach the app.")

    # 10 subcharts & globals
    deps = chart.get("dependencies") or []
    sitems = [dict(label=f"{d.get('name')} {d.get('version', '')}".strip(), hint=(d.get("condition") or d.get("repository") or ""),
                   file="Chart.yaml", line=_line(files.get("Chart.yaml", ""), f"name: {d.get('name')}") or 1) for d in deps]
    sub_dirs = sorted({p.split("/")[1] for p in files if p.startswith("charts/") and p.count("/") >= 2})
    sitems += [dict(label=f"charts/{d}", file=next(p for p in files if p.startswith(f"charts/{d}/")), line=1, hint="vendored") for d in sub_dirs if not any(x.get("name") == d for x in deps)]
    g = _scan(files, r"\.Values\.global\.[\w.]+")
    if g:
        sitems.append(dict(label=f".Values.global ×{len(g)}", file=g[0][0], line=g[0][1]))
    step("subcharts", "Subcharts & globals", "subcharts_and_globals", ["values", "subcharts"],
         "`dependencies` in Chart.yaml become subcharts under `charts/`. The parent configures a subchart under the subchart's name "
         "(`redis.auth.enabled`), and `global:` values are visible to every chart. A subchart can't see its parent's values.",
         sitems, "" if sitems else "No subcharts.")

    # 11 .helmignore
    hi = files.get(".helmignore")
    pats = [l.strip() for l in (hi or "").split("\n") if l.strip() and not l.startswith("#")]
    step("helmignore", ".helmignore", "helm_ignore_file", ["chart"],
         "Patterns for files left out of the packaged chart, such as `.git`, CI config and test data. It also hides them from `.Files`.",
         [dict(label=f"{len(pats)} patterns", file=".helmignore", line=1)] if hi is not None else [],
         "" if hi is not None else "**Missing.** `helm package` will include everything in the folder: `.git`, editor files, local secrets.")

    # 12 debugging
    ditems = [dict(label="helm lint", hint=(re.search(r"\d+ chart\(s\) linted, \d+ chart\(s\) failed", lint or "") or [""])[0] or "ran")]
    ditems.append(dict(label="helm template", hint="failed: see Values" if render_error else f"rendered {len(resources)} resources"))
    lint_issues = [l for l in (lint or "").split("\n") if re.match(r"\[(ERROR|WARNING|INFO)\]", l.strip())]
    ditems += [dict(label=l.strip()[:90]) for l in lint_issues[:8]]
    step("debugging", "Debugging templates", "debugging", ["rendered"],
         "Tools: `helm lint` (best-practice checks), `helm template --debug` (render locally, show the broken YAML), "
         "`helm install --dry-run=server --debug` (validate against a real cluster), and `helm get manifest` (what's deployed). "
         "This app runs `template` and `lint` for you; use **Side by side** to see exactly what each `{{ }}` produced.",
         ditems, count=len(lint_issues) + (1 if render_error else 0) or 1)

    # 13 YAML techniques
    chomp = _scan(files, r"\{\{-|-\}\}")
    ind = _scan(files, r"\b(nindent|indent)\s+\d+")
    toy = _scan(files, r"\btoYaml\b")
    blocks = _scan(files, r":\s*[|>][-+]?\s*$")
    yitems = []
    for lbl, hits in (("{{- / -}} whitespace chomping", chomp), ("nindent / indent", ind), ("toYaml", toy), ("block scalars | >", blocks)):
        if hits:
            yitems.append(dict(label=f"{lbl} ×{len(hits)}", file=hits[0][0], line=hits[0][1]))
    bad_indent = [h for h in ind if re.search(r"\bindent\s+\d+", h[2].group(0)) and "nindent" not in h[2].group(0)]
    step("yaml", "YAML techniques", "yaml_techniques", ["rendered"],
         "Indentation is the most common template bug. Use `toYaml . | nindent N` to drop structured values in at the right depth, "
         "`{{-`/`-}}` to trim whitespace, `quote` for strings YAML would misread (`\"true\"`, `\"1.0\"`, `\"0755\"`), and `|`/`>` for multi-line text.",
         yitems, ("Tip: prefer `nindent` over `indent`. It adds the newline itself, so the template line can start at column 0." if bad_indent else ""),
         count=sum(len(h) for h in (chomp, ind, toy, blocks)))

    # 14 Go data types
    t = _scan(files, r"\b(kindIs|kindOf|typeOf|typeIs|int64|float64|toString|atoi|int)\b")
    eqs = _scan(files, r"\b(eq|ne|lt|gt|le|ge)\s")
    titems = [dict(label=m.group(0), file=p, line=i) for p, i, m in t[:15]]
    if eqs:
        titems.append(dict(label=f"comparisons (eq/ne/lt…) ×{len(eqs)}", file=eqs[0][0], line=eqs[0][1]))
    step("types", "Go data types", "data_types", ["engine"],
         "Values are typed: string, int64, float64, bool, map, slice. `eq 1 \"1\"` is false, and numbers from YAML arrive as float64, "
         "so compare like with like. `--set` guesses types, while `--set-string` forces strings. Argo parameters use `--set` unless `forceString: true`.",
         titems, "" if titems else "Nothing type-sensitive detected.")

    # pipeline diagram description (frontend draws it)
    pipeline = dict(
        nodes=[
            dict(id="chart", x=.07, y=.22, ic="file", l="Chart.yaml", s="metadata", on=True),
            dict(id="values", x=.07, y=.52, ic="sliders", l="values.yaml", s="defaults", on="values.yaml" in files),
            dict(id="overrides", x=.07, y=.84, ic="sliders", l="-f / --set / Argo", s="overrides", ext=True, on=bool(used_value_files or has_overrides)),
            dict(id="subcharts", x=.29, y=.86, ic="puzzle", l="charts/ subcharts", s=f"{len(deps) or len(sub_dirs)} dependencies", on=bool(deps or sub_dirs)),
            dict(id="builtin", x=.29, y=.52, ic="brackets", l="Built-in objects", s=".Values .Release .Chart", on=True),
            dict(id="helpers", x=.29, y=.18, ic="puzzle", l="_helpers.tpl", s=f"{len(defs)} define", on=bool(defs)),
            dict(id="templates", x=.5, y=.3, ic="doc", l="templates/*.yaml", s=f"{len([p for p in tf if not p.endswith(('.tpl', 'NOTES.txt'))])} files", on=True),
            dict(id="engine", x=.6, y=.72, ic="gear", l="Template engine", s="functions · pipelines", on=True),
            dict(id="rendered", x=.76, y=.42, ic="file", l="Rendered YAML", s=f"{len(resources)} resources", on=bool(resources)),
            dict(id="notes", x=.78, y=.84, ic="doc", l="NOTES.txt", s="printed to user", on=bool(notes)),
            dict(id="k8s", x=.94, y=.42, ic="k8s", l="Kubernetes API", s="install / Argo sync", ext=True, on=True),
        ],
        edges=[["chart", "builtin"], ["values", "builtin"], ["overrides", "builtin"], ["subcharts", "builtin"], ["builtin", "templates"],
               ["builtin", "engine"], ["helpers", "templates"], ["templates", "engine"], ["engine", "rendered"], ["engine", "notes"], ["rendered", "k8s"]],
    )
    return dict(steps=steps, pipeline=pipeline)


def _line(text, needle):
    for i, ln in enumerate(text.split("\n"), 1):
        if needle in ln:
            return i
    return None


# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------
def _pod_spec(kind, obj):
    spec = obj.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
    return ((spec.get("template") or {}).get("spec")) or {}


def _pod_meta(kind, obj):
    spec = obj.get("spec") or {}
    if kind == "Pod":
        return obj.get("metadata") or {}
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("metadata") or {}
    return ((spec.get("template") or {}).get("metadata")) or {}


DATA_HINTS = [
    (r"POSTGRES|PG_|PGHOST|DATABASE_URL|JDBC|DB_(HOST|USER|PASS|NAME|PORT)|MYSQL|MARIADB", "Database", "db"),
    (r"REDIS|MEMCACHE|VALKEY", "Cache (Redis)", "db"),
    (r"MONGO", "MongoDB", "db"),
    (r"KAFKA|RABBIT|AMQP|NATS|PULSAR|SQS|PUBSUB", "Message queue", "queue"),
    (r"\bS3_|BUCKET|MINIO|GCS_|AZURE_STORAGE|BLOB", "Object storage", "bucket"),
    (r"ELASTIC|OPENSEARCH", "Search cluster", "db"),
    (r"VAULT_", "Vault", "lock"),
]
AUTH_HINTS = r"OIDC|OAUTH|JWT|AUTH0|KEYCLOAK|DEX_|LDAP|SAML|OKTA|CLIENT_ID|CLIENT_SECRET|ISSUER_URL|SSO"
LOG_IMAGES = r"fluent-?bit|fluentd|vector|promtail|filebeat|otel|opentelemetry|datadog|splunk"


def infrastructure(resources, objs, findings, externals, files, release_ns):
    """resources: analysed resources; objs: {resource id: raw manifest dict}."""
    byk = {}
    for r in resources:
        byk.setdefault(r["kind"], []).append(r)
    fby = {}
    for f in findings:
        fby.setdefault(f["resource"], []).append(f)
    ext_by_cat = {}
    for x in externals:
        ext_by_cat.setdefault(x["category"], []).append(x)

    nodes, edges, seen_nodes = [], [], set()

    def node(nid, lane, label, ic, ext=False, inferred=False, res=None):
        if nid in seen_nodes:
            return nid
        seen_nodes.add(nid)
        nodes.append(dict(id=nid, lane=lane, l=label, ic=ic, ext=ext, inferred=inferred, res=res))
        return nid

    def rp(r, needle=None):
        """pointer into a resource's template (optionally at a matching line)."""
        ln = r["tplStart"]
        if needle:
            t = files.get(r["source"], "")
            for i, x in enumerate(t.split("\n")[r["tplStart"] - 1:r["tplEnd"]], r["tplStart"]):
                if needle in x:
                    ln = i
                    break
        return dict(file=r["source"], line=ln)

    workloads = [r for r in resources if r["kind"] in WORKLOADS and not r.get("hook")]
    containers = []  # (r, container dict)
    envs = []  # (r, container, env name, has_value)
    for r in workloads:
        ps = _pod_spec(r["kind"], objs[r["id"]])
        for c in (ps.get("containers") or []) + (ps.get("initContainers") or []):
            containers.append((r, c))
            for e in c.get("env") or []:
                envs.append((r, c, str(e.get("name", "")), "value" in e))
    for r in workloads:
        node(r["id"], "app", f"{r['kind']} {r['name']}", "cube", res=r["id"])

    concerns = []

    def concern(key, title, lane, what, rows, node_ids, extra_res=()):
        sts = [x["st"] for x in rows]
        st = "bad" if "bad" in sts else "warn" if "warn" in sts else "ext" if "ext" in sts else "ok" if "ok" in sts else "none"
        label = {"bad": f"{sts.count('bad')} issue{'s' if sts.count('bad') > 1 else ''}", "warn": f"{sts.count('warn')} to check",
                 "ext": "external", "ok": "ok", "none": "n/a"}[st]
        ptrs = [dict(file=x["ptr"]["file"], start=x["ptr"]["line"], end=x["ptr"]["line"], label=x["k"], tone="info")
                for x in rows if x.get("ptr") and x["ptr"].get("file")]
        concerns.append(dict(id=f"i-{key}", title=title, group="Concerns", node=None, lane=lane, nodes=node_ids,
                             badge=dict(text=label, cls=st), rows=rows, pointers=ptrs, findings=[],
                             explain=what, resources=list(extra_res)))

    def row(k, v, st, ptr=None, inferred=False):
        return dict(k=k, v=v, st=st, ptr=ptr, inferred=inferred)

    # ---- Network & ingress
    rows, ids = [], []
    ings = byk.get("Ingress", [])
    svcs = byk.get("Service", [])
    exposed = any((objs[s["id"]].get("spec") or {}).get("type") in ("LoadBalancer", "NodePort") for s in svcs)
    if ings or exposed:
        ids.append(node("i-users", "net", "Users / Internet", "globe", ext=True))
    for r in ings:
        s = objs[r["id"]].get("spec") or {}
        hosts = [x.get("host") for x in s.get("rules") or [] if x.get("host")]
        ids.append(node(r["id"], "net", f"Ingress {r['name']}", "arrows", res=r["id"]))
        edges.append(["i-users", r["id"]])
        rows.append(row(f"Ingress {r['name']}", f"hosts: {', '.join(hosts) or '*'} · class: {s.get('ingressClassName') or (r.get('annotations') and 'annotation') or 'default'}", "ok", rp(r, "rules")))
        rows.append(row("TLS", "configured" if s.get("tls") else "**none: plaintext HTTP**", "ok" if s.get("tls") else "warn", rp(r, "tls" if s.get("tls") else "spec")))
        for l in r["links"]:
            edges.append([r["id"], l["to"]])
    for r in svcs:
        s = objs[r["id"]].get("spec") or {}
        ports = ", ".join(f"{p.get('port')}→{p.get('targetPort', p.get('port'))}" for p in s.get("ports") or [])
        t = s.get("type", "ClusterIP")
        ids.append(node(r["id"], "net", f"Service {r['name']}", "swap", res=r["id"]))
        if t in ("LoadBalancer", "NodePort"):
            edges.append(["i-users", r["id"]])
        rows.append(row(f"Service {r['name']}", f"{t} {ports}", "warn" if t in ("NodePort",) else "ok", rp(r, "type")))
        for l in r["links"]:
            edges.append([r["id"], l["to"]])
    for kind in ("Gateway", "HTTPRoute", "VirtualService", "IngressRoute"):
        for r in byk.get(kind, []):
            ids.append(node(r["id"], "net", f"{kind} {r['name']}", "arrows", res=r["id"]))
            rows.append(row(kind, r["name"], "ok", rp(r)))
    nps = byk.get("NetworkPolicy", [])
    for r in nps:
        ids.append(node(r["id"], "net", f"NetPol {r['name']}", "wall", res=r["id"]))
        for l in r["links"]:
            edges.append([r["id"], l["to"]])
    rows.append(row("NetworkPolicy", f"{len(nps)} polic{'y' if len(nps) == 1 else 'ies'}" if nps else "**none: any pod in the cluster can reach these pods**",
                    "ok" if nps else "warn", rp(nps[0]) if nps else None))
    egress = [r for r in nps if "Egress" in ((objs[r["id"]].get("spec") or {}).get("policyTypes") or [])]
    if nps:
        rows.append(row("Egress control", "restricted" if egress else "not restricted (ingress-only policies)", "ok" if egress else "warn", rp(nps[0], "policyTypes")))
    concern("network", "Network & ingress", "net", "How traffic reaches the app, and what it's allowed to talk to.", rows, ids)

    # ---- Compute & scaling
    rows, ids = [], []
    for r in workloads:
        o = objs[r["id"]]
        reps = (o.get("spec") or {}).get("replicas")
        ps = _pod_spec(r["kind"], o)
        cn = [c.get("name") for c in ps.get("containers") or []]
        rows.append(row(f"{r['kind']} {r['name']}", f"containers: {', '.join(cn)}" + (f" · replicas {reps}" if reps is not None else ""), "ok", rp(r, "containers")))
        ids.append(r["id"])
    for r in byk.get("HorizontalPodAutoscaler", []):
        s = objs[r["id"]].get("spec") or {}
        ids.append(node(r["id"], "app", f"HPA {s.get('minReplicas', 1)}–{s.get('maxReplicas')}", "chart", res=r["id"]))
        for l in r["links"]:
            edges.append([r["id"], l["to"]])
        rows.append(row("Autoscaling", f"HPA {s.get('minReplicas', 1)}–{s.get('maxReplicas')} replicas", "ok", rp(r, "maxReplicas")))
    for r in byk.get("PodDisruptionBudget", []):
        ids.append(node(r["id"], "app", f"PDB {r['name']}", "shield", res=r["id"]))
        rows.append(row("Disruption budget", r["name"], "ok", rp(r)))
    if workloads and not byk.get("PodDisruptionBudget"):
        rows.append(row("Disruption budget", "none: node drains can take every replica down at once", "warn" if len(workloads) else "none"))
    nolim = sorted({c.get("name") for r, c in containers if not ((c.get("resources") or {}).get("limits") or {}).get("memory")})
    rows.append(row("Requests / limits", "set on all containers" if not nolim else f"missing memory limit: {', '.join(nolim)}", "ok" if not nolim else "warn",
                    rp(workloads[0], "resources") if workloads else None))
    sel = [x for x in [((_pod_spec(r["kind"], objs[r["id"]]).get("nodeSelector") or {}), r) for r in workloads] if x[0]]
    tol = [r for r in workloads if _pod_spec(r["kind"], objs[r["id"]]).get("tolerations")]
    gpu = [c.get("name") for r, c in containers if any("gpu" in k for k in ((c.get("resources") or {}).get("limits") or {}))]
    if sel or tol:
        rows.append(row("Scheduling", f"nodeSelector on {len(sel)}, tolerations on {len(tol)} workload(s)", "ok", rp((sel[0][1] if sel else tol[0]), "nodeSelector" if sel else "tolerations")))
    if gpu:
        rows.append(row("GPUs", f"requested by {', '.join(gpu)}", "ok"))
    concern("compute", "Compute & scaling", "app", "What runs, how many copies, where it's scheduled and how it scales.", rows, ids)

    # ---- Identity & authentication
    rows, ids = [], []
    for r in byk.get("ServiceAccount", []):
        o = objs[r["id"]]
        ids.append(node(r["id"], "id", f"SA {r['name']}", "user", res=r["id"]))
        rows.append(row(f"ServiceAccount {r['name']}", "token automount off" if o.get("automountServiceAccountToken") is False else "token automount **on**",
                        "ok" if o.get("automountServiceAccountToken") is False else "warn", rp(r)))
    for kind in ("Role", "ClusterRole"):
        for r in byk.get(kind, []):
            rules = objs[r["id"]].get("rules") or []
            summary = "; ".join(f"{','.join(x.get('verbs') or [])} {','.join(x.get('resources') or [])}" for x in rules)[:140]
            wild = any("*" in (x.get("verbs") or []) + (x.get("resources") or []) for x in rules)
            sec = any("secrets" in (x.get("resources") or []) for x in rules)
            ids.append(node(r["id"], "id", f"{kind} {r['name']}", "shield", res=r["id"]))
            rows.append(row(f"{kind} {r['name']}", summary or "no rules", "bad" if wild else "warn" if sec or kind == "ClusterRole" else "ok", rp(r, "rules")))
    for kind in ("RoleBinding", "ClusterRoleBinding"):
        for r in byk.get(kind, []):
            for l in r["links"]:
                edges.append([l["to"], r["id"]] if False else [r["id"], l["to"]])
            ids.append(node(r["id"], "id", f"{kind.replace('Cluster', 'C')} {r['name']}", "link", res=r["id"]))
    for r in workloads:
        for l in r["links"]:
            if l["label"] == "runs as":
                edges.append([l["to"], r["id"]])
    auth_env = sorted({n for r, c, n, _ in envs if re.search(AUTH_HINTS, n, re.I)})
    auth_ann = [r for r in ings if any(re.search(r"auth-url|auth-signin|oauth2|auth-type", a) for a in r.get("annotations", []))]
    if auth_env or auth_ann:
        ids.append(node("i-idp", "id", "Identity provider", "user", ext=True, inferred=True))
        for r in workloads:
            edges.append(["i-idp", r["id"]])
        rows.append(row("User authentication", (f"auth env vars: {', '.join(auth_env[:5])}" if auth_env else "") +
                        (" · ingress auth annotations" if auth_ann else ""), "ext", rp(auth_ann[0]) if auth_ann else None, inferred=True))
    else:
        rows.append(row("User authentication", "none detected (no OIDC/OAuth env vars or ingress auth annotations)", "none"))
    concern("identity", "Identity & authentication", "id",
            "Who the app is to Kubernetes (ServiceAccount + RBAC), and how users or the app authenticate to other systems.", rows, ids)

    # ---- Secrets & config
    rows, ids = [], []
    for r in byk.get("ConfigMap", []):
        keys = list((objs[r["id"]].get("data") or {}).keys())
        ids.append(node(r["id"], "data", f"ConfigMap {r['name']}", "file", res=r["id"]))
        rows.append(row(f"ConfigMap {r['name']}", f"{len(keys)} key(s): {', '.join(keys[:5])}", "ok", rp(r, "data")))
    for r in byk.get("Secret", []):
        ids.append(node(r["id"], "data", f"Secret {r['name']}", "lock", res=r["id"]))
        rows.append(row(f"Secret {r['name']}", "rendered from chart values (likely committed to git)", "warn", rp(r, "data")))
    for kind, lbl in (("ExternalSecret", "External Secrets"), ("SealedSecret", "Sealed Secrets"), ("SecretProviderClass", "CSI secrets store")):
        for r in byk.get(kind, []):
            ids.append(node(r["id"], "data", f"{kind} {r['name']}", "lock", res=r["id"]))
            rows.append(row(lbl, r["name"], "ok", rp(r)))
    for r in workloads:
        for l in r["links"]:
            if l["to"] in seen_nodes:
                edges.append([l["to"], r["id"]])
    for x in ext_by_cat.get("existing", []):
        if x["label"].startswith(("Secret", "ConfigMap")):
            ids.append(node(x["id"], "data", x["label"], "lock" if x["label"].startswith("Secret") else "file", ext=True))
            for c in x["consumers"]:
                edges.append([x["id"], c])
            rows.append(row(x["label"], "must already exist (not created by chart)", "ext", x["pointers"][0] if x["pointers"] else None))
    plain = [f for f in findings if f.get("key") == "secretenv"]
    for f in plain[:5]:
        rows.append(row("Plaintext credential", f["title"], "bad", f.get("tpl")))
    concern("secrets", "Secrets & config", "data", "Where configuration and credentials come from, and whether any credentials sit in plain text.", rows, ids)

    # ---- Storage & data
    rows, ids = [], []
    for r in byk.get("PersistentVolumeClaim", []):
        s = objs[r["id"]].get("spec") or {}
        size = ((s.get("resources") or {}).get("requests") or {}).get("storage", "?")
        ids.append(node(r["id"], "data", f"PVC {r['name']} {size}", "disk", res=r["id"]))
        rows.append(row(f"PVC {r['name']}", f"{size} · {', '.join(s.get('accessModes') or [])} · class {s.get('storageClassName') or 'default'}", "ok", rp(r, "storage")))
    vol_types = {}
    for r in workloads:
        ps = _pod_spec(r["kind"], objs[r["id"]])
        for v in ps.get("volumes") or []:
            t = next((k for k in v if k != "name"), "?")
            vol_types.setdefault(t, []).append((r, v.get("name")))
        for vct in (objs[r["id"]].get("spec") or {}).get("volumeClaimTemplates") or []:
            size = (((vct.get("spec") or {}).get("resources") or {}).get("requests") or {}).get("storage", "?")
            nid = node(f"i-vct-{r['id']}-{(vct.get('metadata') or {}).get('name')}", "data", f"volumeClaimTemplate {size}", "disk")
            ids.append(nid)
            edges.append([nid, r["id"]])
            rows.append(row("StatefulSet storage", f"{(vct.get('metadata') or {}).get('name')} {size} per replica", "ok", rp(r, "volumeClaimTemplates")))
    for t, uses in vol_types.items():
        if t in ("configMap", "secret", "projected"):
            continue
        st = "bad" if t == "hostPath" else "ok"
        note = {"emptyDir": "scratch space, lost when the pod restarts", "hostPath": "**node filesystem: escape risk**",
                "persistentVolumeClaim": "persistent", "csi": "CSI driver"}.get(t, "")
        rows.append(row(f"{t} volume", f"{', '.join(n for _, n in uses[:4])}" + (f" · {note}" if note else ""), st, rp(uses[0][0], t)))
        if t in ("emptyDir", "hostPath"):
            nid = node(f"i-vol-{t}", "data", f"{t}", "disk")
            ids.append(nid)
            for rr, _ in uses:
                edges.append([nid, rr["id"]])
    if not byk.get("PersistentVolumeClaim") and not any(r["kind"] == "StatefulSet" for r in workloads):
        rows.append(row("Persistent storage", "none: the chart is stateless", "none"))
    found = {}
    for r, c, n, _ in envs:
        for rx, label, ic in DATA_HINTS:
            if re.search(rx, n, re.I):
                found.setdefault(label, (ic, set(), r, n))[1].add(n)
    for label, (ic, names, r, n) in found.items():
        nid = node(f"i-data-{label}", "data", label, ic, ext=True, inferred=True)
        ids.append(nid)
        for rr in workloads:
            if any(re.search(re.escape(x), str(objs[rr["id"]])) for x in list(names)[:1]):
                edges.append([rr["id"], nid])
        rows.append(row(label, f"inferred from env {', '.join(sorted(names)[:4])}; **not deployed by this chart**", "ext", rp(r, n), inferred=True))
    concern("storage", "Storage & data", "data", "Persistent data, volumes, and the data services the app talks to.", rows, ids)

    # ---- Logging & observability
    rows, ids = [], []
    mon = byk.get("ServiceMonitor", []) + byk.get("PodMonitor", [])
    for r in mon:
        ids.append(node(r["id"], "obs", f"{r['kind']} {r['name']}", "chart", res=r["id"]))
        rows.append(row(r["kind"], r["name"], "ok", rp(r)))
    metric_ports = [(r, c, p) for r, c in containers for p in c.get("ports") or [] if re.search(r"metric|prom", str(p.get("name", "")), re.I) or p.get("containerPort") in (9090, 9100, 9113, 9187, 8081)]
    prom_ann = [r for r in workloads if any(a.startswith("prometheus.io/") for a in (_pod_meta(r["kind"], objs[r["id"]]).get("annotations") or {}))]
    for r, c, p in metric_ports:
        nid = node(f"i-metrics-{r['id']}-{c.get('name')}", "obs", f"{c.get('name')} :{p.get('containerPort')}", "chart")
        ids.append(nid)
        edges.append([r["id"], nid])
        rows.append(row("Metrics endpoint", f"{c.get('name')} port {p.get('containerPort')} ({p.get('name', '')})", "ok", rp(r, f"containerPort: {p.get('containerPort')}")))
    if metric_ports or prom_ann or mon:
        ids.append(node("i-prom", "obs", "Prometheus", "cloud", ext=True, inferred=not mon))
        for nid in [n["id"] for n in nodes if n["lane"] == "obs" and n["id"] not in ("i-prom", "i-logs")]:
            edges.append([nid, "i-prom"])
        if not mon and not prom_ann:
            rows.append(row("Scraping", "metrics exposed but no ServiceMonitor/PodMonitor or prometheus.io annotations", "warn"))
        elif prom_ann:
            rows.append(row("Scraping", "prometheus.io annotations on pods", "ok", rp(prom_ann[0], "prometheus.io")))
    else:
        rows.append(row("Metrics", "none exposed", "none"))
    log_side = [(r, c) for r, c in containers if re.search(LOG_IMAGES, str(c.get("image", "")), re.I)]
    if log_side:
        for r, c in log_side:
            rows.append(row("Log shipper sidecar", f"{c.get('name')} ({c.get('image')})", "ok", rp(r, c.get("name"))))
    else:
        ids.append(node("i-logs", "obs", "Node log agent", "log", ext=True, inferred=True))
        for r in workloads:
            edges.append([r["id"], "i-logs"])
        rows.append(row("Logs", "stdout/stderr, collected by the cluster's log agent (assumed: nothing in the chart ships logs)", "ext", inferred=True))
    otel = sorted({n for r, c, n, _ in envs if n.startswith("OTEL_") or "JAEGER" in n or "ZIPKIN" in n})
    rows.append(row("Tracing", f"env: {', '.join(otel[:4])}" if otel else "none detected", "ok" if otel else "none", inferred=bool(otel)))
    main = [(r, c) for r, c in containers if c in (_pod_spec(r["kind"], objs[r["id"]]).get("containers") or [])]
    noready = [c.get("name") for r, c in main if not c.get("readinessProbe")]
    nolive = [c.get("name") for r, c in main if not c.get("livenessProbe")]
    rows.append(row("Health probes", "readiness + liveness everywhere" if not noready and not nolive else
                    f"no readiness: {', '.join(noready) or '-'} · no liveness: {', '.join(nolive) or '-'}", "ok" if not noready and not nolive else "warn",
                    rp(workloads[0], "Probe") if workloads else None))
    concern("observability", "Logging & observability", "obs", "How you'd know it's healthy: metrics, logs, traces and probes.", rows, ids)

    # ---- Security posture
    rows, ids = [], []
    sev = {}
    for f in findings:
        sev[f["sev"]] = sev.get(f["sev"], 0) + 1
    rows.append(row("Findings", ", ".join(f"{v} {k}" for k, v in sorted(sev.items(), key=lambda kv: ["critical", "high", "medium", "low", "info"].index(kv[0]))) or "none",
                    "bad" if sev.get("critical") or sev.get("high") else "warn" if sev.get("medium") else "ok"))
    for r, c in containers:
        fl = [f for f in fby.get(r["id"], []) if f["title"].startswith(f"[{c.get('name')}]") and f["sev"] in ("critical", "high", "medium")]
        rows.append(row(f"container {c.get('name')}", "hardened" if not fl else f"{len(fl)} issue(s): " + "; ".join(f["title"].split("] ", 1)[-1] for f in fl[:3]),
                        "ok" if not fl else "bad" if any(f["sev"] in ("critical", "high") for f in fl) else "warn", rp(r, f"name: {c.get('name')}")))
        ids.append(r["id"])
    digests = sum(1 for _, c in containers if "@sha256:" in str(c.get("image", "")))
    rows.append(row("Image provenance", f"{digests}/{len(containers)} images pinned by digest", "ok" if containers and digests == len(containers) else "warn"))
    ns = byk.get("Namespace", [])
    psa = any(any(k.startswith("pod-security.kubernetes.io/") for k in ((objs[r["id"]].get("metadata") or {}).get("labels") or {})) for r in ns)
    rows.append(row("Pod Security Admission", "namespace labelled by chart" if psa else "not set by the chart (depends on the target namespace)", "ok" if psa else "none"))
    concern("security", "Security posture", "app", "The CKS checks regrouped: pod hardening, image supply chain and admission.", rows, list(dict.fromkeys(ids)))

    # ---- Kubernetes platform
    rows, ids = [], []

    def plat(nid, label, ic, why, consumers, ptr=None):
        ids.append(node(nid, "plat", label, ic, ext=True))
        for c in consumers:
            edges.append([nid, c])
        rows.append(row(label, why, "ext", ptr))

    classes = sorted({(objs[r["id"]].get("spec") or {}).get("ingressClassName") or "default" for r in ings})
    if ings:
        plat("i-ingctl", f"Ingress controller ({', '.join(classes)})", "arrows", "routes Ingress objects; not installed by this chart", [r["id"] for r in ings], rp(ings[0], "ingressClassName"))
    if byk.get("HorizontalPodAutoscaler"):
        plat("i-msrv", "metrics-server", "chart", "HPA needs resource metrics", [r["id"] for r in byk["HorizontalPodAutoscaler"]])
    if nps:
        plat("i-cni", "CNI with NetworkPolicy", "wall", "policies are ignored unless the CNI enforces them (Calico, Cilium…)", [r["id"] for r in nps])
    if byk.get("PersistentVolumeClaim") or any((objs[r["id"]].get("spec") or {}).get("volumeClaimTemplates") for r in workloads):
        plat("i-sc", "StorageClass / CSI", "disk", "provisions the volumes", [r["id"] for r in byk.get("PersistentVolumeClaim", [])])
    cm_ann = [r for r in ings if any(a.startswith("cert-manager.io/") for a in r.get("annotations", []))]
    if cm_ann:
        plat("i-certm", "cert-manager", "lock", "issues the Ingress TLS certificate (annotation)", [r["id"] for r in cm_ann], rp(cm_ann[0], "cert-manager.io"))
    dns_ann = [r for r in ings + svcs if any(a.startswith("external-dns.alpha.kubernetes.io/") for a in r.get("annotations", []))]
    if dns_ann:
        plat("i-xdns", "external-dns", "globe", "creates DNS records (annotation)", [r["id"] for r in dns_ann])
    for x in ext_by_cat.get("operator", []) + ext_by_cat.get("cluster", []) + ext_by_cat.get("argo", []):
        plat(x["id"], x["label"], "puzzle" if x["category"] == "operator" else "k8s", x["detail"].split(". ")[0].replace("**", ""), x["consumers"],
             x["pointers"][0] if x["pointers"] else None)
    for x in ext_by_cat.get("values", []):
        rows.append(row(x["label"], "values supplied at deploy time (see Values)", "ext", x["pointers"][0] if x["pointers"] else None))
    apis = sorted({r.get("apiVersion") for r in resources if r.get("apiVersion")})
    rows.append(row("API versions used", ", ".join(apis[:10]), "ok"))
    concern("platform", "Kubernetes platform", "plat", "What the cluster must already provide. Nothing in this lane is installed by the chart.", rows, ids)

    # dedupe edges, keep only ones whose ends exist
    have = {n["id"] for n in nodes}
    uniq = []
    for a, b in edges:
        if a in have and b in have and a != b and [a, b] not in uniq:
            uniq.append([a, b])
    return dict(steps=concerns, diagram=dict(nodes=nodes, edges=uniq,
                lanes=[dict(id="plat", l="Platform (cluster must provide)"), dict(id="net", l="Network & edge"),
                       dict(id="app", l="Compute"), dict(id="data", l="Config · secrets · data")],
                side=[dict(id="id", l="Identity"), dict(id="obs", l="Observability")]))


# ---------------------------------------------------------------------------
# Pods view: what the chart asks Kubernetes to run
# ---------------------------------------------------------------------------
LOGO_RULES = [(r"prometheus|alertmanager|node-exporter|(^|/)prom/", "prometheus"), (r"grafana", "grafana"),
              (r"postgres|cloudnative-pg|cnpg", "postgresql"), (r"redis|valkey", "redis"), (r"nginx", "nginx"),
              (r"argo", "argo"), (r"registry\.k8s\.io|k8s\.gcr\.io|(^|/)kube-", "kubernetes")]


def logo_for(image):
    img = str(image or "").lower()
    return next((slug for rx, slug in LOGO_RULES if re.search(rx, img)), None)


def _res(c):
    r = c.get("resources") or {}
    q, l = r.get("requests") or {}, r.get("limits") or {}
    if not q and not l:
        return "no requests / limits"
    parts = []
    if q.get("cpu") or l.get("cpu"):
        parts.append("cpu " + (str(q.get("cpu", "–")) + (f"→{l['cpu']}" if l.get("cpu") else "")))
    if q.get("memory") or l.get("memory"):
        qm, lm = q.get("memory"), l.get("memory")
        parts.append("mem " + (f"{qm} (request = limit)" if qm and qm == lm else f"{qm or '–'}→{lm or '∞'}"))
    return " · ".join(parts)


def _hardening(c, psc):
    sc = c.get("securityContext") or {}
    out = []
    if sc.get("runAsNonRoot", psc.get("runAsNonRoot")) or (sc.get("runAsUser", psc.get("runAsUser")) or 0) > 0:
        out.append("non-root")
    if sc.get("readOnlyRootFilesystem"):
        out.append("read-only FS")
    if "ALL" in [str(x).upper() for x in ((sc.get("capabilities") or {}).get("drop") or [])]:
        out.append("drop ALL")
    if (sc.get("seccompProfile") or psc.get("seccompProfile") or {}).get("type") in ("RuntimeDefault", "Localhost"):
        out.append("seccomp")
    if sc.get("allowPrivilegeEscalation") is False:
        out.append("no priv-esc")
    if sc.get("privileged"):
        out.append("PRIVILEGED")
    return out


# ---------------------------------------------------------------------------
# Pods an operator creates from a custom resource in the chart (not in the chart itself)
# ---------------------------------------------------------------------------
def _g(d, *path, default=None):
    for p in path:
        d = d.get(p) if isinstance(d, dict) else None
        if d is None:
            return default
    return d


def _cnpg_cluster(n, s):
    inst = int(s.get("instances") or 1)
    return dict(product="CloudNativePG", what="PostgreSQL cluster", logo="postgresql", port=5432,
                image=s.get("imageName") or "ghcr.io/cloudnative-pg/postgresql (operator default)",
                pods=[dict(name=f"{n}-{i + 1}", role="primary" if i == 0 else "replica") for i in range(inst)],
                storage=_g(s, "storage", "size"), podLabels={"cnpg.io/cluster": n},
                services=[(f"{n}-rw", "read/write → primary"), (f"{n}-ro", "read-only → replicas"), (f"{n}-r", "any instance")],
                secrets=[(f"{n}-app", "app user: username, password, host, uri"), (f"{n}-superuser", "postgres superuser (if enabled)"),
                         (f"{n}-ca", "CA certificate"), (f"{n}-server", "server TLS")],
                notes=[] if inst > 1 else ["1 instance: no standby, so a node or pod failure means downtime"])


def _cnpg_pooler(n, s):
    inst = int(s.get("instances") or 1)
    cl = _g(s, "cluster", "name") or "?"
    return dict(product="CloudNativePG", what=f"PgBouncer pooler for {cl}", logo="postgresql", port=5432, image="pgbouncer (operator default)",
                pods=[dict(name=f"{n}-<hash>-{i + 1}", role="pooler") for i in range(inst)], storage=None,
                podLabels={"cnpg.io/poolerName": n}, services=[(n, f"{_g(s, 'type') or 'rw'} pool")], secrets=[], notes=[])


def _zalando(n, s):
    inst = int(s.get("numberOfInstances") or 1)
    return dict(product="Zalando Postgres Operator", what="PostgreSQL cluster", logo="postgresql", port=5432,
                image=s.get("dockerImage") or "spilo (operator default)",
                pods=[dict(name=f"{n}-{i}", role="primary" if i == 0 else "replica") for i in range(inst)],
                storage=_g(s, "volume", "size"), podLabels={"cluster-name": n},
                services=[(n, "primary"), (f"{n}-repl", "replicas")],
                secrets=[(f"{u}.{n}.credentials.postgresql.acid.zalan.do", f"user {u}") for u in (s.get("users") or {})], notes=[])


def _prom(kind):
    def f(n, s):
        reps = int(s.get("replicas") or 1)
        prefix = "prometheus" if kind == "Prometheus" else "alertmanager"
        return dict(product="Prometheus Operator", what=kind, logo="prometheus", port=9090 if kind == "Prometheus" else 9093,
                    image=s.get("image") or f"{prefix} (operator default)",
                    pods=[dict(name=f"{prefix}-{n}-{i}", role=kind.lower()) for i in range(reps)],
                    storage=_g(s, "storage", "volumeClaimTemplate", "spec", "resources", "requests", "storage"),
                    podLabels={kind.lower(): n}, services=[(f"{prefix}-operated", "governing service")], secrets=[], notes=[])
    return f


def _strimzi(n, s):
    reps = int(_g(s, "kafka", "replicas") or 0)
    return dict(product="Strimzi", what="Kafka cluster", logo=None, port=9092, image="kafka (operator default)",
                pods=[dict(name=f"{n}-kafka-{i}", role="broker") for i in range(reps)] or [dict(name=f"{n}-<pool>-N", role="broker (KafkaNodePool)")],
                storage=_g(s, "kafka", "storage", "size"), podLabels={"strimzi.io/cluster": n},
                services=[(f"{n}-kafka-bootstrap", "bootstrap")], secrets=[(f"{n}-cluster-ca-cert", "cluster CA")], notes=[])


MANAGED = {("postgresql.cnpg.io", "Cluster"): _cnpg_cluster, ("postgresql.cnpg.io", "Pooler"): _cnpg_pooler,
           ("acid.zalan.do", "postgresql"): _zalando, ("monitoring.coreos.com", "Prometheus"): _prom("Prometheus"),
           ("monitoring.coreos.com", "Alertmanager"): _prom("Alertmanager"), ("kafka.strimzi.io", "Kafka"): _strimzi}


def managed_spec(obj):
    """Describe what an operator will create for this custom resource, or None."""
    group = str(obj.get("apiVersion", "")).split("/")[0]
    fn = MANAGED.get((group, obj.get("kind")))
    if not fn:
        return None
    try:
        return fn((obj.get("metadata") or {}).get("name") or "?", obj.get("spec") or {})
    except Exception:
        return None


def operator_outputs(objs):
    """(kind, name) pairs that operators will create from the chart's custom resources."""
    out = set()
    for o in objs:
        m = managed_spec(o) if isinstance(o, dict) else None
        if m:
            out |= {("Secret", s) for s, _ in m["secrets"]} | {("Service", s) for s, _ in m["services"]}
    return out


def _peer_allows(peer, labels):
    """Does one NetworkPolicy egress 'to' peer allow pods with these labels in the same namespace?"""
    if "ipBlock" in peer:
        return "unknown"
    ps, ns = peer.get("podSelector"), peer.get("namespaceSelector")
    if ps is None:
        return True if ns is not None else False
    ml, me = ps.get("matchLabels") or {}, ps.get("matchExpressions") or []
    if me:
        return "unknown"
    return all(labels.get(k) == str(v) for k, v in ml.items())


def _egress_status(policies, labels, port):
    """allowed / blocked / unknown / open for a workload's egress to the managed pods."""
    eg = [p for p in policies if "Egress" in (p.get("policyTypes") or [])]
    if not eg:
        return "open", "no egress NetworkPolicy: traffic is not restricted"
    unknown = False
    for p in eg:
        for rule in p.get("egress") or []:
            ports = rule.get("ports") or []
            port_ok = not ports or any(str(x.get("port")) in (str(port), "") or x.get("port") is None for x in ports)
            if not port_ok:
                continue
            peers = rule.get("to")
            if not peers:
                return "allowed", f"egress rule in {p['_name']} allows any destination on port {port}"
            for peer in peers:
                a = _peer_allows(peer, labels)
                if a is True:
                    return "allowed", f"{p['_name']} allows egress to these pods on port {port}"
                unknown = unknown or a == "unknown"
    if unknown:
        return "unknown", "egress uses ipBlock or label expressions: can't confirm from the chart"
    return "blocked", f"egress NetworkPolicy has no rule allowing these pods on port {port}: connections will time out"


def topology(resources, objs, findings, externals, namespace):
    by_kind, byid = {}, {r["id"]: r for r in resources}
    for r in resources:
        by_kind.setdefault(r["kind"], []).append(r)
    fby = {}
    for f in findings:
        if not f.get("accepted"):
            fby.setdefault(f.get("resource"), []).append(f)
    hpa_for = {}
    for h in by_kind.get("HorizontalPodAutoscaler", []):
        s = objs[h["id"]].get("spec") or {}
        met = [m.get("resource", {}).get("name") + " " + str((m.get("resource", {}).get("target") or {}).get("averageUtilization", "")) + "%"
               for m in s.get("metrics") or [] if m.get("type") == "Resource"]
        for l in h["links"]:
            hpa_for[l["to"]] = dict(min=s.get("minReplicas", 1), max=s.get("maxReplicas"), metric=", ".join(met) or "custom")
    pdb_for = {}
    for p in by_kind.get("PodDisruptionBudget", []):
        s = objs[p["id"]].get("spec") or {}
        desc = f"maxUnavailable {s['maxUnavailable']}" if "maxUnavailable" in s else f"minAvailable {s.get('minAvailable')}"
        for l in p["links"]:
            pdb_for[l["to"]] = desc
    np_for = {}
    netpols = []
    for n in by_kind.get("NetworkPolicy", []):
        s = objs[n["id"]].get("spec") or {}
        types = s.get("policyTypes") or ["Ingress"]
        summ = []
        if "Ingress" in types:
            summ.append("ingress: " + ("deny all" if not s.get("ingress") else f"{len(s['ingress'])} rule(s)"))
        if "Egress" in types:
            summ.append("egress: " + ("deny all" if not s.get("egress") else f"{len(s['egress'])} rule(s)"))
        targets = [l["to"] for l in n["links"]]
        netpols.append(dict(id=n["id"], name=n["name"], types=types, summary=" · ".join(summ), targets=targets))
        for t in targets:
            np_for.setdefault(t, []).append(n["name"])

    workloads = []
    for r in resources:
        if r["kind"] not in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "ReplicaSet"):
            continue
        o = objs[r["id"]]
        spec = o.get("spec") or {}
        ps = (spec.get("jobTemplate") or {}).get("spec", {}).get("template", {}).get("spec") if r["kind"] == "CronJob" else \
            (spec if r["kind"] == "Pod" else (spec.get("template") or {}).get("spec")) or {}
        ps = ps or {}
        psc = ps.get("securityContext") or {}
        reps = spec.get("replicas", 1) if r["kind"] in ("Deployment", "StatefulSet", "ReplicaSet") else 1
        hpa = hpa_for.get(r["id"])
        rmin, rmax = (hpa["min"], hpa["max"]) if hpa else (reps, reps)
        vols = {v.get("name"): v for v in ps.get("volumes") or []}
        vct = [dict(name=(t.get("metadata") or {}).get("name"), size=((((t.get("spec") or {}).get("resources") or {}).get("requests") or {}).get("storage", "?")))
               for t in spec.get("volumeClaimTemplates") or []]
        containers = []
        for kind_c, lst in (("init", ps.get("initContainers") or []), ("main", ps.get("containers") or [])):
            for i, c in enumerate(lst):
                cf = [dict(sev=f["sev"], title=f["title"].split("] ", 1)[-1], rule=f.get("rule"))
                      for f in fby.get(r["id"], []) if f["title"].startswith(f"[{c.get('name')}]")]
                containers.append(dict(
                    name=c.get("name"), image=c.get("image"), logo=logo_for(c.get("image")), init=kind_c == "init", side=kind_c == "main" and i > 0,
                    ports=[f"{p.get('containerPort')}{' ' + p['name'] if p.get('name') else ''}" for p in c.get("ports") or []],
                    resources=_res(c), hardening=_hardening(c, psc),
                    probes=[k.replace("Probe", "") for k in ("readinessProbe", "livenessProbe", "startupProbe") if c.get(k)],
                    findings=cf))
        mounts = []
        for c in (ps.get("containers") or []) + (ps.get("initContainers") or []):
            for m in c.get("volumeMounts") or []:
                v = vols.get(m.get("name"), {})
                t = next((k for k in ("configMap", "secret", "persistentVolumeClaim", "emptyDir", "hostPath", "projected", "csi") if k in v), None)
                if not t and any(x["name"] == m.get("name") for x in vct):
                    t = "pvc-template"
                label = {"configMap": f"ConfigMap {(v.get('configMap') or {}).get('name', '')}", "secret": f"Secret {(v.get('secret') or {}).get('secretName', '')}",
                         "persistentVolumeClaim": f"PVC {(v.get('persistentVolumeClaim') or {}).get('claimName', '')}", "emptyDir": f"emptyDir {m.get('mountPath')}",
                         "hostPath": f"hostPath {(v.get('hostPath') or {}).get('path', '')}", "pvc-template": f"PVC {m.get('name')}-<pod>"}.get(t, f"{t or 'volume'} {m.get('mountPath')}")
                if not any(x["label"] == label for x in mounts):
                    mounts.append(dict(type=t or "volume", label=label.strip()))
            for ef in c.get("envFrom") or []:
                if "configMapRef" in ef:
                    mounts.append(dict(type="configMap", label=f"ConfigMap {ef['configMapRef'].get('name')} (env)"))
                if "secretRef" in ef:
                    mounts.append(dict(type="secret", label=f"Secret {ef['secretRef'].get('name')} (env)"))
            for e in c.get("env") or []:
                ref = (e.get("valueFrom") or {}).get("secretKeyRef")
                if ref and not any(x["label"].startswith(f"Secret {ref.get('name')}") for x in mounts):
                    mounts.append(dict(type="secret", label=f"Secret {ref.get('name')} (env)"))
        sa = ps.get("serviceAccountName") or "default"
        spread = bool(ps.get("topologySpreadConstraints")) or bool((ps.get("affinity") or {}).get("podAntiAffinity"))
        zone_spread = any("zone" in str(t.get("topologyKey", "")) for t in ps.get("topologySpreadConstraints") or [])
        wl_findings = [dict(sev=f["sev"], title=f["title"], rule=f.get("rule")) for f in fby.get(r["id"], []) if not f["title"].startswith("[")]
        workloads.append(dict(
            id=r["id"], kind=r["kind"], name=r["name"], hook=r.get("hook"), source=r["source"], tplStart=r["tplStart"],
            replicas=dict(min=rmin, max=rmax, fixed=reps), hpa=hpa, daemon=r["kind"] == "DaemonSet",
            schedule=spec.get("schedule") if r["kind"] == "CronJob" else None,
            pdb=pdb_for.get(r["id"]), netpols=np_for.get(r["id"], []), spread=spread, zoneSpread=zone_spread,
            sa=dict(name=sa, automount=ps.get("automountServiceAccountToken") is not False), vct=vct,
            hostNetwork=bool(ps.get("hostNetwork")), containers=containers, mounts=mounts, findings=wl_findings,
            logo=next((c["logo"] for c in containers if not c["init"] and c["logo"]), None)))

    services = []
    for s in by_kind.get("Service", []):
        sp = objs[s["id"]].get("spec") or {}
        services.append(dict(id=s["id"], name=s["name"], type=sp.get("type", "ClusterIP") + (" · headless" if sp.get("clusterIP") == "None" else ""),
                             ports=[f"{p.get('port')} → {p.get('targetPort', p.get('port'))}" for p in sp.get("ports") or []],
                             targets=[l["to"] for l in s["links"] if l["to"] in {w['id'] for w in workloads}]))
    ingresses = []
    for i in by_kind.get("Ingress", []):
        sp = objs[i["id"]].get("spec") or {}
        hosts = [x.get("host") for x in sp.get("rules") or [] if x.get("host")]
        ingresses.append(dict(id=i["id"], name=i["name"], hosts=hosts, tls=bool(sp.get("tls")), className=sp.get("ingressClassName"),
                              targets=[l["to"] for l in i["links"]]))
    config = []
    for k in ("ConfigMap", "Secret", "PersistentVolumeClaim"):
        for r in by_kind.get(k, []):
            o = objs[r["id"]]
            keys = list((o.get("data") or {}).keys()) + list((o.get("stringData") or {}).keys())
            used_by = [w["id"] for w in workloads if any(r["name"] in m["label"] for m in w["mounts"])]
            config.append(dict(id=r["id"], kind=k, name=r["name"], keys=keys[:6], usedBy=used_by,
                               note="from values.yaml" if k == "Secret" and keys else ""))
    for w in workloads:
        for v in w["vct"]:
            config.append(dict(id=f"vct-{w['id']}-{v['name']}", kind="PVC template", name=f"{v['name']}-{w['name']}-N", keys=[v["size"]], usedBy=[w["id"]], note="per replica"))
    outside = [dict(id=x["id"], label=x["label"], category=x["category"], usedBy=x["consumers"]) for x in externals
               if x["category"] in ("existing", "operator", "values")]

    # pods that an operator creates from the chart's custom resources, and which workloads connect to them
    pol_specs = {}
    for n in by_kind.get("NetworkPolicy", []):
        spec = dict(objs[n["id"]].get("spec") or {}, _name=n["name"])
        spec.setdefault("policyTypes", ["Ingress"])
        for l in n["links"]:
            pol_specs.setdefault(l["to"], []).append(spec)
    wl_text = {w["id"]: str(objs[w["id"]].get("spec") or {}) for w in workloads}
    managed = []
    for r in resources:
        m = managed_spec(objs.get(r["id"]) or {})
        if not m:
            continue
        op = next((x for x in outside if x["category"] == "operator" and r["id"] in x["usedBy"]), None)
        conns = []
        for w in workloads:
            t = wl_text[w["id"]]
            via = [f"Secret {s}" for s, _ in m["secrets"] if s in t] + [f"Service {s}" for s, _ in m["services"] if s in t]
            # also config the workload loads (e.g. DATABASE_URL in a ConfigMap pointing at <cluster>-rw)
            for c in config:
                if w["id"] in c["usedBy"] and c["id"] in objs:
                    data = str(objs[c["id"]].get("data") or "") + str(objs[c["id"]].get("stringData") or "")
                    via += [f"{c['kind']} {c['name']} → {s}" for s, _ in m["services"] + m["secrets"] if re.search(re.escape(s) + r"(?![\w-])", data)]
            if not via:
                continue
            st, why = _egress_status(pol_specs.get(w["id"], []), m["podLabels"], m["port"])
            conns.append(dict(**{"from": w["id"]}, via=via, port=m["port"], status=st, why=why))
        managed.append(dict(id=r["id"], kind=r["kind"], name=r["name"], source=r["source"], tplStart=r["tplStart"],
                            operator=op["id"] if op else None, connections=conns,
                            findings=[dict(sev=f["sev"], title=f["title"], rule=f.get("rule")) for f in fby.get(r["id"], [])],
                            **{k: m[k] for k in ("product", "what", "logo", "port", "image", "pods", "storage", "services", "notes")},
                            secrets=[s for s in m["secrets"] if s[0].endswith("-app") or any(s[0] in c2 for c in conns for c2 in c["via"])] or m["secrets"][:1]))
    # an operator-created Secret is not something that "must already exist"
    made = {f"Secret {s}" for r in resources for s, _ in ((managed_spec(objs.get(r["id"]) or {}) or {}).get("secrets") or [])}
    outside = [x for x in outside if x["label"] not in made]
    return dict(namespace=namespace, ingresses=ingresses, services=services, workloads=workloads, config=config, managed=managed,
                netpols=netpols, outside=outside, ingressClasses=sorted({i["className"] or "default" for i in ingresses}))
