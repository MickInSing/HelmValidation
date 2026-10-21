"""Fix planner: preview the impact of best-practice fixes, then hand the real change to Claude.

How the preview works: each selected finding is fixed in the *rendered* manifests (the same idea as Helm's
--post-renderer), the result is re-analysed, and before/after are compared. That shows exactly what the cluster
would receive and which findings disappear. It does not edit templates; the generated prompt asks Claude to make
the equivalent change in the chart source (as values with secure defaults) and bump the chart version.
"""
import copy
import datetime as dt
import difflib
import re
import shutil
import tempfile
from pathlib import Path

import yaml

import compare
import rules
from analyzer import analyse_chart_dir, AnalysisError

WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "ReplicaSet"}
SECRET_KEY = re.compile(r"(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential|client[_-]?secret)\s*:", re.I)


# ----------------------------------------------------------------------------------------------- helpers
def _pod(kind, o):
    s = o.setdefault("spec", {})
    if kind == "Pod":
        return s
    if kind == "CronJob":
        return s.setdefault("jobTemplate", {}).setdefault("spec", {}).setdefault("template", {}).setdefault("spec", {})
    return s.setdefault("template", {}).setdefault("spec", {})


def _pod_labels(kind, o):
    s = o.get("spec") or {}
    if kind == "Pod":
        return (o.get("metadata") or {}).get("labels") or {}
    t = ((((s.get("jobTemplate") or {}).get("spec") or {}).get("template")) if kind == "CronJob" else s.get("template")) or {}
    return (t.get("metadata") or {}).get("labels") or {}


def _containers(kind, o, f=None, init=True):
    ps = _pod(kind, o)
    cs = list(ps.get("containers") or []) + (list(ps.get("initContainers") or []) if init else [])
    m = re.match(r"\[([^\]]+)\]", (f or {}).get("title", ""))
    return [c for c in cs if c.get("name") == m.group(1)] if m else cs


def _sc(c):
    return c.setdefault("securityContext", {})


# ----------------------------------------------------------------------------------------------- fixers
# Each fixer: (ctx, res, obj, finding) -> summary string (or None if nothing to do). ctx.add(doc) adds a resource.
class Ctx:
    def __init__(self, release, namespace, resources):
        self.release, self.namespace, self.added, self.resources = release, namespace, [], resources

    def add(self, doc, name):
        if not any(d["metadata"]["name"] == doc["metadata"]["name"] and d["kind"] == doc["kind"] for d in self.added):
            self.added.append(doc)
            return True
        return False


def fx_container(setter, label):
    def fix(ctx, r, o, f):
        if r["kind"] not in WORKLOADS:
            return None
        cs = _containers(r["kind"], o, f)
        for c in cs:
            setter(c, _pod(r["kind"], o))
        return f"{label} on {', '.join(c.get('name', '?') for c in cs)}" if cs else None
    return fix


def _ro_rootfs(c, ps):
    _sc(c)["readOnlyRootFilesystem"] = True
    mounts = c.setdefault("volumeMounts", [])
    if not any(m.get("mountPath") == "/tmp" for m in mounts):
        vols = ps.setdefault("volumes", [])
        name = "tmp" if not any(v.get("name") == "tmp" for v in vols) else "tmp-ro-fix"
        if not any(v.get("name") == name for v in vols):
            vols.append({"name": name, "emptyDir": {}})
        mounts.append({"name": name, "mountPath": "/tmp"})


def _resources(c, ps):
    r = c.setdefault("resources", {})
    req, lim = r.setdefault("requests", {}), r.setdefault("limits", {})
    req.setdefault("cpu", "100m")
    mem = lim.get("memory") or req.get("memory") or "256Mi"
    req["memory"], lim["memory"] = mem, mem


def _probes(c, ps):
    port = next((p.get("containerPort") for p in c.get("ports") or [] if p.get("containerPort")), None)
    if not port:
        return
    c.setdefault("readinessProbe", {"tcpSocket": {"port": port}, "periodSeconds": 10})
    c.setdefault("livenessProbe", {"tcpSocket": {"port": port}, "periodSeconds": 20, "failureThreshold": 6})


def _liveness_split(c, ps):
    lp = c.get("livenessProbe")
    if lp:
        lp = dict(lp)
        lp["periodSeconds"] = max(int(lp.get("periodSeconds", 10)), 20)
        lp["failureThreshold"] = max(int(lp.get("failureThreshold", 3)), 6)
        c["livenessProbe"] = lp


def fx_pod(setter, label):
    def fix(ctx, r, o, f):
        if r["kind"] not in WORKLOADS:
            return None
        setter(_pod(r["kind"], o), o, r)
        return label
    return fix


def _netpol(ctx, r, o, f):
    sel = {}
    for x in ctx.resources:
        if x["kind"] in WORKLOADS and x.get("_labels"):
            sel = {k: v for k, v in x["_labels"].items() if k in ("app.kubernetes.io/instance",)} or x["_labels"]
            break
    name = f"{ctx.release}-default-deny"
    doc = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": name, "namespace": ctx.namespace},
           "spec": {"podSelector": {"matchLabels": sel} if sel else {}, "policyTypes": ["Ingress", "Egress"],
                    "ingress": [{"from": [{"podSelector": {}}]}],
                    "egress": [{"to": [{"namespaceSelector": {}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
                                "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]}]}}
    return f"adds NetworkPolicy/{name} (same-namespace ingress, DNS-only egress)" if ctx.add(doc, name) else None


def _egress(ctx, r, o, f):
    s = o.setdefault("spec", {})
    pt = s.setdefault("policyTypes", ["Ingress"])
    if "Egress" not in pt:
        pt.append("Egress")
    s.setdefault("egress", [{"to": [{"namespaceSelector": {}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
                             "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]}])
    return f"adds Egress (DNS only) to NetworkPolicy/{r['name']}"


def _pdb(ctx, r, o, f):
    labels = _pod_labels(r["kind"], o)
    if not labels:
        return None
    name = f"{r['name']}-pdb"
    doc = {"apiVersion": "policy/v1", "kind": "PodDisruptionBudget", "metadata": {"name": name, "namespace": ctx.namespace},
           "spec": {"maxUnavailable": 1, "selector": {"matchLabels": labels}}}
    return f"adds PodDisruptionBudget/{name} (maxUnavailable: 1)" if ctx.add(doc, name) else None


def _spread(ps, o, r):
    labels = _pod_labels(r["kind"], o)
    ps["topologySpreadConstraints"] = [
        {"maxSkew": 1, "topologyKey": "topology.kubernetes.io/zone", "whenUnsatisfiable": "ScheduleAnyway", "labelSelector": {"matchLabels": labels}},
        {"maxSkew": 1, "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway", "labelSelector": {"matchLabels": labels}}]


def _dedicated_sa(ctx, r, o, f):
    name = r["name"]
    ps = _pod(r["kind"], o)
    ps["serviceAccountName"] = name
    ps["automountServiceAccountToken"] = False
    ctx.add({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name, "namespace": ctx.namespace},
             "automountServiceAccountToken": False}, name)
    return f"adds ServiceAccount/{name} and uses it"


def _secret_env(ctx, r, o, f):
    m = re.search(r"env var '([^']+)'", f.get("title", ""))
    if not m:
        return None
    sec = f"{r['name']}-env"
    for c in _containers(r["kind"], o, f):
        for e in c.get("env") or []:
            if e.get("name") == m.group(1) and "value" in e:
                e.pop("value")
                e["valueFrom"] = {"secretKeyRef": {"name": sec, "key": m.group(1).lower()}}
    doc = next((d for d in ctx.added if d["kind"] == "Secret" and d["metadata"]["name"] == sec), None)
    if not doc:
        doc = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "stringData": {},
               "metadata": {"name": sec, "namespace": ctx.namespace,
                            "annotations": {"helm-visualiser.io/placeholder": "create this Secret outside the chart"}}}
        ctx.added.append(doc)
    doc["stringData"][m.group(1).lower()] = "<set-outside-the-chart>"
    return f"{m.group(1)} now read from Secret/{sec}"


def _tls(ctx, r, o, f):
    s = o.setdefault("spec", {})
    hosts = [x.get("host") for x in s.get("rules") or [] if x.get("host")]
    s["tls"] = [{"hosts": hosts or ["example.com"], "secretName": f"{r['name']}-tls"}]
    return f"adds spec.tls (secret {r['name']}-tls)"


def _cluster_ip(ctx, r, o, f):
    s = o.setdefault("spec", {})
    old = s.get("type")
    s["type"] = "ClusterIP"
    for p in s.get("ports") or []:
        p.pop("nodePort", None)
    return f"type {old} → ClusterIP"


def _ing_auth(ctx, r, o, f):
    ann = o.setdefault("metadata", {}).setdefault("annotations", {})
    ann["nginx.ingress.kubernetes.io/auth-url"] = "https://oauth2-proxy.example.internal/oauth2/auth"
    ann["nginx.ingress.kubernetes.io/auth-signin"] = "https://oauth2-proxy.example.internal/oauth2/start?rd=$escaped_request_uri"
    return "adds oauth2-proxy auth annotations"


def _api_version(ctx, r, o, f):
    m = re.search(r"Use \*\*([a-z0-9./-]+)\*\*", f.get("detail", ""))
    if m and "/" in m.group(1) and " " not in m.group(1):
        old = o.get("apiVersion")
        o["apiVersion"] = m.group(1)
        return f"apiVersion {old} → {m.group(1)}"
    return None


def _host_ns(ps, o, r):
    for k in ("hostNetwork", "hostPID", "hostIPC"):
        if ps.get(k):
            ps[k] = False


def _pss_baseline(ctx, r, o, f):
    ps = _pod(r["kind"], o)
    safe = __import__("learnings").SAFE_SYSCTLS
    if (ps.get("securityContext") or {}).get("sysctls"):
        ps["securityContext"]["sysctls"] = [s for s in ps["securityContext"]["sysctls"] if s.get("name") in safe] or None
        if not ps["securityContext"]["sysctls"]:
            ps["securityContext"].pop("sysctls")
    for c in (ps.get("containers") or []) + (ps.get("initContainers") or []):
        for p in c.get("ports") or []:
            p.pop("hostPort", None)
        sc = c.get("securityContext") or {}
        if sc.get("procMount") == "Unmasked":
            sc["procMount"] = "Default"
        if (sc.get("appArmorProfile") or {}).get("type") == "Unconfined":
            sc["appArmorProfile"] = {"type": "RuntimeDefault"}
        sc.pop("seLinuxOptions", None)
    return "removes hostPort / unsafe sysctls / Unmasked procMount / unconfined AppArmor"


def _psa(ctx, r, o, f):
    o.setdefault("metadata", {}).setdefault("labels", {})["pod-security.kubernetes.io/enforce"] = "restricted"
    return "labels the Namespace pod-security enforce=restricted"


def _prom_flags(ctx, r, o, f):
    for c in _containers(r["kind"], o, f):
        for k in ("args", "command"):
            if c.get(k):
                c[k] = [a for a in c[k] if not str(a).startswith(("--web.enable-admin-api", "--web.enable-lifecycle"))]
    return "removes --web.enable-admin-api / --web.enable-lifecycle"


def _cnpg(ctx, r, o, f):
    s = o.setdefault("spec", {})
    t = f.get("title", "")
    if "instance" in t:
        s["instances"] = 3
        return "instances → 3"
    if "enableSuperuserAccess" in t:
        s["enableSuperuserAccess"] = False
        return "enableSuperuserAccess → false"
    return None


def _cap_add(c, ps):
    caps = _sc(c).setdefault("capabilities", {})
    caps["add"] = [a for a in caps.get("add") or [] if str(a).upper() not in ("SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE")] or None
    if not caps["add"]:
        caps.pop("add")


def _cpu_request(c, ps):
    c.setdefault("resources", {}).setdefault("requests", {}).setdefault("cpu", "100m")


def _mem_equal(c, ps):
    r = c.get("resources") or {}
    if (r.get("limits") or {}).get("memory"):
        r.setdefault("requests", {})["memory"] = r["limits"]["memory"]


def _sa_automount(ctx, r, o, f):
    o["automountServiceAccountToken"] = False
    return "automountServiceAccountToken: false"


# rule -> (fixer, risk note)  (None fixer = needs a human/Claude decision; included in the prompt only)
FIXERS = {
    "CKS-POD-001": (fx_container(lambda c, ps: _sc(c).__setitem__("privileged", False), "privileged: false"),
                    "If the container genuinely needs device access it will stop working; find a narrower capability instead."),
    "CKS-POD-002": (fx_container(lambda c, ps: (_sc(c).__setitem__("runAsNonRoot", True), _sc(c).setdefault("runAsUser", 10001)), "runAsNonRoot + runAsUser 10001"),
                    "Fails to start if the image only works as root, or if files it needs are owned by root. Prefer an image with a non-root USER."),
    "CKS-POD-003": (fx_container(lambda c, ps: _sc(c).__setitem__("allowPrivilegeEscalation", False), "allowPrivilegeEscalation: false"),
                    "Breaks only processes that rely on setuid binaries (e.g. sudo, ping in old images)."),
    "CKS-POD-004": (fx_container(_ro_rootfs, "readOnlyRootFilesystem (+ emptyDir at /tmp)"),
                    "Apps that write outside /tmp (caches, PID files, nginx temp dirs) fail; add an emptyDir for each writable path."),
    "CKS-POD-005": (fx_container(lambda c, ps: _sc(c).setdefault("capabilities", {}).__setitem__("drop", ["ALL"]), "capabilities.drop: [ALL]"),
                    "Binding to ports < 1024 needs NET_BIND_SERVICE added back (or listen on 8080)."),
    "CKS-POD-006": (fx_container(_cap_add, "removes dangerous capabilities.add"), "Whatever needed that capability will fail; confirm what it was for."),
    "CKS-POD-007": (fx_pod(lambda ps, o, r: ps.setdefault("securityContext", {}).__setitem__("seccompProfile", {"type": "RuntimeDefault"}), "pod seccompProfile: RuntimeDefault"),
                    "Very rarely an app uses a syscall RuntimeDefault blocks; test once."),
    "CKS-HOST-001": (fx_pod(_host_ns, "host namespaces off"), "Agents that need the host network/PIDs (CNI, node exporters) break; those usually deserve an exception instead."),
    "CKS-SA-001": (fx_pod(lambda ps, o, r: ps.__setitem__("automountServiceAccountToken", False), "automountServiceAccountToken: false"),
                   "Apps that call the Kubernetes API (operators, controllers) lose their token; set it back to true only for those."),
    "CKS-SA-002": (_dedicated_sa, "Needs RBAC moved to the new ServiceAccount if the default one had any."),
    "CKS-SA-003": (_sa_automount, "Pods using this ServiceAccount stop getting a token unless they opt in."),
    "CKS-SEC-001": (_secret_env, "The real value must be created outside the chart (External Secrets / Sealed Secrets / kubectl)."),
    "CKS-NET-001": (_netpol, "Default-deny blocks traffic from other namespaces, including the ingress controller; add an allow rule for it."),
    "CKS-NET-002": (_tls, "Needs a TLS certificate Secret (cert-manager annotation or pre-created)."),
    "K8S-RES-001": (fx_container(_resources, "requests/limits (memory request = limit)"), "Values are placeholders: size from real usage, or the pod may be OOM-killed / throttled."),
    "K8S-HEALTH-001": (fx_container(_probes, "tcpSocket readiness/liveness probes"), "TCP probes only prove the port is open; an HTTP health endpoint is better."),
    "K8S-NET-001": (_cluster_ip, "Anything reaching the service from outside the cluster loses access; route via an Ingress instead."),
    "K8S-AVAIL-001": (_pdb, "With 1 replica a PDB blocks node drains; make sure there are ≥ 2 replicas."),
    "K8S-API-001": (_api_version, "Newer API versions can change field names (e.g. Ingress v1 backend.service); check the migration guide."),
    "K8S-API-002": (_api_version, "Newer API versions can change field names; check the migration guide."),
    "LRN-SEC-002": (_pss_baseline, "Anything that relied on the host port or sysctl needs another approach (Service, node tuning)."),
    "LRN-SEC-003": (_psa, "Pods that don't meet the restricted profile are rejected in this namespace."),
    "LRN-SEC-007": (_egress, "Egress becomes DNS-only: add allows for databases, APIs and anything else the pods call."),
    "LRN-SEC-008": (lambda ctx, r, o, f: _cluster_ip(ctx, r, o, f) if r["kind"] == "Service" else _ing_auth(ctx, r, o, f),
                    "Users need to log in via SSO (oauth2-proxy URL is a placeholder); external integrations need another path."),
    "LRN-SEC-009": (_prom_flags, "Config reloads need a restart (or a sidecar) instead of POST /-/reload."),
    "LRN-PERF-001": (fx_container(_mem_equal, "memory request = limit"), "Reserves more memory on the node; check cluster capacity."),
    "LRN-PERF-002": (fx_container(_cpu_request, "cpu request 100m"), "Placeholder request: size it from real usage or the HPA scales at the wrong point."),
    "LRN-PERF-003": (fx_pod(_spread, "topologySpreadConstraints (zone + node)"), "With ScheduleAnyway it never blocks scheduling; switch to DoNotSchedule only with enough nodes/zones."),
    "LRN-PERF-004": (fx_container(_liveness_split, "more tolerant liveness probe"), "Hung containers take a little longer to restart."),
    "LRN-PERF-006": (_cnpg, "3 instances triple the database footprint; backups still need an object store configured."),
}
MANUAL = {
    "CKS-SUP-001": "Pick a real version tag (and ideally a digest) for the image.",
    "CKS-SUP-002": "Resolve the tag to a digest (crane digest / docker buildx imagetools inspect).",
    "CKS-HOST-002": "Replace hostPath with a PVC, ConfigMap, Secret or CSI volume.",
    "CKS-RBAC-001": "List the exact verbs/resources the app needs.", "CKS-RBAC-002": "Use resourceNames for specific secrets.",
    "CKS-RBAC-003": "Remove exec/escalate/bind/impersonate.", "CKS-RBAC-004": "Use a namespaced Role if possible.",
    "CKS-SEC-002": "Move to an external secret store / existingSecret pattern.",
    "LRN-SEC-001": "Replace cluster-admin with a least-privilege Role.", "LRN-SEC-004": "Move credentials from the ConfigMap to a Secret.",
    "LRN-SEC-005": "Empty the default; add existingSecret support.", "LRN-SEC-006": "Split credentials out of the URL into a Secret.",
    "LRN-SEC-010": "Disable anonymous access or set org_role Viewer.", "LRN-SEC-011": "Read the admin password from a Secret.",
    "LRN-SEC-012": "Set cookie_secure, disable embedding, add metrics basic auth.", "LRN-SEC-013": "Use sslmode=require (or verify-full).",
    "LRN-SEC-014": "Switch the dependency repository to https:// or oci://.", "LRN-PERF-005": "Mount a PersistentVolumeClaim at the data path.",
    "HELM-CHART-003": "Add a .helmignore.", "HELM-CHART-004": "Add values.schema.json.", "HELM-CHART-005": "Add templates/NOTES.txt.",
    "HELM-TPL-001": "Prefix define names with the chart name.", "HELM-TPL-002": "Remove non-deterministic functions.",
    "HELM-TPL-003": "Use .Release.Namespace.", "HELM-VAL-001": "Remove or wire up unused values.", "HELM-VAL-002": "Move the image to values.",
    "LRN-PERF-006": "Configure spec.backup (barmanObjectStore or a backup plugin) and a ScheduledBackup; needs an object store.",
    "HELM-DEP-001": "Commit Chart.lock.", "HELM-DEP-002": "Constrain dependency versions.", "HELM-CHART-001": "apiVersion: v2.",
    "HELM-CHART-002": "Use SemVer.", "K8S-META-001": "Add app.kubernetes.io/* labels via the labels helper.",
}


def fixability(rule_id):
    return "preview" if rule_id in FIXERS else "manual"


# ----------------------------------------------------------------------------------------------- rendered docs
def _docs(rendered):
    """Split rendered output into (source, text) docs, keeping order."""
    out, cur = [], []
    for ln in rendered.split("\n"):
        if ln.strip() == "---":
            if any(x.strip() for x in cur):
                out.append("\n".join(cur))
            cur = []
        else:
            cur.append(ln)
    if any(x.strip() for x in cur):
        out.append("\n".join(cur))
    res = []
    for t in out:
        m = re.search(r"^# Source: (.+)$", t, re.M)
        try:
            obj = yaml.safe_load(t)
        except yaml.YAMLError:
            obj = None
        res.append(dict(source=m.group(1).strip() if m else "", text=t, obj=obj))
    return res


def _dump(obj):
    return yaml.safe_dump(obj, sort_keys=False, default_flow_style=False, width=120).rstrip()


def _key(o):
    m = o.get("metadata") or {}
    return (o.get("kind"), m.get("name"))


def side_by_side(a, b, context=3):
    """Rows for a side-by-side view: [{t: equal|change|add|del|skip, l, r, ln, rn}]."""
    al, bl = a.split("\n"), b.split("\n")
    rows = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, al, bl, autojunk=False).get_opcodes():
        if tag == "equal":
            n = i2 - i1
            if n > context * 2 + 1:
                for k in range(context):
                    rows.append(dict(t="equal", l=al[i1 + k], r=bl[j1 + k], ln=i1 + k + 1, rn=j1 + k + 1))
                rows.append(dict(t="skip", l=f"… {n - 2 * context} unchanged lines …", r="", ln=None, rn=None))
                for k in range(n - context, n):
                    rows.append(dict(t="equal", l=al[i1 + k], r=bl[j1 + k], ln=i1 + k + 1, rn=j1 + k + 1))
            else:
                for k in range(n):
                    rows.append(dict(t="equal", l=al[i1 + k], r=bl[j1 + k], ln=i1 + k + 1, rn=j1 + k + 1))
        else:
            n = max(i2 - i1, j2 - j1)
            for k in range(n):
                l = al[i1 + k] if i1 + k < i2 else None
                r = bl[j1 + k] if j1 + k < j2 else None
                rows.append(dict(t="change" if l is not None and r is not None else "del" if r is None else "add",
                                 l=l or "", r=r or "", ln=i1 + k + 1 if l is not None else None, rn=j1 + k + 1 if r is not None else None))
    return rows


# ----------------------------------------------------------------------------------------------- plan
def _semver_bump(v, part):
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", str(v or ""))
    if not m:
        return "0.1.1" if part == "patch" else "0.2.0"
    a, b, c = map(int, m.groups())
    return f"{a}.{b}.{c + 1}" if part == "patch" else f"{a}.{b + 1}.0"


REDACT = re.compile(r"^(\s*-?\s*[A-Za-z0-9_.-]*?(?:pass(?:word|wd)?|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential|client[_-]?secret))\s*:\s*(\S.*)$", re.I)


def _redact(text):
    out = []
    for ln in text.split("\n"):
        m = REDACT.match(ln)
        if m and not re.search(r"\{\{|existing|secretname|key\s*:|ref\s*:|\"\"|''|:\s*$", ln, re.I):
            out.append(f"{m.group(1)}: <redacted>")
        else:
            out.append(re.sub(r"(://[^/\s:@]+:)[^@\s/]+@", r"\1<redacted>@", ln))
    return "\n".join(out)


def plan(files, rendered, rule_ids, release="demo", namespace="default", kube_target=None, source=None):
    """Apply fixes for `rule_ids` to the rendered chart, re-check, and build the Claude prompt."""
    work = Path(tempfile.mkdtemp(prefix="fix-"))
    try:
        for p, t in files.items():
            if p.startswith("(") or ".." in Path(p).parts:
                continue
            dest = work / "chart" / p
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(t)
        chart_dir = work / "chart"
        if not (chart_dir / "Chart.yaml").exists():
            raise AnalysisError("Chart.yaml missing from the planner request")
        opts = dict(release=release, namespace=namespace, kube_target=kube_target)
        before = analyse_chart_dir(chart_dir, rendered_override=rendered, keep_objs=True, **opts)
        objs = {k: copy.deepcopy(v) for k, v in before.pop("_objs").items()}
        for r in before["resources"]:
            r["_labels"] = _pod_labels(r["kind"], objs[r["id"]]) if r["kind"] in WORKLOADS else {}
        ctx = Ctx(release, namespace, before["resources"])
        wanted = set(rule_ids)
        changes, touched = [], set()
        byid = {r["id"]: r for r in before["resources"]}
        for f in before["findings"]:
            if f.get("rule") not in wanted or f.get("accepted"):
                continue
            fixer, risk = FIXERS.get(f["rule"], (None, None))
            res = byid.get(f.get("resource"))
            if fixer is None:
                changes.append(dict(rule=f["rule"], title=f["title"], resource=f"{res['kind']}/{res['name']}" if res else "(chart)",
                                    applied=False, summary=MANUAL.get(f["rule"], "Needs a manual change."), risk=""))
                continue
            try:
                summary = fixer(ctx, res, objs[res["id"]], f) if res else fixer(ctx, None, None, f)
            except Exception as e:  # a fixer must never break the preview
                summary = None
                risk = f"(could not preview: {e})"
            if summary:
                if res:
                    touched.add(res["id"])
                changes.append(dict(rule=f["rule"], title=f["title"], resource=f"{res['kind']}/{res['name']}" if res else "(chart)",
                                    applied=True, summary=summary, risk=risk))
            else:
                changes.append(dict(rule=f["rule"], title=f["title"], resource=f"{res['kind']}/{res['name']}" if res else "(chart)",
                                    applied=False, summary=MANUAL.get(f["rule"], "Nothing to change automatically."), risk=risk or ""))
        # rebuild rendered: unchanged docs verbatim, changed docs re-dumped, added docs at the end
        docs = _docs(rendered)
        id_by_key = {(r["kind"], r["name"]): r["id"] for r in before["resources"]}
        parts, panes = [], []
        for d in docs:
            if not isinstance(d["obj"], dict):
                parts.append(d["text"])
                continue
            rid = id_by_key.get(_key(d["obj"]))
            if rid in touched:
                new_text = f"# Source: {d['source']}\n" + _dump(objs[rid])
                old_norm = f"# Source: {d['source']}\n" + _dump(d["obj"])
                parts.append(new_text)
                panes.append(dict(resource=f"{d['obj']['kind']}/{d['obj']['metadata']['name']}", source=d["source"], status="changed",
                                  rows=side_by_side(old_norm, new_text)))
            else:
                parts.append(d["text"])
        for a in ctx.added:
            src = f"{(before.get('chart') or {}).get('name') or 'chart'}/templates/{a['kind'].lower()}-fix.yaml"
            text = f"# Source: {src}\n" + _dump(a)
            parts.append(text)
            panes.append(dict(resource=f"{a['kind']}/{a['metadata']['name']}", source="(new resource)", status="added",
                              rows=side_by_side("", text)))
        fixed_rendered = "---\n" + "\n---\n".join(parts) + "\n"
        after = analyse_chart_dir(chart_dir, rendered_override=fixed_rendered, **opts)
        d = compare.diff(before, after)
        chart = before.get("chart") or {}
        adds_values = any(c["applied"] for c in changes)
        bump = dict(current=chart.get("version"), patch=_semver_bump(chart.get("version"), "patch"),
                    minor=_semver_bump(chart.get("version"), "minor"), recommended="minor" if adds_values else "patch")
        prompt = build_prompt(files, before, after, changes, d, panes, bump, source)
        git = git_commands(chart, changes, bump, source)
        return dict(
            chart=chart, source=source, ruleset=before.get("ruleset"),
            before=dict(score=before["score"], counts=before["counts"]), after=dict(score=after["score"], counts=after["counts"]),
            scoreDelta=d["scoreDelta"], fixed=d["fixed"], introduced=d["new"], changes=changes, panes=panes,
            renderedBefore=rendered, renderedAfter=fixed_rendered, prompt=prompt, git=git, bump=bump,
            topologyAfter=after.get("topology"),
        )
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ----------------------------------------------------------------------------------------------- prompt + git
def build_prompt(files, before, after, changes, d, panes, bump, source):
    chart = before.get("chart") or {}
    cat = rules.CATALOG
    sel = sorted({c["rule"] for c in changes})
    tpl_files = sorted({(f.get("tpl") or {}).get("file") for f in before["findings"] if f.get("rule") in sel and (f.get("tpl") or {}).get("file")})
    tpl_files = [p for p in tpl_files if p in files][:8]
    where = (f"{source.get('repo')} (ref {source.get('ref')}, commit {source.get('commit')}, path {source.get('path') or '.'})"
             if source and source.get("type") == "git" else "the chart in this conversation")
    L = []
    L += [f"# Task: apply Helm/Kubernetes best-practice fixes to the `{chart.get('name')}` chart", "",
          f"Chart: **{chart.get('name')}** version {chart.get('version')} (appVersion {chart.get('appVersion')}), from {where}.",
          f"Checked with helm-visualiser ruleset {before.get('ruleset')}. Current score **{before['score']}**; the previewed fix scores **{after['score']}** "
          f"({d['scoreDelta']:+d}).", "",
          "## What to change", ""]
    for rid in sel:
        r = cat.get(rid, {})
        items = [c for c in changes if c["rule"] == rid]
        L.append(f"### {rid}: {r.get('title', '')}  ({r.get('severity', '')}, {r.get('category', '')})")
        L.append(f"Why: {r.get('why', '')}")
        L.append(f"Fix: `{r.get('fix', '')}`")
        for c in items:
            L.append(f"- {c['resource']}: {c['title']} → {c['summary']}" + (f"  \n  ⚠ Risk: {c['risk']}" if c.get("risk") else ""))
        if r.get("refs"):
            L.append("Refs: " + ", ".join(f"[{x['title']}]({x['url']})" for x in r["refs"][:3]))
        L.append("")
    L += ["## How to implement it", "",
          "1. Change the **templates and values**, not the rendered output. Expose each fix as a value with a **secure default** "
          "(e.g. `securityContext`, `resources`, `networkPolicy.enabled: true`), so existing users can still override it.",
          "2. Keep it backwards compatible: don't rename existing values; document new ones in values.yaml comments (and values.schema.json if present).",
          f"3. Bump `version` in Chart.yaml: **{bump['current']} → {bump[bump['recommended']]}** ({bump['recommended']}: "
          + ("new values were added" if bump["recommended"] == "minor" else "fixes only") + "). Don't change appVersion.",
          "4. For anything you decide **not** to fix, add an entry to `.helm-visualiser.yaml` with `rule`, `resource`, `reason` and an `expires` date ≤ 12 months out.",
          "5. Address every ⚠ risk above (e.g. add emptyDir mounts for paths the app writes, NET_BIND_SERVICE for ports < 1024, NetworkPolicy allows for the ingress controller).",
          "6. Verify: `helm lint`, `helm template` renders, and re-run the check: "
          "`docker run --rm -v \"$PWD:/work\" ghcr.io/mickinsing/helm-visualiser python /app/app/cli.py scan --head /work --fail-on-new high`.", "",
          "## Target rendered output (preview of the fixed manifests)", ""]
    for p in panes[:8]:
        new = "\n".join(r["r"] for r in p["rows"] if r["t"] != "skip" and r["r"] != "")
        L += [f"**{p['resource']}** ({p['status']})", "```yaml", new[:2500], "```", ""]
    L += ["## Current chart source (secrets redacted)", ""]
    for p in ["Chart.yaml", "values.yaml"] + [x for x in tpl_files if x not in ("Chart.yaml", "values.yaml")]:
        if p in files:
            L += [f"`{p}`", "```yaml", _redact(files[p])[:6000], "```", ""]
    L += ["When done, summarise the changes, the new chart version, and anything left as an exception."]
    return "\n".join(L)


def git_commands(chart, changes, bump, source):
    sel = sorted({c["rule"] for c in changes})
    short = "-".join(x.lower() for x in sel[:2]) + (f"-and-{len(sel) - 2}-more" if len(sel) > 2 else "")
    branch = f"fix/helmviz-{chart.get('name') or 'chart'}-{dt.date.today():%Y%m%d}-{short}"[:90]
    path = (source or {}).get("path") or "."
    repo = (source or {}).get("repo") or ""
    clone = f"https://{repo}.git" if repo and "/" in repo else "<repo-url>"
    title = f"{chart.get('name')}: best-practice fixes ({', '.join(sel[:4])}{'…' if len(sel) > 4 else ''})"
    body = "Fixes from helm-visualiser: " + ", ".join(sel) + f". Chart version {bump['current']} → {bump[bump['recommended']]}."
    return dict(branch=branch, title=title, commands="\n".join([
        f"# 1. get the repo (skip if you have it). No write access? fork first: gh repo fork {repo or '<owner/repo>'} --clone",
        f"git clone {clone} && cd \"$(basename {clone} .git)\"" if clone != "<repo-url>" else "cd <your-chart-repo>",
        "git checkout main && git pull",
        f"git checkout -b {branch}",
        "",
        "# 2. make the change: paste the generated prompt into Claude (Claude Code can edit the files directly)",
        f"#    then check the version bump in {path}/Chart.yaml: {bump['current']} -> {bump[bump['recommended']]}",
        f"grep -n '^version:' {path}/Chart.yaml",
        "",
        "# 3. verify",
        f"helm lint {path} && helm template check {path} > /dev/null",
        "",
        "# 4. commit, push, open the PR (the helm-check action will comment before/after scores)",
        f"git add -A && git commit -m \"{title}\"",
        f"git push -u origin {branch}",
        f"gh pr create --fill --title \"{title}\" --body \"{body}\"",
    ]))
