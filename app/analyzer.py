"""Chart analysis: extract -> helm template -> parse -> link -> CKS checks -> walkthrough steps."""
import io
import shutil
import os
import re
import subprocess
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

import yaml

import views
import rules
import deprecations
import exceptions

HELM = os.environ.get("HELM_BIN", "helm")
HELM_TIMEOUT = int(os.environ.get("HELM_TIMEOUT", "30"))
MAX_FILES = 2000
MAX_FILE_BYTES = 512 * 1024
TEXT_EXT = {".yaml", ".yml", ".tpl", ".txt", ".md", ".json", ".helmignore", ".toml", ".conf", ".ini", ".sh", ""}

R = "__rendered__"  # pseudo file name for the helm template output


class AnalysisError(Exception):
    pass


# ---------------------------------------------------------------------------
# Archive handling (path-traversal safe)
# ---------------------------------------------------------------------------
def _safe_target(base: Path, name: str) -> Path:
    target = (base / name).resolve()
    if not str(target).startswith(str(base.resolve()) + os.sep):
        raise AnalysisError(f"unsafe path in archive: {name}")
    return target


def extract_archive(data: bytes, filename: str, work: Path) -> Path:
    dest = work / "src"
    dest.mkdir()
    count = 0
    if filename.lower().endswith(".zip") or data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                count += 1
                if count > MAX_FILES or info.file_size > MAX_FILE_BYTES * 4:
                    raise AnalysisError("archive too large")
                t = _safe_target(dest, info.filename)
                t.parent.mkdir(parents=True, exist_ok=True)
                t.write_bytes(z.read(info))
    else:
        try:
            tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
        except tarfile.TarError:
            raise AnalysisError("not a .tgz / .tar.gz / .zip chart archive")
        with tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue  # skip links, devices, dirs
                count += 1
                if count > MAX_FILES or m.size > MAX_FILE_BYTES * 4:
                    raise AnalysisError("archive too large")
                t = _safe_target(dest, m.name)
                t.parent.mkdir(parents=True, exist_ok=True)
                t.write_bytes(tf.extractfile(m).read())
    # locate the chart root = shallowest dir containing Chart.yaml
    charts = sorted(dest.rglob("Chart.yaml"), key=lambda p: len(p.parts))
    if not charts:
        raise AnalysisError("no Chart.yaml found in the archive")
    return charts[0].parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _read_files(chart_dir: Path):
    files = {}
    for p in sorted(chart_dir.rglob("*")):
        if not p.is_file() or len(files) >= MAX_FILES:
            continue
        rel = p.relative_to(chart_dir).as_posix()
        if p.suffix.lower() not in TEXT_EXT and p.name != ".helmignore":
            continue
        if p.stat().st_size > MAX_FILE_BYTES:
            files[rel] = f"# (file too large to display: {p.stat().st_size} bytes)\n"
            continue
        try:
            files[rel] = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
    return files


def _run(args, cwd=None):
    try:
        p = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=HELM_TIMEOUT)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "helm binary not found in container"
    except subprocess.TimeoutExpired:
        return 124, "", "helm timed out"


def _line_of(text: str, pattern, start=1, end=None, regex=False):
    """1-based line number of first line (within [start,end]) matching pattern."""
    lines = text.split("\n")
    end = end or len(lines)
    pats = pattern if isinstance(pattern, (list, tuple)) else [pattern]
    for pat in pats:
        for i in range(start - 1, min(end, len(lines))):
            ln = lines[i]
            if regex:
                hit = re.search(pat, ln)
            elif pat.endswith(":"):
                hit = ln.strip().lstrip("- ").startswith(pat)
            else:
                hit = pat in ln
            if hit:
                return i + 1
    return None


def _values_index(text: str):
    """Map dotted values paths -> line numbers using indentation tracking."""
    idx, stack = {}, []  # stack of (indent, key)
    for n, line in enumerate(text.split("\n"), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^(\s*)(?:-\s+)?([A-Za-z0-9_\-\.\"']+)\s*:(\s|$)", line)
        if not m:
            continue
        indent = len(m.group(1)) + (2 if line.lstrip().startswith("- ") else 0)
        key = m.group(2).strip("\"'")
        while stack and stack[-1][0] >= indent:
            stack.pop()
        stack.append((indent, key))
        idx.setdefault(".".join(k for _, k in stack), n)
    return idx


def _split_segments(text: str):
    """Split a template file on '---' separators -> list of (start, end) line ranges."""
    lines = text.split("\n")
    segs, s = [], 1
    for i, ln in enumerate(lines, 1):
        if ln.strip() == "---":
            if i - 1 >= s and any(x.strip() for x in lines[s - 1:i - 1]):
                segs.append((s, i - 1))
            s = i + 1
    if any(x.strip() for x in lines[s - 1:]):
        segs.append((s, len(lines)))
    return segs or [(1, len(lines))]


def _strip_root(src: str) -> str:
    return src.split("/", 1)[1] if "/" in src else src


# ---------------------------------------------------------------------------
# Domain knowledge
# ---------------------------------------------------------------------------
INSTALL_ORDER = [
    "Namespace", "NetworkPolicy", "ResourceQuota", "LimitRange", "PodSecurityPolicy",
    "PodDisruptionBudget", "ServiceAccount", "Secret", "SecretList", "ConfigMap", "StorageClass",
    "PersistentVolume", "PersistentVolumeClaim", "CustomResourceDefinition", "ClusterRole",
    "ClusterRoleList", "ClusterRoleBinding", "ClusterRoleBindingList", "Role", "RoleList",
    "RoleBinding", "RoleBindingList", "Service", "DaemonSet", "Pod", "ReplicationController",
    "ReplicaSet", "Deployment", "HorizontalPodAutoscaler", "StatefulSet", "Job", "CronJob",
    "IngressClass", "Ingress", "APIService",
]
WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "ReplicaSet"}

TIER = {  # column in the diagram
    "Namespace": 0, "ServiceAccount": 0, "Role": 0, "ClusterRole": 0, "RoleBinding": 0,
    "ClusterRoleBinding": 0, "ConfigMap": 1, "Secret": 1, "PersistentVolumeClaim": 1,
    "Deployment": 2, "StatefulSet": 2, "DaemonSet": 2, "Job": 2, "CronJob": 2, "Pod": 2,
    "HorizontalPodAutoscaler": 2, "PodDisruptionBudget": 2,
    "Service": 3, "NetworkPolicy": 3, "Ingress": 4, "IngressClass": 4,
}

KIND_INFO = {
    "ServiceAccount": ("Identity the pods run as. API calls from the pod authenticate with this account's token.",
                       "CKS: one ServiceAccount per app, never `default`. Set `automountServiceAccountToken: false` unless the app talks to the API server."),
    "Role": ("Namespaced set of permissions (verbs on resources).",
             "CKS: least privilege. Avoid `*` verbs/resources and avoid `get/list/watch` on `secrets` unless you truly need it."),
    "ClusterRole": ("Cluster-wide set of permissions.",
                    "CKS: prefer a namespaced Role. ClusterRoles with wide verbs are a common privilege-escalation path."),
    "RoleBinding": ("Grants a Role to subjects (users, groups, ServiceAccounts) in one namespace.",
                    "CKS: check every subject. Binding to `system:authenticated` or to the default SA widens access."),
    "ClusterRoleBinding": ("Grants a ClusterRole across all namespaces.",
                           "CKS: high blast radius. Make sure the chart really needs cluster scope."),
    "ConfigMap": ("Non-secret configuration, mounted as files or env vars.",
                  "CKS: never put credentials here. ConfigMaps are readable by anyone with `get configmaps`."),
    "Secret": ("Sensitive data, base64-encoded (not encrypted) in the manifest.",
               "CKS: enable encryption at rest (EncryptionConfiguration) and don't keep real secrets in values.yaml. Prefer an external secret store."),
    "PersistentVolumeClaim": ("Requests storage for the pods.", "Check the storageClass and access mode."),
    "Service": ("Stable virtual IP / DNS name that load-balances to pods matching its selector.",
                "CKS: `NodePort`/`LoadBalancer` expose the app outside the cluster. Use ClusterIP + Ingress unless you need direct exposure."),
    "Deployment": ("Manages a ReplicaSet of identical, stateless pods and rolls out updates.",
                   "CKS: this is where pod hardening lives: securityContext, resources, image pinning, SA token mounting."),
    "StatefulSet": ("Pods with stable identity and storage (databases, queues).",
                    "CKS: same pod hardening rules as Deployments apply."),
    "DaemonSet": ("Runs one pod per node, usually for agents.",
                  "CKS: DaemonSets often ask for hostPath/hostNetwork/privileged. Question every one of them."),
    "Job": ("Runs pods to completion.", "CKS: same pod hardening rules apply. Hooks often run as Jobs."),
    "CronJob": ("Runs a Job on a schedule.", "CKS: same pod hardening rules apply."),
    "Pod": ("A bare pod (often a Helm test hook).", "CKS: same pod hardening rules apply."),
    "HorizontalPodAutoscaler": ("Scales a workload's replicas based on metrics.",
                                "Needs CPU/memory requests set on the target pods to work."),
    "PodDisruptionBudget": ("Limits how many pods can be voluntarily evicted at once.", "Availability during node drains/upgrades."),
    "NetworkPolicy": ("Firewall rules for pod traffic (ingress/egress) by label, namespace or CIDR.",
                      "CKS: start from default-deny, then allow only the flows you need. Policies need a CNI that enforces them."),
    "Ingress": ("HTTP(S) routing from outside the cluster to Services.",
                "CKS: terminate TLS (`spec.tls`) and keep the controller patched."),
    "Namespace": ("Isolation boundary for names, RBAC, quotas and policies.",
                  "CKS: label it with Pod Security Admission, e.g. `pod-security.kubernetes.io/enforce: restricted`."),
}

FIX = {
    "runAsNonRoot": "securityContext:\n  runAsNonRoot: true\n  runAsUser: 10001",
    "allowPrivilegeEscalation": "securityContext:\n  allowPrivilegeEscalation: false",
    "readOnlyRootFilesystem": "securityContext:\n  readOnlyRootFilesystem: true\n# mount an emptyDir at /tmp if the app needs scratch space",
    "capabilities": "securityContext:\n  capabilities:\n    drop: [\"ALL\"]",
    "privileged": "securityContext:\n  privileged: false",
    "seccomp": "securityContext:\n  seccompProfile:\n    type: RuntimeDefault",
    "resources": "resources:\n  requests: { cpu: 100m, memory: 128Mi }\n  limits:   { memory: 256Mi }",
    "image": "image: registry.example.com/app:1.4.2@sha256:<digest>",
    "automount": "automountServiceAccountToken: false",
    "host": "hostNetwork: false\nhostPID: false\nhostIPC: false",
    "probes": "readinessProbe:\n  httpGet: { path: /healthz, port: http }\nlivenessProbe:\n  httpGet: { path: /healthz, port: http }",
    "netpol": "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default-deny\nspec:\n  podSelector: {}\n  policyTypes: [Ingress, Egress]",
    "tls": "spec:\n  tls:\n    - hosts: [app.example.com]\n      secretName: app-tls",
    "rbac": "rules:\n  - apiGroups: [\"\"]\n    resources: [\"configmaps\"]\n    verbs: [\"get\"]",
    "secretenv": "env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef: { name: app-db, key: password }",
}

SEV_WEIGHT = {"critical": 25, "high": 12, "medium": 6, "low": 2, "info": 0}


def _pod_spec(kind, obj):
    spec = obj.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
    return ((spec.get("template") or {}).get("spec")) or {}


def _pod_labels(kind, obj):
    spec = obj.get("spec") or {}
    if kind == "Pod":
        return (obj.get("metadata") or {}).get("labels") or {}
    if kind == "CronJob":
        t = ((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}
    else:
        t = spec.get("template") or {}
    return (t.get("metadata") or {}).get("labels") or {}


def _matches(selector, labels):
    if not selector:
        return False
    return all(labels.get(k) == v for k, v in selector.items())


# ---------------------------------------------------------------------------
# Security / best-practice checks
# ---------------------------------------------------------------------------
def _check_workload(res, obj):
    out = []
    kind = res["kind"]
    ps = _pod_spec(kind, obj)
    psc = ps.get("securityContext") or {}

    anchor = [None]

    def add(sev, key, title, detail, fix, tpl_keys, out_keys=None):
        out.append(dict(sev=sev, key=key, title=title, detail=detail, fix=FIX.get(fix, ""),
                        tpl_keys=tpl_keys, out_keys=out_keys or tpl_keys, anchor=anchor[0]))

    for flag in ("hostNetwork", "hostPID", "hostIPC"):
        if ps.get(flag):
            add("critical", flag, f"{flag}: true", "The pod shares the node's namespace and can see or affect host processes and traffic.",
                "host", [flag])
    for v in ps.get("volumes") or []:
        if "hostPath" in v:
            add("high", "hostPath", f"hostPath volume '{v.get('name')}'",
                "hostPath mounts give the pod direct access to the node filesystem, a classic container-escape path.",
                "", ["hostPath"])
    if ps.get("automountServiceAccountToken") is not False:
        add("medium", "automount", "ServiceAccount token auto-mounted",
            "Every container gets an API token at /var/run/secrets/kubernetes.io/serviceaccount. If the app never calls the API, an attacker who gets in gets the token too.",
            "automount", ["automountServiceAccountToken", "serviceAccountName", "spec:"])
    if not ps.get("serviceAccountName") and not ps.get("serviceAccount"):
        add("low", "defaultsa", "Runs as the `default` ServiceAccount",
            "Give each workload its own ServiceAccount so RBAC can be scoped to it.", "",
            ["serviceAccountName", "spec:"])
    pod_seccomp = (psc.get("seccompProfile") or {}).get("type")

    containers = (ps.get("containers") or []) + (ps.get("initContainers") or [])
    for c in containers:
        cn = c.get("name", "?")
        anchor[0] = f"name: {cn}"
        sc = c.get("securityContext") or {}
        img = c.get("image") or ""
        tag = img.split("@")[0].rsplit(":", 1)[1] if ":" in img.split("@")[0].split("/")[-1] else ""
        if "@sha256:" not in img:
            if not tag or tag == "latest":
                add("high", "image", f"[{cn}] image not pinned ({img or 'empty'})",
                    "`latest` or a missing tag means you can't tell what's running, and a re-pull can silently change it.",
                    "image", ["image:", "tag"])
            else:
                add("info", "image", f"[{cn}] image pinned by tag, not digest",
                    "Tags can be re-pushed. A digest (@sha256:…) makes the image immutable and is what admission policies usually check.",
                    "image", ["image:"])
        if sc.get("privileged"):
            add("critical", "privileged", f"[{cn}] privileged: true",
                "A privileged container has every capability and access to host devices. It's effectively root on the node.",
                "privileged", ["privileged"])
        nonroot = sc.get("runAsNonRoot", psc.get("runAsNonRoot"))
        uid = sc.get("runAsUser", psc.get("runAsUser"))
        if not nonroot and not (isinstance(uid, int) and uid > 0):
            add("high", "runAsNonRoot", f"[{cn}] may run as root",
                "Without `runAsNonRoot: true` (or a non-zero runAsUser) the container runs as whatever user the image specifies, often root.",
                "runAsNonRoot", ["runAsNonRoot", "runAsUser", "securityContext", "containers:"])
        if sc.get("allowPrivilegeEscalation") is not False:
            add("high", "allowPrivilegeEscalation", f"[{cn}] allowPrivilegeEscalation not false",
                "setuid binaries can let a process gain more privileges than its parent. The `restricted` Pod Security Standard requires this to be false.",
                "allowPrivilegeEscalation", ["allowPrivilegeEscalation", "securityContext", "containers:"])
        if not sc.get("readOnlyRootFilesystem"):
            add("medium", "readOnlyRootFilesystem", f"[{cn}] writable root filesystem",
                "A read-only root FS stops attackers dropping tools or modifying binaries in the container.",
                "readOnlyRootFilesystem", ["readOnlyRootFilesystem", "securityContext", "containers:"])
        drops = [str(x).upper() for x in ((sc.get("capabilities") or {}).get("drop") or [])]
        if "ALL" not in drops:
            add("medium", "capabilities", f"[{cn}] capabilities not dropped",
                "Containers get a default set of Linux capabilities (e.g. NET_RAW). Drop ALL and add back only what's needed.",
                "capabilities", ["capabilities", "securityContext", "containers:"])
        adds = (sc.get("capabilities") or {}).get("add") or []
        if any(str(a).upper() in ("SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE") for a in adds):
            add("high", "capadd", f"[{cn}] adds dangerous capabilities {adds}",
                "These capabilities are frequently enough to break out of the container.", "capabilities", ["add:", "capabilities"])
        if (sc.get("seccompProfile") or {}).get("type", pod_seccomp) not in ("RuntimeDefault", "Localhost"):
            add("medium", "seccomp", f"[{cn}] no seccomp profile",
                "Seccomp filters syscalls. `RuntimeDefault` blocks dozens of rarely-needed, risky syscalls at near-zero cost.",
                "seccomp", ["seccompProfile", "securityContext", "containers:"])
        r = c.get("resources") or {}
        lim, req = r.get("limits") or {}, r.get("requests") or {}
        if not lim.get("memory") or not req.get("cpu"):
            add("medium", "resources", f"[{cn}] missing resource requests/limits",
                "Without requests the scheduler can't place pods well. Without a memory limit one pod can starve the node (a DoS vector).",
                "resources", ["resources", "containers:"])
        if res["kind"] in ("Deployment", "StatefulSet", "DaemonSet") and not c.get("readinessProbe") and c in (ps.get("containers") or []):
            add("low", "probes", f"[{cn}] no readiness/liveness probes",
                "Probes let Kubernetes route traffic only to healthy pods and restart hung ones.", "probes",
                ["Probe", "containers:"])
        for e in c.get("env") or []:
            if "value" in e and re.search(r"pass|secret|token|apikey|api_key|credential", str(e.get("name", "")), re.I):
                add("high", "secretenv", f"[{cn}] secret-looking env var '{e.get('name')}' set as plain value",
                    "This value is visible in the manifest, in `kubectl describe` and in values.yaml. Reference a Secret instead.",
                    "secretenv", [e.get("name", "env:")])
    return out


def _check_other(res, obj):
    out, kind = [], res["kind"]

    def add(sev, key, title, detail, fix, keys):
        out.append(dict(sev=sev, key=key, title=title, detail=detail, fix=FIX.get(fix, ""), tpl_keys=keys, out_keys=keys, anchor=None))

    if kind in ("Role", "ClusterRole"):
        for rule in obj.get("rules") or []:
            verbs, resources = rule.get("verbs") or [], rule.get("resources") or []
            if "*" in verbs or "*" in resources:
                add("high", "rbacwild", "Wildcard in RBAC rule", f"verbs={verbs} resources={resources}. Wildcards grant future resources/verbs too.", "rbac", ["*", "rules:"])
            if "secrets" in resources and set(verbs) & {"get", "list", "watch", "*"}:
                add("medium", "rbacsecrets", "Can read Secrets", "`list`/`watch` on secrets returns every secret in scope.", "rbac", ["secrets", "rules:"])
            if set(resources) & {"pods/exec", "pods/attach"} or "escalate" in verbs or "bind" in verbs or "impersonate" in verbs:
                add("high", "rbacesc", "Escalation-capable permissions", "exec/attach/escalate/bind/impersonate can be used to gain more privileges.", "rbac", ["rules:"])
        if kind == "ClusterRole":
            add("info", "clusterscope", "Cluster-scoped permissions", "Confirm the chart needs cluster-wide access rather than a namespaced Role.", "", ["kind:"])
    if kind == "Service" and (obj.get("spec") or {}).get("type") in ("NodePort", "LoadBalancer"):
        add("low", "svcexpose", f"Service type {obj['spec']['type']}", "Exposes the app outside the cluster directly. Make sure that's intended.", "", ["type:"])
    if kind == "Ingress" and not (obj.get("spec") or {}).get("tls"):
        add("medium", "tls", "Ingress without TLS", "Traffic reaches the cluster in plaintext.", "tls", ["spec:", "rules:"])
    if kind == "Secret":
        add("info", "secretvalues", "Secret rendered from chart values",
            "If the data comes from values.yaml it's probably committed to git. Consider External Secrets / Sealed Secrets / CSI secrets store, plus encryption at rest.",
            "", ["data:", "stringData:"])
    if kind == "ServiceAccount" and obj.get("automountServiceAccountToken") is not False:
        add("low", "saautomount", "SA does not disable token automount",
            "You can set `automountServiceAccountToken: false` on the ServiceAccount itself as the default for all pods using it.",
            "automount", ["kind:"])
    return out


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------
SET_LINE = re.compile(r"^[A-Za-z0-9_\-\.\[\]\\]+=.*$")


def _value_files(files):
    """Extra values files shipped with the chart (values-prod.yaml, envs/dev.yaml, ...)."""
    out = []
    for p in files:
        name = p.split("/")[-1]
        if p.startswith(("templates/", "charts/")) or p == "values.yaml" or not name.endswith((".yaml", ".yml")):
            continue
        if "values" in name.lower() or p.split("/")[0] in ("values", "envs", "environments", "overlays", "clusters"):
            out.append(p)
    return sorted(out)


def _required_from_error(files, render_error, found):
    """Catch values named only in the fail() message, e.g. 'orgID and clusterName must be set'."""
    if not render_error:
        return found
    words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", render_error))
    known = {p.split(".")[-1]: p for t in files.values() for p in re.findall(r"\.Values\.([A-Za-z0-9_\.]+)", t)}
    have = {f["path"] for f in found}
    m = re.search(r"(?:error calling (?:fail|required)|Fail:)\s*:?\s*(.*)", render_error)
    for w in sorted(words):
        if w in known and known[w].rstrip(".") not in have and len(w) > 3:
            p = known[w].rstrip(".")
            loc = next(((f, i + 1) for f, t in files.items() for i, ln in enumerate(t.split("\n")) if f".Values.{p}" in ln), ("", 1))
            found.append(dict(path=p, file=loc[0], line=loc[1], message=(m.group(1).strip()[:160] if m else "")))
            have.add(p)
    return found


def _required_values(files):
    """Values a chart insists on: `required ... .Values.x` and `.Values.x` guarding a `fail`."""
    found = {}
    for p, txt in files.items():
        if not p.startswith("templates/"):
            continue
        lines = txt.split("\n")
        for i, ln in enumerate(lines):
            if not re.search(r"\b(required|fail)\b", ln):
                continue
            window = "\n".join(lines[max(0, i - 3):i + 1]) if "fail" in ln else ln
            msg = re.search(r'(?:required|fail)\s+(?:\(\s*printf\s+)?"([^"]*)"', ln)
            for m in re.finditer(r"\.Values\.([A-Za-z0-9_\.]+)", window):
                found.setdefault(m.group(1).rstrip("."), dict(path=m.group(1).rstrip("."), file=p, line=i + 1,
                                                               message=msg.group(1) if msg else ""))
    return list(found.values())


OPERATORS = {  # apiVersion group -> the third-party tool that must be installed
    "argoproj.io": "Argo (CD / Rollouts / Workflows)", "cert-manager.io": "cert-manager",
    "acme.cert-manager.io": "cert-manager", "external-secrets.io": "External Secrets Operator",
    "monitoring.coreos.com": "Prometheus Operator", "keda.sh": "KEDA", "networking.istio.io": "Istio",
    "security.istio.io": "Istio", "traefik.io": "Traefik", "traefik.containo.us": "Traefik",
    "bitnami.com": "Sealed Secrets", "kyverno.io": "Kyverno", "policy.sigstore.dev": "Sigstore policy-controller",
    "cilium.io": "Cilium", "gateway.networking.k8s.io": "Gateway API controller",
    "secrets-store.csi.x-k8s.io": "Secrets Store CSI driver", "snapshot.storage.k8s.io": "CSI snapshotter",
    "kustomize.toolkit.fluxcd.io": "Flux", "helm.toolkit.fluxcd.io": "Flux", "source.toolkit.fluxcd.io": "Flux",
    "postgresql.cnpg.io": "CloudNativePG", "velero.io": "Velero", "vault.hashicorp.com": "Vault",
}


def _bypass_checks(chart_dir: Path):
    """Preview mode: neutralise fail/required in a scratch copy so the chart renders for the diagram."""
    n = 0
    for p in chart_dir.rglob("*"):
        if not p.is_file() or "templates" not in p.parts or p.suffix not in (".yaml", ".yml", ".tpl", ".txt"):
            continue
        t = p.read_text(encoding="utf-8", errors="replace")
        t2 = re.sub(r'\brequired\s+("(?:[^"\\]|\\.)*"|\(\s*printf[^)]*\))\s*', 'default "setme-required" ', t)
        t2 = re.sub(r"(\{\{-?\s*)fail\b", r"\1$_ := list", t2)
        t2 = re.sub(r"\(\s*fail\b", "(list", t2)
        if t2 != t:
            n += 1
            p.write_text(t2, encoding="utf-8")
    return n


def _placeholder(path):
    return "setme-" + re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-")


def _externals(files, resources, required, render_error):
    """Things the chart relies on that Helm itself doesn't provide."""
    ext = []

    def add(key, label, category, detail, pointers, consumers):
        ext.append(dict(id=f"x{len(ext)}", key=key, label=label, category=category, detail=detail,
                        pointers=pointers[:30], consumers=sorted(set(consumers))))

    by_src = {}
    for r in resources:
        by_src.setdefault(r["source"], []).append(r)

    def consumers_of_lines(hits):
        out = []
        for f, ln in hits:
            for r in by_src.get(f, []):
                if r["tplStart"] <= ln <= r["tplEnd"]:
                    out.append(r["id"])
            if f.endswith(".tpl"):  # a helper: anyone including it from that file is affected, approximate with all
                pass
        return out

    # 1. values that must come from outside (Argo parameters, CI, etc.)
    if required:
        blob = " ".join([render_error or ""] + [r.get("message", "") for r in required])
        who = "ArgoCD" if re.search(r"argo", blob, re.I) else "Deploy-time"
        cons = []
        for r in resources:
            seg = "\n".join(files.get(r["source"], "").split("\n")[r["tplStart"] - 1:r["tplEnd"]])
            if any(f".Values.{q['path']}" in seg for q in required):
                cons.append(r["id"])
        add("values", f"{who} values", "values",
            f"The chart refuses to render unless these are supplied at deploy time: "
            + ", ".join(f"`{q['path']}`" for q in required)
            + (". The error text says they come from **ArgoCD** (Application `spec.source.helm.parameters`)." if who == "ArgoCD" else "."),
            [dict(file=q["file"], line=q["line"], label=q["path"]) for q in required], cons)

    # 2. lookup: reads live objects from the cluster; `helm template` always gets an empty result
    hits = [(p, i + 1) for p, t in files.items() if p.startswith("templates/")
            for i, ln in enumerate(t.split("\n")) if re.search(r"\blookup\s", ln)]
    if hits:
        add("lookup", "Live cluster (lookup)", "cluster",
            "`lookup` queries the real cluster during install. `helm template` and ArgoCD both render it as an **empty map**, "
            "so whatever depends on it (reusing an existing Secret's password, for example) will look different in this preview than on a real `helm install`.",
            [dict(file=f, line=l, label="lookup") for f, l in hits], consumers_of_lines(hits))

    # 3. capabilities: output depends on which APIs / k8s version the cluster has
    hits = [(p, i + 1) for p, t in files.items() if p.startswith("templates/")
            for i, ln in enumerate(t.split("\n")) if ".Capabilities." in ln]
    if hits:
        add("caps", "Cluster capabilities", "cluster",
            "Templates branch on `.Capabilities` (installed APIs or Kubernetes version). Offline, Helm assumes a default set, "
            "so resources gated on CRDs (ServiceMonitor, for example) may be missing from this preview.",
            [dict(file=f, line=l, label=".Capabilities") for f, l in hits], consumers_of_lines(hits))

    # 4. third-party operators whose CRDs the chart creates
    ops = {}
    for r in resources:
        group = (r.get("apiVersion") or "").split("/")[0] if "/" in (r.get("apiVersion") or "") else ""
        tool = OPERATORS.get(group) or next((v for k, v in OPERATORS.items() if group.endswith("." + k)), None)
        if not tool and group and "." in group and not group.endswith("k8s.io") and group not in ("apps", "batch", "policy", "autoscaling"):
            tool = f"CRD: {group}"
        if tool:
            ops.setdefault(tool, []).append(r)
    for tool, rs in ops.items():
        add(f"op:{tool}", tool, "operator",
            f"{len(rs)} resource(s) use this tool's CRDs. It must already be installed in the cluster, otherwise the install fails with `no matches for kind`.",
            [dict(file=r["source"], line=r["tplStart"], label=f"{r['kind']}/{r['name']}") for r in rs], [r["id"] for r in rs])

    # 5. ArgoCD annotations (sync waves, hooks, compare options)
    rs = [r for r in resources if any(a.startswith("argocd.argoproj.io/") for a in r.get("annotations", []))]
    if rs:
        add("argo-ann", "ArgoCD sync behaviour", "argo",
            "These resources carry `argocd.argoproj.io/*` annotations (sync-wave, hook, sync-options). Argo applies them in waves; plain Helm ignores them.",
            [dict(file=r["source"], line=r["tplStart"], label=f"{r['kind']}/{r['name']}") for r in rs], [r["id"] for r in rs])

    # 6. objects referenced but not created by the chart (existingSecret patterns)
    missing = {}
    for r in resources:
        for kind, name, why in r.get("missing", []):
            missing.setdefault((kind, name), []).append((r, why))
    for (kind, name), refs in missing.items():
        add(f"missing:{kind}:{name}", f"{kind} {name}", "existing",
            f"Referenced ({', '.join(sorted({w for _, w in refs}))}) but **not created by this chart**. It must already exist in the namespace, "
            "often created by External Secrets, Vault, a platform team or a previous release.",
            [dict(file=r["source"], line=r["tplStart"], label=f"{r['kind']}/{r['name']}") for r, _ in refs], [r["id"] for r, _ in refs])
    return ext


def _skeleton(paths):
    root = {}
    for p in paths:
        node, parts = root, p.split(".")
        for k in parts[:-1]:
            node = node.setdefault(k, {}) if isinstance(node.get(k, {}), dict) else node
        node.setdefault(parts[-1], "CHANGE-ME")
    return yaml.safe_dump(root, sort_keys=False) if root else ""


def _from_argo_application(text, available_vf):
    """If the override is an ArgoCD Application, pull out what Argo would pass to helm."""
    if "kind:" not in text or "Application" not in text:
        return None
    try:
        docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except yaml.YAMLError:
        return None
    app = next((d for d in docs if d.get("kind") == "Application"), None)
    if not app:
        return None
    spec = app.get("spec") or {}
    sources = [spec["source"]] if spec.get("source") else (spec.get("sources") or [])
    sets, inline, vfs = [], [], []
    for src in sources:
        h = (src or {}).get("helm") or {}
        for p in h.get("parameters") or []:
            if p.get("name") is not None:
                sets.append(("--set-string" if p.get("forceString") else "--set", f"{p['name']}={p.get('value', '')}"))
        if isinstance(h.get("values"), str) and h["values"].strip():
            inline.append(h["values"])
        if isinstance(h.get("valuesObject"), dict):
            inline.append(yaml.safe_dump(h["valuesObject"], sort_keys=False))
        for vf in h.get("valueFiles") or []:
            vf = str(vf).lstrip("./")
            match = next((a for a in available_vf if a == vf or a.endswith("/" + vf) or vf.endswith(a)), None)
            if match:
                vfs.append(match)
    # several inline blocks: last one wins, like multiple -f files
    merged = {}
    for block in inline:
        merged = _deep_merge(merged, yaml.safe_load(block) or {})
    return sets, (yaml.safe_dump(merged, sort_keys=False) if merged else ""), vfs


def _deep_merge(a, b):
    out = dict(a)
    for k, v in b.items():
        out[k] = _deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def analyse_chart_dir(chart_dir: Path, release="demo", namespace="default", overrides="", value_files=(),
                      set_lines=(), bypass=False, kube_target=None, repo_exceptions=None):
    chart_dir = Path(chart_dir)
    t0 = time.time()
    if not (chart_dir / "Chart.yaml").exists():
        raise AnalysisError("Chart.yaml not found")
    if not re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", release):
        release = "demo"
    if not re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", namespace):
        namespace = "default"

    files = _read_files(chart_dir)
    try:
        chart = yaml.safe_load(files.get("Chart.yaml", "")) or {}
    except yaml.YAMLError as e:
        raise AnalysisError(f"Chart.yaml is not valid YAML: {e}")

    notes = []
    if chart.get("dependencies") and not (chart_dir / "charts").exists():
        rc, _, err = _run([HELM, "dependency", "build", str(chart_dir)])
        notes.append("Fetched dependencies with `helm dependency build`." if rc == 0
                     else f"Dependencies could not be fetched: {err.strip()[:300]}")

    # Extra values, the way ArgoCD passes them: valueFiles (-f) then parameters (--set) / inline values (-f)
    available_vf = _value_files(files)
    extra, cleanup = [], []
    used_vf = [v for v in value_files if v in available_vf]
    for v in used_vf:
        extra += ["-f", str(chart_dir / v)]
    overrides = (overrides or "").strip()
    argo_note = ""
    argo = _from_argo_application(overrides, available_vf)
    if argo:
        overrides_src = overrides
        sets, inline, vfs = argo
        for v in vfs:
            if v not in used_vf:
                used_vf.append(v)
                extra += ["-f", str(chart_dir / v)]
        overrides = inline
        for flag, l in sets:
            extra += [flag, l]
        argo_note = (f"Read ArgoCD Application: {len(sets)} parameter(s), "
                     f"{'inline values, ' if inline else ''}{len(vfs)} matching valueFile(s).")
        files["(argo application)"] = overrides_src + "\n"
    if overrides:
        lines = [l.strip() for l in overrides.split("\n") if l.strip() and not l.strip().startswith("#")]
        if lines and all(SET_LINE.match(l) for l in lines):
            for l in lines:
                extra += ["--set", l]
        else:
            try:
                yaml.safe_load(overrides)
            except yaml.YAMLError as e:
                raise AnalysisError(f"Your values override is not valid YAML: {e}")
            fd, ov = tempfile.mkstemp(prefix="overrides-", suffix=".yaml")  # /tmp: the app's FS is read-only
            with os.fdopen(fd, "w") as fh:
                fh.write(overrides + "\n")
            cleanup.append(ov)
            extra += ["-f", ov]
        files["(your overrides)"] = overrides + "\n"

    # manual answers from the "required values" form
    for l in set_lines:
        if SET_LINE.match(l):
            extra += ["--set-string", l]

    render_dir, scratch = chart_dir, None
    if bypass:  # never touch the original (it may be the read-only sample or mount)
        scratch = Path(tempfile.mkdtemp(prefix="bypass-"))
        render_dir = scratch / chart_dir.name
        shutil.copytree(chart_dir, render_dir)
        n = _bypass_checks(render_dir)
        notes.append(f"**Preview mode:** `fail`/`required` checks were switched off in {n} template file(s) so the chart could render. "
                     "Anything marked `setme-…` is a placeholder, not a real value.")

    rc, rendered, err = _run([HELM, "template", release, str(render_dir), "--namespace", namespace] + extra)
    render_error = err.strip() if rc != 0 else ""
    lrc, lout, lerr = _run([HELM, "lint", str(render_dir)] + extra)
    if scratch:
        shutil.rmtree(scratch, ignore_errors=True)
    lint = (lout + lerr).strip()
    for p in cleanup:
        os.unlink(p)
    required = _required_from_error(files, render_error, _required_values(files))
    if argo_note:
        notes.append(argo_note)

    resources = _parse_rendered(rendered, files)
    _link(resources)
    findings = _findings(resources, files, rendered)

    # global: NetworkPolicy presence
    if resources and not any(r["kind"] == "NetworkPolicy" for r in resources) and any(r["kind"] in WORKLOADS for r in resources):
        findings.append(dict(id=f"f{len(findings)}", sev="medium", key="netpol", resource=None,
                             title="No NetworkPolicy in chart",
                             detail="Pods accept traffic from anywhere in the cluster. Ship a default-deny policy plus explicit allows (or make sure the platform provides one).",
                             fix=FIX["netpol"], tpl=None, out=None))

    values_text = files.get("values.yaml", "")
    vindex = _values_index(values_text)
    for r in resources:
        r["values"] = _values_refs(files.get(r["source"], ""), r["tplStart"], r["tplEnd"], vindex)
        r["helpers"] = _helper_refs(files, r)

    externals = _externals(files, resources, required, render_error)
    for x in externals:
        for rid in x["consumers"]:
            next(r for r in resources if r["id"] == rid).setdefault("externals", []).append(x["id"])
    for r in resources:
        r.pop("missing", None)

    # rules catalog: chart-level Helm/Kubernetes checks + deprecated APIs, then rule IDs on everything
    kube_target = kube_target if kube_target in deprecations.TARGETS else deprecations.DEFAULT_TARGET
    objs0 = {r["id"]: r["_obj"] for r in resources}
    extra = rules.chart_checks(files, chart, resources, objs0, vindex, namespace) + deprecations.check(resources, files, kube_target)
    byid = {r["id"]: r for r in resources}
    for f in extra:
        f["id"] = f"f{len(findings)}"
        findings.append(f)
        if f.get("resource") in byid:
            byid[f["resource"]]["findings"].append(f["id"])
    rules.tag(findings)
    # .helm-visualiser.yaml: accepted findings + notes
    exc_cfg, exc_problems = exceptions.load(files, repo_exceptions)
    exc_rows = exceptions.apply(findings, exc_cfg, resources)
    for p in exc_problems:
        notes.append(f"**{exceptions.FILENAME}:** {p}")
    if exc_cfg["notes"]:
        notes.insert(0, "**Chart notes (from " + exceptions.FILENAME + "):** " + exc_cfg["notes"])

    hooks = {r["id"] for r in resources if r["hook"]}
    penalty = sum(SEV_WEIGHT[f["sev"]] * (0.5 if f["resource"] in hooks else 1) for f in findings if not f.get("accepted"))
    score = round(100 / (1 + penalty / 80))
    steps = _build_steps(chart, files, resources, findings, vindex, lint, render_error, notes, release, namespace, externals)

    # extra lenses on the same data (Helm concepts / Infrastructure views)
    objs = {r["id"]: r.pop("_obj") for r in resources}
    helm_view = views.helm_concepts(files, chart, resources, lint, render_error, vindex, used_vf, bool(overrides or argo or set_lines))
    infra_view = views.infrastructure(resources, objs, findings, externals, files, namespace)
    return dict(chart=dict(name=chart.get("name"), version=chart.get("version"), appVersion=chart.get("appVersion"),
                           description=chart.get("description"), apiVersion=chart.get("apiVersion"), type=chart.get("type", "application")),
                release=release, namespace=namespace, files=files, rendered=rendered, renderError=render_error,
                lint=lint, resources=resources, findings=findings, score=score, steps=steps, notes=notes,
                valueFiles=available_vf, usedValueFiles=used_vf,
                required=[dict(q, placeholder=_placeholder(q["path"])) for q in required],
                suggested=_skeleton([r["path"] for r in required]), externals=externals, bypass=bool(bypass),
                helm=helm_view, infra=infra_view,
                ruleset=rules.RULESET["version"], kubeTarget=kube_target, kubeTargets=deprecations.TARGETS,
                exceptions=exc_rows, chartNotes=exc_cfg["notes"],
                counts={s: sum(1 for f in findings if f["sev"] == s and not f.get("accepted")) for s in SEV_WEIGHT},
                accepted=sum(1 for f in findings if f.get("accepted")),
                durationMs=int((time.time() - t0) * 1000))


def _parse_rendered(rendered, files):
    resources, lines = [], rendered.split("\n")
    docs, cur = [], None
    for i, ln in enumerate(lines, 1):
        if ln.strip() == "---":
            if cur:
                docs.append(cur)
            cur = {"start": i + 1, "lines": []}
            continue
        if cur is None:
            cur = {"start": i, "lines": []}
        cur["lines"].append(ln)
    if cur:
        docs.append(cur)

    def src_of(d):
        m = re.search(r"^# Source: (.+)$", "\n".join(d["lines"]), re.M)
        return _strip_root(m.group(1).strip()) if m else ""

    src_counts = {}
    for d in docs:
        if "\n".join(d["lines"]).strip():
            src_counts[src_of(d)] = src_counts.get(src_of(d), 0) + 1

    seg_counter = {}
    for d in docs:
        text = "\n".join(d["lines"])
        if not text.strip():
            continue
        src = src_of(d)
        try:
            obj = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if not isinstance(obj, dict) or "kind" not in obj:
            continue
        meta = obj.get("metadata") or {}
        segs = _split_segments(files.get(src, "")) if src in files else [(1, 1)]
        k = seg_counter.get(src, 0)
        seg_counter[src] = k + 1
        n_docs_from_src = src_counts.get(src, 0)
        ts, te = segs[k] if len(segs) == n_docs_from_src and k < len(segs) else (1, len(files.get(src, "").split("\n")))
        hook = (meta.get("annotations") or {}).get("helm.sh/hook")
        ann = list((meta.get("annotations") or {}).keys())
        resources.append(dict(
            id=f"r{len(resources)}", kind=obj["kind"], name=meta.get("name", "?"),
            apiVersion=obj.get("apiVersion"), namespace=meta.get("namespace"), source=src, hook=hook,
            outStart=d["start"], outEnd=d["start"] + len(d["lines"]) - 1,
            tplStart=ts, tplEnd=te, tier=TIER.get(obj["kind"], 2), links=[], _obj=obj, annotations=ann, missing=[],
        ))
    order = {k: i for i, k in enumerate(INSTALL_ORDER)}
    resources.sort(key=lambda r: (1 if r["hook"] else 0, order.get(r["kind"], 999), r["name"]))
    for i, r in enumerate(resources):
        r["id"] = f"r{i}"
    return resources


def _link(resources):
    by = {}
    for r in resources:
        by.setdefault((r["kind"], r["name"]), r)

    def link(a, kind, name, label):
        t = by.get((kind, name))
        if not t and name and kind in ("ConfigMap", "Secret", "ServiceAccount", "PersistentVolumeClaim") \
                and not (kind == "ServiceAccount" and name == "default") \
                and not any(m[:2] == (kind, name) for m in a["missing"]):
            a["missing"].append((kind, name, label))
        if t and t is not a and not any(l["to"] == t["id"] for l in a["links"]):
            a["links"].append(dict(to=t["id"], label=label))

    for r in resources:
        o, k = r["_obj"], r["kind"]
        if k in WORKLOADS:
            ps = _pod_spec(k, o)
            link(r, "ServiceAccount", ps.get("serviceAccountName") or ps.get("serviceAccount"), "runs as")
            for v in ps.get("volumes") or []:
                if "configMap" in v: link(r, "ConfigMap", v["configMap"].get("name"), "mounts")
                if "secret" in v: link(r, "Secret", v["secret"].get("secretName"), "mounts")
                if "persistentVolumeClaim" in v: link(r, "PersistentVolumeClaim", v["persistentVolumeClaim"].get("claimName"), "mounts")
                for s in (v.get("projected") or {}).get("sources") or []:
                    if "configMap" in s: link(r, "ConfigMap", s["configMap"].get("name"), "mounts")
                    if "secret" in s: link(r, "Secret", s["secret"].get("name"), "mounts")
            for c in (ps.get("containers") or []) + (ps.get("initContainers") or []):
                for ef in c.get("envFrom") or []:
                    if "configMapRef" in ef: link(r, "ConfigMap", ef["configMapRef"].get("name"), "env")
                    if "secretRef" in ef: link(r, "Secret", ef["secretRef"].get("name"), "env")
                for e in c.get("env") or []:
                    vf = e.get("valueFrom") or {}
                    if "configMapKeyRef" in vf: link(r, "ConfigMap", vf["configMapKeyRef"].get("name"), "env")
                    if "secretKeyRef" in vf: link(r, "Secret", vf["secretKeyRef"].get("name"), "env")
            r["podLabels"] = _pod_labels(k, o)
    for r in resources:
        o, k, s = r["_obj"], r["kind"], (r["_obj"].get("spec") or {})
        if k == "Service":
            for w in resources:
                if w["kind"] in WORKLOADS and _matches(s.get("selector"), w.get("podLabels", {})):
                    r["links"].append(dict(to=w["id"], label="selects"))
        elif k == "Ingress":
            def backends(spec):
                if spec.get("defaultBackend"): yield spec["defaultBackend"]
                for rule in spec.get("rules") or []:
                    for p in ((rule.get("http") or {}).get("paths") or []):
                        yield p.get("backend") or {}
            for b in backends(s):
                name = (b.get("service") or {}).get("name") or b.get("serviceName")
                link(r, "Service", name, "routes to")
        elif k == "HorizontalPodAutoscaler":
            t = s.get("scaleTargetRef") or {}
            link(r, t.get("kind"), t.get("name"), "scales")
        elif k in ("RoleBinding", "ClusterRoleBinding"):
            rr = o.get("roleRef") or {}
            link(r, rr.get("kind"), rr.get("name"), "grants")
            for sub in o.get("subjects") or []:
                if sub.get("kind") == "ServiceAccount":
                    link(r, "ServiceAccount", sub.get("name"), "to")
        elif k in ("NetworkPolicy", "PodDisruptionBudget"):
            sel = (s.get("podSelector") if k == "NetworkPolicy" else s.get("selector")) or {}
            ml = sel.get("matchLabels") or {}
            for w in resources:
                if w["kind"] in WORKLOADS and (not sel or _matches(ml, w.get("podLabels", {}))):
                    r["links"].append(dict(to=w["id"], label="guards" if k == "NetworkPolicy" else "protects"))


def _findings(resources, files, rendered):
    findings = []
    for r in resources:
        raw = _check_workload(r, r["_obj"]) if r["kind"] in WORKLOADS else _check_other(r, r["_obj"])
        tpl_text = files.get(r["source"], "")
        for f in raw:
            anchor = f.pop("anchor")
            ts, os_ = r["tplStart"], r["outStart"]
            if anchor:  # search inside the right container block
                ts = _line_of(tpl_text, anchor, r["tplStart"], r["tplEnd"]) or ts
                os_ = _line_of(rendered, anchor, r["outStart"], r["outEnd"]) or os_
            tl = _line_of(tpl_text, f.pop("tpl_keys"), ts, r["tplEnd"]) or ts
            ol = _line_of(rendered, f.pop("out_keys"), os_, r["outEnd"]) or os_
            f.update(id=f"f{len(findings)}", resource=r["id"],
                     tpl=dict(file=r["source"], line=tl), out=dict(file=R, line=ol))
            findings.append(f)
        r["findings"] = [f["id"] for f in findings if f["resource"] == r["id"]]
    return findings




def _values_refs(text, start, end, vindex):
    seg = "\n".join(text.split("\n")[start - 1:end])
    refs, seen = [], set()
    for m in re.finditer(r"\.Values\.([A-Za-z0-9_\.]+)", seg):
        path = m.group(1).rstrip(".")
        parts = path.split(".")
        while parts and ".".join(parts) not in vindex:
            parts.pop()
        if not parts:
            continue
        p = ".".join(parts)
        if p in seen:
            continue
        seen.add(p)
        tl = _line_of(text, m.group(0), start, end)
        refs.append(dict(path=p, line=vindex[p], tplLine=tl))
    return refs


def _helper_refs(files, r):
    seg = "\n".join(files.get(r["source"], "").split("\n")[r["tplStart"] - 1:r["tplEnd"]])
    out, seen = [], set()
    for m in re.finditer(r'(?:include|template)\s+"([^"]+)"', seg):
        name = m.group(1)
        if name in seen:
            continue
        seen.add(name)
        for path, txt in files.items():
            if path.endswith(".tpl"):
                ln = _line_of(txt, f'define "{name}"')
                if ln:
                    out.append(dict(name=name, file=path, line=ln))
                    break
    return out


# ---------------------------------------------------------------------------
# Walkthrough
# ---------------------------------------------------------------------------
def _p(file, start, end=None, label="", tone="focus"):
    return dict(file=file, start=start, end=end or start, label=label, tone=tone)


def _build_steps(chart, files, resources, findings, vindex, lint, render_error, notes, release, ns, externals=()):
    steps = []
    ct = files.get("Chart.yaml", "")
    ptr = [_p("Chart.yaml", 1, len(ct.split("\n")), "Chart metadata", "soft")]
    for key, lbl in (("apiVersion:", "apiVersion v2 = Helm 3 chart"), ("version:", "Chart version (bump on every change)"),
                     ("appVersion:", "Version of the app being deployed"), ("dependencies:", "Sub-charts")):
        ln = _line_of(ct, key, regex=False)
        if ln:
            ptr.append(_p("Chart.yaml", ln, ln, lbl))
    steps.append(dict(id="s-chart", title="Chart.yaml", group="Chart", node=None, pointers=ptr,
                      explain=(f"**{chart.get('name')}** v{chart.get('version')} (app {chart.get('appVersion')}). "
                               "`Chart.yaml` is the chart's identity card: name, chart version (SemVer, bump it on every change) and appVersion. "
                               "`apiVersion: v2` means Helm 3."
                               + (" " + " ".join(notes) if notes else "")),
                      findings=[]))

    vt = files.get("values.yaml", "")
    if vt:
        top = [(k, l) for k, l in vindex.items() if "." not in k]
        vp = [_p("values.yaml", l, l, f"`{k}`", "focus") for k, l in sorted(top, key=lambda x: x[1])]
        steps.append(dict(id="s-values", title="values.yaml", group="Chart", node=None,
                          pointers=[_p("values.yaml", 1, len(vt.split("\n")), "Defaults", "soft")] + vp,
                          explain=("`values.yaml` holds the **defaults** that templates read through `.Values.*`. "
                                   "Users override them with `-f my-values.yaml` or `--set`. Good charts ship **secure defaults** here "
                                   "(non-root securityContext, resource limits, pinned image tag) so a plain `helm install` is already hardened. "
                                   f"Top-level keys: {', '.join('`'+k+'`' for k, _ in top[:12])}."),
                          findings=[]))
    tpls = [p for p in files if p.startswith("templates/") and p.endswith(".tpl")]
    if tpls:
        ptrs = []
        for p in tpls:
            for i, ln in enumerate(files[p].split("\n"), 1):
                m = re.search(r'define\s+"([^"]+)"', ln)
                if m:
                    ptrs.append(_p(p, i, i, f"`{m.group(1)}`"))
        steps.append(dict(id="s-helpers", title="_helpers.tpl", group="Chart", node=None, pointers=ptrs,
                          explain=("Files starting with `_` are **not rendered** on their own. They hold named templates (`define`) "
                                   "that other templates pull in with `include`. Typical helpers build the full name, the standard "
                                   "`app.kubernetes.io/*` labels and the selector labels so every resource is labelled consistently."),
                          findings=[]))

    if externals:
        ptrs = []
        for x in externals:
            ptrs += [_p(p["file"], p["line"], p["line"], f"{x['label']}: {p['label']}", "info") for p in x["pointers"] if p.get("file")]
        steps.append(dict(id="s-external", title="External dependencies", group="Chart", node=None, externals=[x["id"] for x in externals],
                          pointers=ptrs,
                          explain=("Things this chart relies on that **Helm doesn't provide**. They're the dashed nodes on the diagram. "
                                   "This is usually why a chart renders in ArgoCD but not with plain `helm template`.\n\n"
                                   + "\n\n".join(f"**{x['label']}**: {x['detail']}" for x in externals)),
                          findings=[]))
    fmap = {f["id"]: f for f in findings}
    for r in resources:
        desc, cks = KIND_INFO.get(r["kind"], ("Custom or less common resource.", ""))
        ptrs = [_p(r["source"], r["tplStart"], r["tplEnd"], f"Template for {r['kind']}", "soft"),
                _p(R, r["outStart"], r["outEnd"], "Rendered manifest", "soft")]
        for h in r["helpers"]:
            ptrs.append(_p(h["file"], h["line"], h["line"], f"include \"{h['name']}\"", "info"))
        for v in r["values"]:
            if v.get("tplLine"):
                ptrs.append(_p(r["source"], v["tplLine"], v["tplLine"], f".Values.{v['path']}", "info"))
            ptrs.append(_p("values.yaml", v["line"], v["line"], f"value: {v['path']}", "info"))
        links_txt = ""
        if r["links"]:
            names = {x["id"]: f"{x['kind']}/{x['name']}" for x in resources}
            links_txt = " Connections: " + "; ".join(f"{l['label']} **{names[l['to']]}**" for l in r["links"]) + "."
        hook = f" This is a Helm **hook** (`{r['hook']}`), run outside the normal install order." if r["hook"] else ""
        if r.get("externals"):
            xl = {x["id"]: x["label"] for x in externals}
            hook += " Depends on something outside the chart: " + ", ".join(f"**{xl[i]}**" for i in r["externals"]) + "."
        steps.append(dict(id=f"s-{r['id']}", title=f"{r['kind']}: {r['name']}", group="Resources", node=r["id"], pointers=ptrs,
                          explain=f"{desc}{hook}{links_txt}\n\n{cks}",
                          findings=[fmap[i] for i in r["findings"]]))

    if "templates/NOTES.txt" in files:
        n = files["templates/NOTES.txt"]
        steps.append(dict(id="s-notes", title="NOTES.txt", group="Chart", node=None,
                          pointers=[_p("templates/NOTES.txt", 1, len(n.split("\n")), "Post-install message", "soft")],
                          explain="Rendered and printed after `helm install`/`upgrade`. Use it to tell users how to reach the app. Don't echo secrets here.",
                          findings=[]))
    glob = [f for f in findings if f["resource"] is None]
    steps.append(dict(id="s-summary", title="Summary & lint", group="Review", node=None, pointers=[],
                      explain=(f"Rendered as release `{release}` in namespace `{ns}`. "
                               "Helm installs resources in a fixed **kind order** (Namespaces, policies, SAs, Secrets, ConfigMaps, RBAC, Services, workloads, Ingress), "
                               "which is the order you just walked through.\n\n"
                               f"**helm lint**\n```\n{lint or 'n/a'}\n```"
                               + (f"\n\n**helm template error**\n```\n{render_error}\n```" if render_error else "")),
                      findings=glob))
    return steps
