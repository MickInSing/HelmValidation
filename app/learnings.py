"""Learnings: 20 security & performance practices from public guidance, beyond the CKS curriculum.

Sources (checked 2026-10-20):
  OWASP Kubernetes Top 10 (2025)          https://kubernetes-top10.owasp.org/
  Kubernetes Security Checklist            https://kubernetes.io/docs/concepts/security/security-checklist/
  NSA/CISA Kubernetes Hardening Guidance   https://kubernetes.io/blog/2021/10/05/nsa-cisa-kubernetes-hardening-guidance/
  Pod Security Standards (baseline)        https://kubernetes.io/docs/concepts/security/pod-security-standards/
  Prometheus security model                https://prometheus.io/docs/operating/security/
  Grafana security hardening / anon auth   https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-security-hardening/
  CloudNativePG security                   https://cloudnative-pg.io/docs/devel/security
  Helm provenance & integrity              https://helm.sh/docs/topics/provenance/
  Kubernetes HPA / probes / topology spread docs

Every rule here can be detected from the chart itself; process-only advice (patch cadence, audit logs) is left out.
"""
import re

import yaml

OW = "https://kubernetes-top10.owasp.org/2025/en/src/"
OWASP = {
    "K01": (OW + "K01-Insecure-Workload-Configurations.html", "OWASP K01 (2025) Insecure Workload Configurations"),
    "K02": (OW + "K02-Overly-Permissive-Authorization-Configurations.html", "OWASP K02 (2025) Overly Permissive Authorization"),
    "K03": (OW + "K03-Secrets-Management-Failures.html", "OWASP K03 (2025) Secrets Management Failures"),
    "K04": (OW + "K04-Lack-Of-Cluster-Level-Policy-Enforcement.html", "OWASP K04 (2025) Lack of Cluster-Level Policy Enforcement"),
    "K05": (OW + "K05-Missing-Network-Segmentation-Controls.html", "OWASP K05 (2025) Missing Network Segmentation"),
    "K06": (OW + "K06-Overly-Exposed-Kubernetes-Components.html", "OWASP K06 (2025) Overly Exposed Components"),
    "K07": (OW + "K07-Misconfigured-And-Vulnerable-Cluster-Components.html", "OWASP K07 (2025) Misconfigured & Vulnerable Components"),
    "K09": (OW + "K09-Broken-Authentication-Mechanisms.html", "OWASP K09 (2025) Broken Authentication"),
}
K8S = "https://kubernetes.io/docs/"
CHECKLIST = (K8S + "concepts/security/security-checklist/", "Kubernetes Security Checklist")
NSA = ("https://kubernetes.io/blog/2021/10/05/nsa-cisa-kubernetes-hardening-guidance/", "NSA/CISA Kubernetes Hardening Guidance")
PSS = (K8S + "concepts/security/pod-security-standards/", "Pod Security Standards (baseline)")
PSA = (K8S + "concepts/security/pod-security-admission/", "Pod Security Admission")
PROM = ("https://prometheus.io/docs/operating/security/", "Prometheus security model")
PROM_STORE = ("https://prometheus.io/docs/prometheus/latest/storage/", "Prometheus storage")
GF_HARD = ("https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-security-hardening/", "Grafana security hardening")
GF_ANON = ("https://grafana.com/docs/grafana/latest/setup-grafana/configure-access/configure-authentication/anonymous-auth/", "Grafana anonymous access")
GF_CONF = ("https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/", "Grafana configuration")
CNPG_SEC = ("https://cloudnative-pg.io/docs/devel/security", "CloudNativePG security")
CNPG_DOCS = ("https://cloudnative-pg.io/docs/devel", "CloudNativePG docs (replication, backup)")
HELM_PROV = ("https://helm.sh/docs/topics/provenance/", "Helm provenance & integrity")
HPA = (K8S + "tasks/run-application/horizontal-pod-autoscale/", "Horizontal Pod Autoscaling")
SPREAD = (K8S + "concepts/scheduling-eviction/topology-spread-constraints/", "Topology spread constraints")
PROBES = (K8S + "concepts/configuration/liveness-readiness-startup-probes/", "Liveness, readiness & startup probes")

# (id, kind, severity, title, why, fix, refs, source label)
RULES = [
    ("LRN-SEC-001", "security", "critical", "No bindings to cluster-admin or anonymous users",
     "Binding cluster-admin hands over the whole cluster; binding system:anonymous / system:unauthenticated lets anyone who can reach the API server in.",
     "Bind a least-privilege Role; never grant to system:anonymous, system:unauthenticated or system:authenticated.", [OWASP["K02"], NSA], "OWASP K02 · NSA/CISA"),
    ("LRN-SEC-002", "security", "high", "Pod Security baseline: no hostPort, unsafe sysctls, Unmasked procMount, unconfined AppArmor or custom SELinux types",
     "These are the baseline-profile controls beyond the usual privileged/hostNetwork checks; each widens the path from container to node.",
     "Remove hostPort (use a Service), keep sysctls to the safe set, leave procMount Default, AppArmor RuntimeDefault, SELinux type container_t.", [PSS, NSA], "Pod Security Standards · NSA/CISA"),
    ("LRN-SEC-003", "security", "medium", "Namespaces enforce Pod Security Admission",
     "A Namespace without pod-security.kubernetes.io/enforce relies on whatever the cluster default is; policy should be explicit.",
     "metadata.labels: pod-security.kubernetes.io/enforce: restricted (or baseline)", [PSA, OWASP["K04"]], "OWASP K04 · Pod Security Admission"),
    ("LRN-SEC-004", "security", "high", "No credentials in ConfigMaps",
     "ConfigMaps aren't designed for confidential data: no encryption-at-rest option, readable by anyone with get configmaps.",
     "Move the value into a Secret (or an external secret store) and reference it.", [CHECKLIST, OWASP["K03"]], "Kubernetes Security Checklist · OWASP K03"),
    ("LRN-SEC-005", "security", "high", "No literal secrets in values.yaml",
     "Defaults in values.yaml live in git and in every packaged chart version, forever.",
     "Leave the default empty and use existingSecret / External Secrets / Sealed Secrets.", [OWASP["K03"]], "OWASP K03"),
    ("LRN-SEC-006", "security", "high", "No passwords embedded in URLs",
     "user:password@host URLs leak through logs, process listings, error messages and the manifest itself.",
     "Pass credentials separately from a Secret, or use a Secret-backed connection URI.", [OWASP["K03"]], "OWASP K03"),
    ("LRN-SEC-007", "security", "low", "NetworkPolicies restrict egress too",
     "Ingress-only policies still let a compromised pod reach anything: other namespaces, cloud metadata, the internet.",
     "Add policyTypes: [Egress] with explicit allows (DNS + what the app needs).", [CHECKLIST, NSA, OWASP["K05"]], "Kubernetes Security Checklist · NSA/CISA · OWASP K05"),
    ("LRN-SEC-008", "security", "high", "Monitoring and admin UIs aren't publicly exposed",
     "Prometheus says its HTTP endpoints (metrics, APIs, pprof) should not be exposed to public networks; Grafana, Alertmanager and exporters likewise.",
     "ClusterIP + an Ingress with SSO (oauth2-proxy / auth annotations), or a VPN. Never NodePort/LoadBalancer.", [PROM, OWASP["K06"]], "Prometheus security model · OWASP K06"),
    ("LRN-SEC-009", "security", "high", "Prometheus admin and lifecycle APIs stay disabled",
     "--web.enable-admin-api allows deleting time series; --web.enable-lifecycle allows /-/reload and /-/quit. Prometheus has no CSRF protection on them.",
     "Remove the flags (or keep them behind an authenticated proxy that blocks those paths).", [PROM], "Prometheus security model"),
    ("LRN-SEC-010", "security", "high", "Grafana anonymous access off (or Viewer-only)",
     "With anonymous access on, anyone who reaches Grafana can query every data source it's connected to; Editor/Admin roles let them change it too.",
     "[auth.anonymous] enabled = false, or org_role = Viewer for genuinely public dashboards.", [GF_ANON, OWASP["K09"]], "Grafana docs · OWASP K09"),
    ("LRN-SEC-011", "security", "high", "Grafana admin password isn't default or plaintext",
     "Grafana's built-in admin/admin is the first thing attackers try; a literal password in the manifest is just as public.",
     "GF_SECURITY_ADMIN_PASSWORD from a Secret (valueFrom.secretKeyRef) or __FILE, or SSO-only login.", [GF_CONF, OWASP["K09"]], "Grafana docs · OWASP K09"),
    ("LRN-SEC-012", "security", "low", "Grafana hardening: secure cookies, no embedding, authenticated metrics",
     "Grafana's hardening guide: cookie_secure behind HTTPS (MITM), keep allow_embedding off (clickjacking), require basic auth on /metrics (information leak).",
     "[security] cookie_secure = true, allow_embedding = false; [metrics] basic_auth_username/password.", [GF_HARD], "Grafana security hardening"),
    ("LRN-SEC-013", "security", "medium", "Database connections don't disable TLS",
     "sslmode=disable (or ssl=false) sends database credentials and data in plaintext across the pod network.",
     "sslmode=require (or verify-full with the CA). CloudNativePG serves TLS by default.", [CNPG_SEC, OWASP["K03"]], "CloudNativePG security · OWASP K03"),
    ("LRN-SEC-014", "security", "high", "Chart dependencies come from HTTPS or OCI repositories",
     "A plain http:// chart repository can be tampered with in transit; you'd install whatever arrives.",
     "Use https:// or oci:// repositories, and verify provenance (helm verify / signed OCI artifacts).", [HELM_PROV, OWASP["K07"]], "Helm provenance · OWASP K07"),
    ("LRN-PERF-001", "performance", "low", "Memory limit equals memory request",
     "The Kubernetes Security Checklist recommends memory limits equal to (or below) requests: overcommitted pods are the first OOM-killed under node pressure.",
     "Set resources.limits.memory = resources.requests.memory.", [CHECKLIST], "Kubernetes Security Checklist"),
    ("LRN-PERF-002", "performance", "medium", "Autoscaled workloads request the metric they scale on",
     "Utilization-based HPA targets are a percentage of the request; with no request the HPA can't compute it and won't scale.",
     "Set resources.requests.cpu (and memory if the HPA uses it) on every container of the target.", [HPA], "Kubernetes HPA docs"),
    ("LRN-PERF-003", "performance", "low", "Replicas spread across nodes and zones",
     "Without spread constraints or anti-affinity, all replicas can land on one node or zone, so one failure takes the whole service down.",
     "topologySpreadConstraints on topology.kubernetes.io/zone and kubernetes.io/hostname (or podAntiAffinity).", [SPREAD], "Kubernetes topology spread docs"),
    ("LRN-PERF-004", "performance", "low", "Liveness probe is not a copy of the readiness probe",
     "Identical probes mean a slow dependency or a busy moment restarts the container instead of just taking it out of rotation, which leads to cascading restarts.",
     "Make liveness cheaper and more tolerant (local check, higher failureThreshold); add a startupProbe for slow starts.", [PROBES], "Kubernetes probes docs"),
    ("LRN-PERF-005", "performance", "medium", "Prometheus, Grafana and databases keep state on persistent volumes",
     "On emptyDir (or no volume) every restart loses metrics history, dashboards and users, or the database itself.",
     "Mount a PersistentVolumeClaim at the data path (Prometheus /prometheus, Grafana /var/lib/grafana, Alertmanager /alertmanager).", [PROM_STORE], "Prometheus storage docs"),
    ("LRN-PERF-006", "performance", "medium", "CloudNativePG clusters: HA, backups, no superuser",
     "One instance means downtime on every node drain; no backup section means no point-in-time recovery; superuser access is off by default for least privilege.",
     "instances: 3, configure spec.backup (or a backup plugin) + ScheduledBackup, leave enableSuperuserAccess false.", [CNPG_DOCS, CNPG_SEC], "CloudNativePG docs"),
]

SECRET_KEY = re.compile(r"(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential|auth[_-]?key|client[_-]?secret)$", re.I)
NOT_SECRET = re.compile(r"(name|ref|file|path|existingsecret|secretname|keyref|enabled|length|policy|mode|type|header|field|env|annotation)$", re.I)
PLACEHOLDER = re.compile(r"^(|~|null|none|\"\"|''|<.*>|\$\{.*\}|\$\(.*\)|\{\{.*\}\}|changeit|set-?me|xxx+|\*+)$", re.I)
URL_CREDS = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@'\"]+:([^@\s/'\"]+)@", re.I)
SAFE_SYSCTLS = {"kernel.shm_rmid_forced", "net.ipv4.ip_local_port_range", "net.ipv4.ip_unprivileged_port_start", "net.ipv4.tcp_syncookies",
                "net.ipv4.ping_group_range", "net.ipv4.ip_local_reserved_ports", "net.ipv4.tcp_keepalive_time", "net.ipv4.tcp_fin_timeout",
                "net.ipv4.tcp_keepalive_intvl", "net.ipv4.tcp_keepalive_probes"}
SAFE_SELINUX = {"", "container_t", "container_init_t", "container_kvm_t", "container_engine_t"}
MONITORING = re.compile(r"(^|/)(prometheus|alertmanager|grafana|pushgateway|node-exporter|kube-state-metrics|[\w-]*exporter|argocd|kibana|jaeger)(:|@|$)", re.I)
DATA_PATHS = {"prometheus": "/prometheus", "grafana": "/var/lib/grafana", "alertmanager": "/alertmanager", "loki": "/loki",
              "postgres": "/var/lib/postgresql/data", "mysql": "/var/lib/mysql", "redis": "/data", "mongo": "/data/db"}
AUTH_ANN = re.compile(r"auth-url|auth-signin|auth-type|oauth2|middlewares|authorization-policy|auth-response-headers", re.I)


def register(rule_fn):
    for rid, kind, sev, title, why, fix, refs, src in RULES:
        rule_fn(rid, "Learnings", sev, title, why, fix, refs, domain=f"{kind.capitalize()} · {src}")


def _pod_spec(kind, obj):
    spec = obj.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
    return ((spec.get("template") or {}).get("spec")) or {}


def _pod_meta(kind, obj):
    spec = obj.get("spec") or {}
    t = (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") if kind == "CronJob" else spec.get("template")) or {}
    return (obj.get("metadata") if kind == "Pod" else t.get("metadata")) or {}


WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "ReplicaSet"}


def check(files, chart, resources, objs, values_index, catalog):
    out = []

    def f(rid, title, detail, r=None, needle=None, file=None, line=None, sev=None):
        tpl = None
        if r is not None:
            ln = r["tplStart"]
            if needle:
                t = files.get(r["source"], "")
                ln = next((i for i, x in enumerate(t.split("\n")[r["tplStart"] - 1:r["tplEnd"]], r["tplStart"]) if needle in x), ln)
            tpl = dict(file=r["source"], line=ln)
        elif file:
            tpl = dict(file=file, line=line or 1)
        c = catalog[rid]
        out.append(dict(sev=sev or c["severity"], key=rid, rule=rid, category="Learnings", title=title, detail=detail, fix=c["fix"],
                        resource=r["id"] if r is not None else None, tpl=tpl,
                        out=dict(file="__rendered__", line=r["outStart"]) if r is not None else None))

    by_kind = {}
    for r in resources:
        by_kind.setdefault(r["kind"], []).append(r)
    workloads = [r for r in resources if r["kind"] in WORKLOADS]

    def containers(r):
        ps = _pod_spec(r["kind"], objs[r["id"]])
        return ps, (ps.get("containers") or []) + (ps.get("initContainers") or [])

    # LRN-SEC-001 dangerous bindings
    for r in by_kind.get("ClusterRoleBinding", []) + by_kind.get("RoleBinding", []):
        o = objs[r["id"]]
        if (o.get("roleRef") or {}).get("name") == "cluster-admin":
            f("LRN-SEC-001", f"{r['kind']}/{r['name']} grants cluster-admin", "Full control of the cluster for its subjects.", r, "cluster-admin")
        for s in o.get("subjects") or []:
            if s.get("name") in ("system:anonymous", "system:unauthenticated", "system:authenticated"):
                f("LRN-SEC-001", f"{r['kind']}/{r['name']} binds {s.get('name')}", "Grants the role to every (or every unauthenticated) caller of the API server.", r, s.get("name"))

    for r in workloads:
        o = objs[r["id"]]
        ps, cs = containers(r)
        psc = ps.get("securityContext") or {}
        ann = _pod_meta(r["kind"], o).get("annotations") or {}
        # LRN-SEC-002 PSS baseline extras
        for c in cs:
            for p in c.get("ports") or []:
                if p.get("hostPort"):
                    f("LRN-SEC-002", f"[{c.get('name')}] hostPort {p['hostPort']}", "Binds directly on the node; bypasses Services and NetworkPolicies, and is disallowed by the baseline profile.", r, "hostPort", sev="medium")
            sc = c.get("securityContext") or {}
            if sc.get("procMount") == "Unmasked":
                f("LRN-SEC-002", f"[{c.get('name')}] procMount: Unmasked", "Exposes host /proc paths normally masked from containers.", r, "procMount")
            if ((sc.get("appArmorProfile") or {}).get("type") == "Unconfined") or ann.get(f"container.apparmor.security.beta.kubernetes.io/{c.get('name')}") == "unconfined":
                f("LRN-SEC-002", f"[{c.get('name')}] AppArmor unconfined", "Turns off the AppArmor profile that confines the container.", r, "nconfined")
            se = sc.get("seLinuxOptions") or {}
            if se.get("type", "") not in SAFE_SELINUX or se.get("user") or se.get("role"):
                f("LRN-SEC-002", f"[{c.get('name')}] custom SELinux options", "Custom SELinux user/role/type can escape the container policy.", r, "seLinuxOptions")
        if (psc.get("appArmorProfile") or {}).get("type") == "Unconfined":
            f("LRN-SEC-002", "Pod AppArmor unconfined", "Turns off AppArmor for every container in the pod.", r, "appArmorProfile")
        for s in psc.get("sysctls") or []:
            if s.get("name") not in SAFE_SYSCTLS:
                f("LRN-SEC-002", f"Unsafe sysctl {s.get('name')}", "Only the namespaced 'safe' sysctls are allowed by the baseline profile.", r, "sysctls")

    # LRN-SEC-003 Namespaces without PSA
    for r in by_kind.get("Namespace", []):
        labels = (objs[r["id"]].get("metadata") or {}).get("labels") or {}
        if "pod-security.kubernetes.io/enforce" not in labels:
            f("LRN-SEC-003", f"Namespace/{r['name']} has no Pod Security enforce label", "Pods in it are only checked against the cluster default.", r, "metadata")

    # LRN-SEC-004 credentials in ConfigMaps (+ LRN-SEC-006 URL creds, LRN-SEC-013 TLS off in configs)
    for r in by_kind.get("ConfigMap", []):
        for k, v in ((objs[r["id"]].get("data") or {}).items()):
            v = str(v)
            if SECRET_KEY.search(k) and not NOT_SECRET.search(k) and not PLACEHOLDER.match(v.strip()):
                f("LRN-SEC-004", f"ConfigMap/{r['name']} key '{k}' looks like a credential", "Store it in a Secret instead.", r, k)
            if "-----BEGIN" in v and "PRIVATE KEY" in v:
                f("LRN-SEC-004", f"ConfigMap/{r['name']} contains a private key ({k})", "Private keys belong in a Secret (or cert-manager).", r, k)
            if URL_CREDS.search(v) and not URL_CREDS.search(v).group(1).startswith("$"):
                f("LRN-SEC-006", f"ConfigMap/{r['name']} '{k}' has a password in a URL", "Anyone who can read the ConfigMap has the password.", r, k)
            if re.search(r"sslmode\s*[=:]\s*['\"]?disable|\bssl\s*[=:]\s*['\"]?false\b", v, re.I):
                f("LRN-SEC-013", f"ConfigMap/{r['name']} '{k}' disables database TLS", "Connection is unencrypted.", r, k)

    # env-level: URL creds, TLS off
    for r in workloads:
        _, cs = containers(r)
        for c in cs:
            for e in c.get("env") or []:
                v = str(e.get("value", "")) if "value" in e else ""
                m = URL_CREDS.search(v)
                if m and not m.group(1).startswith("$"):
                    f("LRN-SEC-006", f"[{c.get('name')}] env {e.get('name')} has a password in a URL", "Visible in the manifest and `kubectl describe`.", r, e.get("name"))
                if re.search(r"sslmode=disable|[?&;]ssl=false", v, re.I):
                    f("LRN-SEC-013", f"[{c.get('name')}] env {e.get('name')} disables database TLS", "Credentials and data cross the network unencrypted.", r, e.get("name"))

    # LRN-SEC-005 literal secrets in values.yaml
    vt = files.get("values.yaml", "")
    if vt:
        for i, ln in enumerate(vt.split("\n"), 1):
            m = re.match(r"^\s*-?\s*([A-Za-z0-9_.-]+)\s*:\s*(.+?)\s*(#.*)?$", ln)
            if not m:
                continue
            k, v = m.group(1), m.group(2).strip().strip("'\"")
            if v in ("|", ">", "{}", "[]") or v.lower() in ("true", "false"):
                continue
            if SECRET_KEY.search(k) and not NOT_SECRET.search(k) and not PLACEHOLDER.match(v):
                f("LRN-SEC-005", f"values.yaml: `{k}` has a literal default", f"`{k}: {'*' * min(8, len(v))}` is committed with the chart.", file="values.yaml", line=i)

    # LRN-SEC-007 egress
    nps = by_kind.get("NetworkPolicy", [])
    if nps and workloads and not any("Egress" in ((objs[r["id"]].get("spec") or {}).get("policyTypes") or []) for r in nps):
        f("LRN-SEC-007", "NetworkPolicies only restrict ingress", f"{len(nps)} polic{'y' if len(nps) == 1 else 'ies'}, none with policyTypes: [Egress].", nps[0], "policyTypes")

    # monitoring workloads
    mon = {}   # workloads whose MAIN container is a monitoring/admin UI (sidecar exporters don't count)
    for r in workloads:
        ps, _ = containers(r)
        main0 = (ps.get("containers") or [{}])[0]
        m = MONITORING.search(str(main0.get("image", "")).split("@")[0].rsplit(":", 1)[0] + ":")
        if m:
            mon.setdefault(r["id"], set()).add(m.group(2).lower())
    # LRN-SEC-008 exposure
    for s in by_kind.get("Service", []):
        targets = [l["to"] for l in s["links"] if l["to"] in mon]
        st = (objs[s["id"]].get("spec") or {}).get("type", "ClusterIP")
        if targets and st in ("LoadBalancer", "NodePort"):
            what = ", ".join(sorted(set().union(*[mon[t] for t in targets])))
            f("LRN-SEC-008", f"Service/{s['name']} exposes {what} as {st}", "Reachable from outside the cluster without any authentication layer.", s, "type")
    svc_mon = {s["id"]: s for s in by_kind.get("Service", []) if any(l["to"] in mon for l in s["links"])}
    for ing in by_kind.get("Ingress", []):
        hits = [l["to"] for l in ing["links"] if l["to"] in svc_mon]
        if hits and not any(AUTH_ANN.search(a) for a in ing.get("annotations", [])):
            f("LRN-SEC-008", f"Ingress/{ing['name']} publishes a monitoring UI without auth", "No auth annotations (oauth2-proxy / auth-url / middleware) on the Ingress.", ing, "rules", sev="medium")

    for r in workloads:
        _, cs = containers(r)
        for c in cs:
            args = " ".join(str(a) for a in (c.get("args") or []) + (c.get("command") or []))
            img = str(c.get("image", ""))
            # LRN-SEC-009 Prometheus flags
            if "--web.enable-admin-api" in args:
                f("LRN-SEC-009", f"[{c.get('name')}] --web.enable-admin-api", "Anyone reaching Prometheus can delete time series and take snapshots.", r, "enable-admin-api")
            if "--web.enable-lifecycle" in args:
                f("LRN-SEC-009", f"[{c.get('name')}] --web.enable-lifecycle", "Anyone reaching Prometheus can reload or shut it down via /-/reload and /-/quit.", r, "enable-lifecycle", sev="medium")
            # Grafana
            if re.search(r"(^|/)grafana(-oss|-enterprise)?(:|@|$)", img.split("@")[0].rsplit(":", 1)[0] + ":", re.I):
                env = {e.get("name"): e for e in c.get("env") or []}
                ini = _grafana_ini(objs, by_kind)
                val = lambda name, sect, key: str((env.get(name) or {}).get("value", ini.get(sect, {}).get(key, ""))).strip().lower()
                anon, role = val("GF_AUTH_ANONYMOUS_ENABLED", "auth.anonymous", "enabled"), val("GF_AUTH_ANONYMOUS_ORG_ROLE", "auth.anonymous", "org_role") or "viewer"
                if anon == "true":
                    f("LRN-SEC-010", f"[{c.get('name')}] Grafana anonymous access as {role.capitalize()}",
                      "Anyone who reaches Grafana can query every connected data source" + (" and edit dashboards/settings." if role in ("editor", "admin") else "."),
                      r, "ANONYMOUS", sev="high" if role in ("editor", "admin") else "medium")
                pw = env.get("GF_SECURITY_ADMIN_PASSWORD")
                if pw and "value" in pw:
                    f("LRN-SEC-011", f"[{c.get('name')}] Grafana admin password set as a plain value", "It's in the manifest; use valueFrom.secretKeyRef.", r, "GF_SECURITY_ADMIN_PASSWORD",
                      sev="critical" if str(pw.get("value")).strip() in ("admin", "") else "high")
                elif not pw and "GF_SECURITY_ADMIN_PASSWORD__FILE" not in env and not ini.get("security", {}).get("admin_password"):
                    f("LRN-SEC-011", f"[{c.get('name')}] Grafana admin password not set", "Grafana starts with admin/admin unless it's changed on first login.", r, "image:", sev="medium")
                elif ini.get("security", {}).get("admin_password"):
                    f("LRN-SEC-011", "Grafana admin_password in grafana.ini", "The ini lives in a ConfigMap/values in plaintext.", r, "image:")
                if val("GF_SECURITY_ALLOW_EMBEDDING", "security", "allow_embedding") == "true":
                    f("LRN-SEC-012", f"[{c.get('name')}] Grafana allow_embedding = true", "Drops the X-Frame-Options protection (clickjacking).", r, "EMBEDDING", sev="medium")
                if val("GF_SECURITY_COOKIE_SECURE", "security", "cookie_secure") != "true":
                    f("LRN-SEC-012", f"[{c.get('name')}] Grafana cookie_secure not enabled", "Session cookie can travel over plain HTTP (set it when served via HTTPS).", r, "image:")
                if not (val("GF_METRICS_BASIC_AUTH_USERNAME", "metrics", "basic_auth_username") and val("GF_METRICS_BASIC_AUTH_PASSWORD", "metrics", "basic_auth_password")) \
                        and val("GF_METRICS_ENABLED", "metrics", "enabled") != "false":
                    f("LRN-SEC-012", f"[{c.get('name')}] Grafana /metrics is unauthenticated", "Grafana's own metrics are readable by anyone who reaches it.", r, "image:", sev="info")

    # LRN-SEC-014 http chart repos
    ct = files.get("Chart.yaml", "")
    for d in chart.get("dependencies") or []:
        repo = str(d.get("repository") or "")
        if repo.startswith("http://"):
            line = next((i for i, x in enumerate(ct.split("\n"), 1) if repo in x), 1)
            f("LRN-SEC-014", f"Dependency {d.get('name')} from {repo}", "Plain HTTP: the subchart can be swapped in transit.", file="Chart.yaml", line=line)

    # ---- performance / reliability
    hpa_targets = {}
    for h in by_kind.get("HorizontalPodAutoscaler", []):
        spec = objs[h["id"]].get("spec") or {}
        res = {m.get("resource", {}).get("name") for m in spec.get("metrics") or [] if m.get("type") == "Resource"}
        if spec.get("targetCPUUtilizationPercentage"):
            res.add("cpu")
        for l in h["links"]:
            hpa_targets[l["to"]] = (h, res or {"cpu"})
    for r in workloads:
        o = objs[r["id"]]
        ps, cs = containers(r)
        main = ps.get("containers") or []
        for c in main:
            rs = c.get("resources") or {}
            req, lim = rs.get("requests") or {}, rs.get("limits") or {}
            if lim.get("memory") and req.get("memory") and _bytes(lim["memory"]) > _bytes(req["memory"]):
                f("LRN-PERF-001", f"[{c.get('name')}] memory limit {lim['memory']} > request {req['memory']}", "The pod is overcommitted: first in line for OOM kills under node pressure.", r, "resources")
            # LRN-PERF-004
            lp, rp = c.get("livenessProbe"), c.get("readinessProbe")
            if lp and rp and lp == rp:
                f("LRN-PERF-004", f"[{c.get('name')}] liveness probe identical to readiness", "A slow dependency will restart the container, not just drain it.", r, "livenessProbe")
        # LRN-PERF-002
        if r["id"] in hpa_targets:
            h, needed = hpa_targets[r["id"]]
            for c in main:
                miss = [x for x in needed if x in ("cpu", "memory") and not ((c.get("resources") or {}).get("requests") or {}).get(x)]
                if miss:
                    f("LRN-PERF-002", f"[{c.get('name')}] no {'/'.join(miss)} request but HPA {h['name']} scales on it", "The HPA can't compute utilization for this pod.", r, "resources")
        # LRN-PERF-003
        reps = (o.get("spec") or {}).get("replicas")
        replicated = (isinstance(reps, int) and reps > 1) or r["id"] in hpa_targets
        if r["kind"] in ("Deployment", "StatefulSet") and replicated and not ps.get("topologySpreadConstraints") \
                and not ((ps.get("affinity") or {}).get("podAntiAffinity")):
            f("LRN-PERF-003", f"{r['kind']}/{r['name']}: replicas not spread across nodes/zones", "All replicas may be scheduled onto the same node or zone.", r, "spec:")
        # LRN-PERF-005
        mounts = {m.get("mountPath"): m.get("name") for c in main for m in c.get("volumeMounts") or []}
        vols = {v.get("name"): v for v in ps.get("volumes") or []}
        vct = {(t.get("metadata") or {}).get("name") for t in (o.get("spec") or {}).get("volumeClaimTemplates") or []}
        for c in main:
            img = str(c.get("image", "")).lower()
            for app, path in DATA_PATHS.items():
                if re.search(rf"(^|/){app}[\w-]*(:|@|$)", img.split("@")[0] + ":") and "exporter" not in img:
                    vname = mounts.get(path)
                    v = vols.get(vname) if vname else None
                    persistent = vname in vct or (v and ("persistentVolumeClaim" in v or "ephemeral" in v))
                    if not persistent:
                        f("LRN-PERF-005", f"[{c.get('name')}] {app} data at {path} is {'on emptyDir' if v and 'emptyDir' in v else 'not on a volume'}",
                          "Restarts lose the data.", r, "volumeMounts" if vname else "image:")
                    break
    for r in by_kind.get("Prometheus", []):
        if not (objs[r["id"]].get("spec") or {}).get("storage"):
            f("LRN-PERF-005", f"Prometheus/{r['name']} (operator) has no spec.storage", "TSDB is on emptyDir: history is lost on restart.", r, "spec:")
    # LRN-PERF-006 CNPG
    for r in by_kind.get("Cluster", []):
        if not str(r.get("apiVersion", "")).startswith("postgresql.cnpg.io"):
            continue
        spec = objs[r["id"]].get("spec") or {}
        if int(spec.get("instances") or 1) < 2:
            f("LRN-PERF-006", f"Cluster/{r['name']}: {spec.get('instances') or 1} instance", "No standby: node drains and failures mean database downtime.", r, "instances", sev="low")
        if not spec.get("backup") and not spec.get("plugins"):
            f("LRN-PERF-006", f"Cluster/{r['name']}: no backup configured", "No point-in-time recovery if the volume or cluster is lost.", r, "spec:")
        if spec.get("enableSuperuserAccess"):
            f("LRN-PERF-006", f"Cluster/{r['name']}: enableSuperuserAccess: true", "Creates a postgres superuser Secret; keep it off unless you need it.", r, "enableSuperuserAccess")
    return out


def _grafana_ini(objs, by_kind):
    """Parse grafana.ini found in ConfigMaps (Grafana Helm chart style)."""
    out = {}
    for r in by_kind.get("ConfigMap", []):
        for k, v in ((objs[r["id"]].get("data") or {}).items()):
            if k != "grafana.ini" and "[auth" not in str(v) and "[security]" not in str(v):
                continue
            sect = ""
            for ln in str(v).split("\n"):
                ln = ln.strip()
                if ln.startswith("[") and ln.endswith("]"):
                    sect = ln[1:-1].strip()
                elif "=" in ln and not ln.startswith(("#", ";")):
                    a, b = ln.split("=", 1)
                    out.setdefault(sect, {})[a.strip()] = b.strip().strip('"')
    return out


def _bytes(q):
    m = re.fullmatch(r"([\d.]+)\s*([KMGTPE]i?|[kmgtpe])?", str(q).strip())
    if not m:
        return 0
    n, u = float(m.group(1)), (m.group(2) or "")
    mult = {"": 1, "k": 1e3, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18,
            "Ki": 2 ** 10, "Mi": 2 ** 20, "Gi": 2 ** 30, "Ti": 2 ** 40, "Pi": 2 ** 50, "Ei": 2 ** 60}
    return n * mult.get(u, 1)
