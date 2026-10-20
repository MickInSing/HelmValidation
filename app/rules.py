"""Rules catalog: every check the visualiser runs, with an ID, framework, severity, rationale, fix and references.

Bump RULESET["version"] and the rule's "updated" date whenever a check changes. Every scan records the
ruleset version, so scores from different rulesets are never compared as if they were the same.
"""
import re

RULESET = {
    "version": "2026.10.1",
    "updated": "2026-10-20",
    "sources": {
        "kubernetes": "Pod Security Standards, RBAC/Secrets good practices, Deprecated API Migration Guide (removals up to v1.32; none scheduled in v1.33-v1.36 docs)",
        "helm": "Helm 4 Chart Best Practices + Chart Template Guide",
        "cks": "CNCF CKS curriculum domains",
    },
}

K8S = "https://kubernetes.io/docs/"
HELM = "https://helm.sh/docs/"
PSS = (K8S + "concepts/security/pod-security-standards/", "Pod Security Standards")
SECCTX = (K8S + "tasks/configure-pod-container/security-context/", "Configure a Security Context")
CKS = ("https://github.com/cncf/curriculum", "CNCF CKS curriculum")

_R = []


def rule(id, category, severity, title, why, fix, refs, domain="", added="2026-10-20", updated="2026-10-20"):
    _R.append(dict(id=id, category=category, severity=severity, title=title, why=why, fix=fix, domain=domain,
                   refs=[dict(url=u, title=t) for u, t in refs], added=added, updated=updated))


# --- CKS: pod & container hardening ---------------------------------------------------------------
D_MSV = "Minimize Microservice Vulnerabilities"
D_SYS = "System Hardening"
D_CLH = "Cluster Hardening"
D_SUP = "Supply Chain Security"
D_CLS = "Cluster Setup"
rule("CKS-HOST-001", "CKS", "critical", "No host namespaces (hostNetwork / hostPID / hostIPC)",
     "Sharing the node's network, process or IPC namespace lets a container see and affect the host.",
     "Remove hostNetwork/hostPID/hostIPC, or set them to false.", [PSS, CKS], D_SYS)
rule("CKS-HOST-002", "CKS", "high", "No hostPath volumes",
     "hostPath mounts expose the node filesystem; a classic container-escape path.",
     "Use emptyDir, a PVC, a ConfigMap/Secret or a CSI volume instead.", [PSS, (K8S + "concepts/storage/volumes/#hostpath", "hostPath")], D_SYS)
rule("CKS-POD-001", "CKS", "critical", "No privileged containers",
     "Privileged containers get every capability and host devices: effectively root on the node.",
     "securityContext.privileged: false", [PSS, SECCTX, CKS], D_MSV)
rule("CKS-POD-002", "CKS", "high", "Run as non-root",
     "Without runAsNonRoot the container runs as whatever user the image specifies, often root.",
     "securityContext: { runAsNonRoot: true, runAsUser: 10001 }", [PSS, SECCTX], D_MSV)
rule("CKS-POD-003", "CKS", "high", "Disallow privilege escalation",
     "setuid binaries can let a process gain more privileges than its parent. Required by the restricted profile.",
     "securityContext.allowPrivilegeEscalation: false", [PSS, SECCTX], D_MSV)
rule("CKS-POD-004", "CKS", "medium", "Read-only root filesystem",
     "Stops an attacker dropping tools or modifying binaries inside the container.",
     "securityContext.readOnlyRootFilesystem: true (+ emptyDir for /tmp)", [SECCTX], D_MSV)
rule("CKS-POD-005", "CKS", "medium", "Drop all Linux capabilities",
     "Containers get a default capability set (e.g. NET_RAW). Drop ALL and add back only what's needed.",
     'securityContext.capabilities.drop: ["ALL"]', [PSS, SECCTX], D_MSV)
rule("CKS-POD-006", "CKS", "high", "No dangerous added capabilities",
     "SYS_ADMIN, NET_ADMIN, SYS_PTRACE or ALL are frequently enough to break out of the container.",
     "Remove them from capabilities.add; find a narrower capability or redesign.", [PSS, SECCTX], D_MSV)
rule("CKS-POD-007", "CKS", "medium", "Seccomp profile set",
     "RuntimeDefault blocks dozens of rarely-needed, risky syscalls at near-zero cost. Required by the restricted profile.",
     "securityContext.seccompProfile.type: RuntimeDefault", [PSS, (K8S + "tutorials/security/seccomp/", "Seccomp tutorial")], D_SYS)
# --- CKS: identity & RBAC -------------------------------------------------------------------------
SA = (K8S + "tasks/configure-pod-container/configure-service-account/", "Configure Service Accounts")
RBAC = (K8S + "concepts/security/rbac-good-practices/", "RBAC good practices")
rule("CKS-SA-001", "CKS", "medium", "Don't auto-mount the ServiceAccount token",
     "Every container gets an API token. If the app never calls the API, an attacker who gets in gets the token too.",
     "automountServiceAccountToken: false (pod or ServiceAccount)", [SA, CKS], D_CLH)
rule("CKS-SA-002", "CKS", "low", "Use a dedicated ServiceAccount",
     "The namespace's default ServiceAccount is shared; RBAC can't be scoped to one workload.",
     "Create a ServiceAccount per workload and set serviceAccountName.", [SA], D_CLH)
rule("CKS-SA-003", "CKS", "low", "ServiceAccount disables token automount by default",
     "Setting it on the ServiceAccount protects every pod that uses it, including future ones.",
     "automountServiceAccountToken: false on the ServiceAccount", [SA], D_CLH)
rule("CKS-RBAC-001", "CKS", "high", "No wildcards in RBAC rules",
     "'*' grants every current and future verb/resource in scope.", "List the exact verbs and resources.", [RBAC, CKS], D_CLH)
rule("CKS-RBAC-002", "CKS", "medium", "Avoid reading Secrets",
     "list/watch on secrets returns every secret in scope, including other apps' credentials.",
     "Grant get on named secrets only (resourceNames), or mount the secret instead.", [RBAC], D_CLH)
rule("CKS-RBAC-003", "CKS", "high", "No escalation-capable permissions",
     "pods/exec, pods/attach, escalate, bind and impersonate can be used to gain more privileges.",
     "Remove them; use a break-glass role outside the chart if needed.", [RBAC], D_CLH)
rule("CKS-RBAC-004", "CKS", "info", "Prefer namespaced roles",
     "ClusterRoles apply cluster-wide; a namespaced Role limits the blast radius.",
     "Use Role/RoleBinding unless the chart truly needs cluster scope.", [RBAC], D_CLH)
# --- CKS: secrets, supply chain, network ------------------------------------------------------------
SECRETS = (K8S + "concepts/security/secrets-good-practices/", "Secrets good practices")
IMAGES = (K8S + "concepts/containers/images/", "Images")
NETPOL = (K8S + "concepts/services-networking/network-policies/", "Network Policies")
rule("CKS-SEC-001", "CKS", "high", "No credentials in plain env vars",
     "Plain values are visible in the manifest, `kubectl describe`, values.yaml and git history.",
     "env.valueFrom.secretKeyRef, or mount the Secret as a file.", [SECRETS], D_MSV)
rule("CKS-SEC-002", "CKS", "info", "Secrets not rendered from committed values",
     "A Secret built from values.yaml usually means the credential is in git. Base64 isn't encryption.",
     "Use External Secrets / Sealed Secrets / CSI secrets store, and enable encryption at rest.", [SECRETS], D_MSV)
rule("CKS-SUP-001", "CKS", "high", "Pin image tags (no latest / untagged)",
     "latest or a missing tag means you can't tell what's running, and a re-pull can silently change it.",
     "Use an explicit version tag, ideally with a digest.", [IMAGES, CKS], D_SUP)
rule("CKS-SUP-002", "CKS", "info", "Pin images by digest",
     "Tags can be re-pushed; a digest is immutable and is what admission policies usually verify.",
     "image: repo/app:1.2.3@sha256:<digest>", [IMAGES], D_SUP)
rule("CKS-NET-001", "CKS", "medium", "Ship a NetworkPolicy",
     "Without one, any pod in the cluster can reach these pods.",
     "Default-deny plus explicit allows for the flows you need.", [NETPOL, CKS], D_CLS)
rule("CKS-NET-002", "CKS", "medium", "Terminate TLS at the Ingress",
     "Without spec.tls traffic reaches the cluster in plaintext.", "Add spec.tls (cert-manager can issue it).",
     [(K8S + "concepts/services-networking/ingress/#tls", "Ingress TLS")], D_CLS)

# --- Kubernetes operational best practice -----------------------------------------------------------
rule("K8S-RES-001", "Kubernetes", "medium", "Set resource requests and memory limits",
     "Without requests the scheduler can't place pods well; without a memory limit one pod can starve the node.",
     "resources: { requests: { cpu, memory }, limits: { memory } }",
     [(K8S + "concepts/configuration/manage-resources-containers/", "Resource management")])
rule("K8S-HEALTH-001", "Kubernetes", "low", "Readiness and liveness probes",
     "Probes route traffic only to ready pods and restart hung ones.", "Add readinessProbe and livenessProbe.",
     [(K8S + "concepts/configuration/liveness-readiness-startup-probes/", "Probes")])
rule("K8S-NET-001", "Kubernetes", "low", "Avoid NodePort / LoadBalancer unless intended",
     "These expose the app outside the cluster directly, bypassing the Ingress layer.",
     "Use ClusterIP behind an Ingress/Gateway unless direct exposure is required.",
     [(K8S + "concepts/services-networking/service/#publishing-services-service-types", "Service types")])
rule("K8S-AVAIL-001", "Kubernetes", "low", "PodDisruptionBudget for replicated workloads",
     "Node drains and upgrades can otherwise evict every replica at once.",
     "Add a PodDisruptionBudget (minAvailable or maxUnavailable).", [(K8S + "tasks/run-application/configure-pdb/", "Configure a PDB")])
rule("K8S-META-001", "Kubernetes", "low", "Recommended labels",
     "app.kubernetes.io/name and /instance make resources discoverable by tools, dashboards and policies.",
     "Add the app.kubernetes.io/* labels (usually via a labels helper).",
     [(K8S + "concepts/overview/working-with-objects/common-labels/", "Recommended labels")])
DEPR = (K8S + "reference/using-api/deprecation-guide/", "Deprecated API Migration Guide")
rule("K8S-API-001", "Kubernetes", "high", "No API versions removed in the target Kubernetes version",
     "The API server rejects removed versions: the install fails outright on that cluster.",
     "Move to the replacement API version listed in the migration guide.", [DEPR])
rule("K8S-API-002", "Kubernetes", "medium", "No deprecated API versions",
     "Deprecated versions still work but are scheduled for removal in a later release.",
     "Migrate now to the stable version.", [DEPR])

# --- Helm --------------------------------------------------------------------------------------------
BP = HELM + "chart_best_practices/"
rule("HELM-CHART-001", "Helm", "low", "Chart apiVersion v2",
     "apiVersion v1 is the Helm 2 format; dependencies and type only exist in v2.", "apiVersion: v2 in Chart.yaml",
     [(HELM + "topics/charts/#the-chartyaml-file", "The Chart.yaml file")])
rule("HELM-CHART-002", "Helm", "medium", "Chart version is SemVer 2",
     "Helm, repositories and dependency ranges all assume SemVer; anything else breaks upgrades and ordering.",
     "version: MAJOR.MINOR.PATCH (bump on every change)", [(BP + "conventions/#version-numbers", "Version numbers")])
rule("HELM-CHART-003", "Helm", "low", "Has a .helmignore",
     "Without it `helm package` ships everything in the folder: .git, CI files, local secrets.",
     "Add .helmignore (helm create's default is a good start).", [(HELM + "chart_template_guide/helm_ignore_file/", ".helmignore")])
rule("HELM-CHART-004", "Helm", "info", "Has values.schema.json",
     "A JSON schema validates user values at install time and documents them.",
     "Add values.schema.json describing your values.", [(HELM + "topics/charts/#schema-files", "Schema files")])
rule("HELM-CHART-005", "Helm", "info", "Has NOTES.txt",
     "Tells users how to reach and use the release after install.", "Add templates/NOTES.txt.",
     [(HELM + "chart_template_guide/notes_files/", "NOTES.txt")])
rule("HELM-TPL-001", "Helm", "low", "Named templates are prefixed with the chart name",
     "Template names are global across a chart and its subcharts; unprefixed names collide.",
     'define "<chart>.name" instead of define "name"', [(BP + "templates/#names-of-defined-templates", "Names of defined templates")])
rule("HELM-TPL-002", "Helm", "medium", "No non-deterministic functions",
     "rand*/gen*/uuidv4/now give a different result every render: permanent ArgoCD diffs and rotating secrets.",
     "Generate once outside the chart (or use lookup to keep an existing value).", [(HELM + "chart_template_guide/function_list/", "Function list")])
rule("HELM-TPL-003", "Helm", "low", "Don't hard-code namespaces",
     "Resources should land in the release namespace so `helm install -n` and ArgoCD destinations work.",
     "Omit metadata.namespace or use {{ .Release.Namespace }}.", [(BP + "templates/", "Templates")])
rule("HELM-VAL-001", "Helm", "low", "No unused values",
     "Values nobody reads mislead users into thinking they configure something.", "Remove them or wire them up.",
     [(BP + "values/", "Values")])
rule("HELM-VAL-002", "Helm", "low", "Image repository and tag come from values",
     "Hard-coded images can't be overridden for mirrors, air-gapped registries or patch releases.",
     'image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"', [(BP + "pods/#images", "Images")])
rule("HELM-DEP-001", "Helm", "low", "Dependencies are locked (Chart.lock)",
     "Without Chart.lock, `helm dependency build` can resolve different subchart versions over time.",
     "Run `helm dependency update` and commit Chart.lock.", [(BP + "dependencies/", "Dependencies")])
rule("HELM-DEP-002", "Helm", "low", "Dependency versions are constrained",
     "'*' or 'x' ranges pull in any new major version.", "Use a range like ~1.2.0 or ^1.2.0.",
     [(BP + "dependencies/#versions", "Dependency versions")])

CATALOG = {r["id"]: r for r in _R}

# finding key (from the analyser) -> rule ID
KEY_TO_RULE = {
    "hostNetwork": "CKS-HOST-001", "hostPID": "CKS-HOST-001", "hostIPC": "CKS-HOST-001", "hostPath": "CKS-HOST-002",
    "privileged": "CKS-POD-001", "runAsNonRoot": "CKS-POD-002", "allowPrivilegeEscalation": "CKS-POD-003",
    "readOnlyRootFilesystem": "CKS-POD-004", "capabilities": "CKS-POD-005", "capadd": "CKS-POD-006", "seccomp": "CKS-POD-007",
    "automount": "CKS-SA-001", "defaultsa": "CKS-SA-002", "saautomount": "CKS-SA-003",
    "rbacwild": "CKS-RBAC-001", "rbacsecrets": "CKS-RBAC-002", "rbacesc": "CKS-RBAC-003", "clusterscope": "CKS-RBAC-004",
    "secretenv": "CKS-SEC-001", "secretvalues": "CKS-SEC-002", "netpol": "CKS-NET-001", "tls": "CKS-NET-002",
    "resources": "K8S-RES-001", "probes": "K8S-HEALTH-001", "svcexpose": "K8S-NET-001",
}


def tag(findings):
    """Attach rule IDs (and the rule's category) to analyser findings."""
    for f in findings:
        if f.get("rule"):
            continue
        k = f.get("key")
        rid = ("CKS-SUP-002" if f["sev"] == "info" else "CKS-SUP-001") if k == "image" else KEY_TO_RULE.get(k)
        if rid:
            f["rule"] = rid
            f["category"] = CATALOG[rid]["category"]
    return findings


def catalog():
    return dict(ruleset=RULESET, rules=_R)


# ---------------------------------------------------------------------------------------------------
# Chart-level checks (Helm + Kubernetes), beyond the per-resource security checks in the analyser
# ---------------------------------------------------------------------------------------------------
SEMVER = re.compile(r"^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
NONDET = re.compile(r"\b(randAlphaNum|randAlpha|randNumeric|randAscii|randBytes|genCA|genSelfSignedCert|genSignedCert|genPrivateKey|uuidv4|now)\b")


def _f(rid, title, detail, tpl=None, resource=None, out=None, sev=None):
    r = CATALOG[rid]
    return dict(sev=sev or r["severity"], key=rid, rule=rid, category=r["category"], title=title, detail=detail,
                fix=r["fix"], resource=resource, tpl=tpl, out=out)


def _first(files, rx, only_templates=True):
    for p, t in files.items():
        if only_templates and not (p.startswith("templates/") or "/templates/" in p):
            continue
        for i, ln in enumerate(t.split("\n"), 1):
            if re.search(rx, ln):
                yield p, i, ln


def chart_checks(files, chart, resources, objs, values_index, release_ns):
    out = []
    api = str(chart.get("apiVersion", ""))
    if api and api != "v2":
        out.append(_f("HELM-CHART-001", f"Chart apiVersion is {api}", "Helm 3/4 charts should use apiVersion v2.", dict(file="Chart.yaml", line=1)))
    ver = str(chart.get("version", ""))
    if ver and not SEMVER.match(ver):
        out.append(_f("HELM-CHART-002", f"Chart version '{ver}' isn't SemVer", "Use MAJOR.MINOR.PATCH.", dict(file="Chart.yaml", line=1)))
    if ".helmignore" not in files:
        out.append(_f("HELM-CHART-003", ".helmignore missing", "`helm package` will include everything in the chart folder.", dict(file="Chart.yaml", line=1)))
    if "values.schema.json" not in files:
        out.append(_f("HELM-CHART-004", "No values.schema.json", "Values aren't validated at install time.", dict(file="values.yaml", line=1) if "values.yaml" in files else None))
    if not any(p.endswith("templates/NOTES.txt") for p in files):
        out.append(_f("HELM-CHART-005", "No NOTES.txt", "Users get no post-install instructions.", None))

    # named templates without the chart-name prefix
    name = str(chart.get("name") or "")
    for p, i, ln in _first(files, r'define\s+"[^"]+"'):
        n = re.search(r'define\s+"([^"]+)"', ln).group(1)
        if name and not n.startswith(name + ".") and not p.startswith("charts/"):
            out.append(_f("HELM-TPL-001", f'Template "{n}" isn\'t prefixed with "{name}."', "Unprefixed names can collide with subcharts.", dict(file=p, line=i)))
    for p, i, ln in _first(files, NONDET.pattern):
        if "{{" in ln:
            fn = NONDET.search(ln).group(1)
            out.append(_f("HELM-TPL-002", f"Non-deterministic `{fn}`", "Renders differently every time: ArgoCD shows a permanent diff, and secrets rotate on every upgrade.", dict(file=p, line=i)))
    # hard-coded namespaces (rendered namespace that isn't the release namespace)
    for r in resources:
        ns = r.get("namespace")
        if ns and ns != release_ns:
            t = files.get(r["source"], "")
            line = next((i for i, ln in enumerate(t.split("\n")[r["tplStart"] - 1:r["tplEnd"]], r["tplStart"]) if "namespace:" in ln), r["tplStart"])
            out.append(_f("HELM-TPL-003", f"{r['kind']}/{r['name']} hard-codes namespace '{ns}'", "It won't follow `helm install -n` or the ArgoCD destination namespace.", dict(file=r["source"], line=line), r["id"]))

    # unused values (top-level keys never referenced)
    refs = set()
    for t in [t for p, t in files.items() if p.startswith("templates/") or "/templates/" in p]:
        refs |= {m.split(".")[0] for m in re.findall(r"\.Values\.([A-Za-z0-9_]+)", t)}
        if re.search(r"toYaml\s+\.Values\s*[|}]|\.Values\s*\|\s*toYaml|\$\.Values\s*\}\}", t):
            refs.add("*")
    sub = {str(d.get("alias") or d.get("name")) for d in chart.get("dependencies") or []}
    if "*" not in refs:
        for k, line in values_index.items():
            if "." in k or k in refs or k in sub or k in ("global", "nameOverride", "fullnameOverride"):
                continue
            out.append(_f("HELM-VAL-001", f"Value `{k}` is never used", "No template reads it (and it isn't a subchart's values).", dict(file="values.yaml", line=line)))

    # hard-coded images
    for p, i, ln in _first(files, r"^\s*-?\s*image:\s*[\"']?[a-z0-9][\w./-]+(:[\w.-]+)?[\"']?\s*$"):
        out.append(_f("HELM-VAL-002", "Image hard-coded in template", ln.strip()[:100], dict(file=p, line=i)))

    # dependencies
    deps = chart.get("dependencies") or []
    if deps and "Chart.lock" not in files and "requirements.lock" not in files:
        out.append(_f("HELM-DEP-001", "Dependencies aren't locked", f"{len(deps)} dependencies but no Chart.lock.", dict(file="Chart.yaml", line=1)))
    for d in deps:
        v = str(d.get("version", ""))
        if not v or v in ("*", "x", ">=0.0.0") or re.fullmatch(r"\d+\.x(\.x)?|x\.x\.x", v):
            ct = files.get("Chart.yaml", "")
            line = next((i for i, ln in enumerate(ct.split("\n"), 1) if f"name: {d.get('name')}" in ln), 1)
            out.append(_f("HELM-DEP-002", f"Dependency {d.get('name')} version '{v or 'unset'}' is unconstrained", "Any new major version can be pulled in.", dict(file="Chart.yaml", line=line)))

    # Kubernetes: PDB + recommended labels
    has_pdb = any(r["kind"] == "PodDisruptionBudget" for r in resources)
    for r in resources:
        if r["kind"] in ("Deployment", "StatefulSet") and not r.get("hook"):
            o = objs.get(r["id"]) or {}
            reps = (o.get("spec") or {}).get("replicas")
            hpa = any(x["kind"] == "HorizontalPodAutoscaler" and any(l["to"] == r["id"] for l in x["links"]) for x in resources)
            if not has_pdb and ((isinstance(reps, int) and reps > 1) or hpa):
                out.append(_f("K8S-AVAIL-001", f"{r['kind']}/{r['name']} has multiple replicas but no PDB", "A node drain can evict every replica at once.",
                              dict(file=r["source"], line=r["tplStart"]), r["id"]))
    missing = [r for r in resources if not r.get("hook") and r["kind"] not in ("Namespace",)
               and not {"app.kubernetes.io/name", "app.kubernetes.io/instance"} <= set(((objs.get(r["id"]) or {}).get("metadata") or {}).get("labels") or {})]
    if missing:
        r = missing[0]
        out.append(_f("K8S-META-001", f"{len(missing)} resource(s) missing app.kubernetes.io/name or /instance labels",
                      ", ".join(f"{x['kind']}/{x['name']}" for x in missing[:6]), dict(file=r["source"], line=r["tplStart"]), None))
    return out
