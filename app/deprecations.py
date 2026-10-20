"""Removed / deprecated Kubernetes API versions.

Source: https://kubernetes.io/docs/reference/using-api/deprecation-guide/
(checked 2026-10-20: the most recent removal is v1.32; no removals listed for v1.33-v1.36).
Each entry: (apiVersion, kinds or None for "all kinds in this group/version", removed_in, replacement).
"""
from rules import CATALOG

DEFAULT_TARGET = "1.36"
TARGETS = [f"1.{m}" for m in range(25, 37)]

REMOVED = [
    # v1.32
    ("flowcontrol.apiserver.k8s.io/v1beta3", ["FlowSchema", "PriorityLevelConfiguration"], "1.32", "flowcontrol.apiserver.k8s.io/v1"),
    # v1.29
    ("flowcontrol.apiserver.k8s.io/v1beta2", ["FlowSchema", "PriorityLevelConfiguration"], "1.29", "flowcontrol.apiserver.k8s.io/v1"),
    # v1.27
    ("storage.k8s.io/v1beta1", ["CSIStorageCapacity"], "1.27", "storage.k8s.io/v1"),
    # v1.26
    ("flowcontrol.apiserver.k8s.io/v1beta1", ["FlowSchema", "PriorityLevelConfiguration"], "1.26", "flowcontrol.apiserver.k8s.io/v1"),
    ("autoscaling/v2beta2", ["HorizontalPodAutoscaler"], "1.26", "autoscaling/v2"),
    # v1.25
    ("batch/v1beta1", ["CronJob"], "1.25", "batch/v1"),
    ("discovery.k8s.io/v1beta1", ["EndpointSlice"], "1.25", "discovery.k8s.io/v1"),
    ("events.k8s.io/v1beta1", ["Event"], "1.25", "events.k8s.io/v1"),
    ("autoscaling/v2beta1", ["HorizontalPodAutoscaler"], "1.25", "autoscaling/v2"),
    ("policy/v1beta1", ["PodDisruptionBudget"], "1.25", "policy/v1"),
    ("policy/v1beta1", ["PodSecurityPolicy"], "1.25", "Pod Security Admission (no replacement API)"),
    ("node.k8s.io/v1beta1", ["RuntimeClass"], "1.25", "node.k8s.io/v1"),
    # v1.22
    ("admissionregistration.k8s.io/v1beta1", ["MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"], "1.22", "admissionregistration.k8s.io/v1"),
    ("apiextensions.k8s.io/v1beta1", ["CustomResourceDefinition"], "1.22", "apiextensions.k8s.io/v1"),
    ("apiregistration.k8s.io/v1beta1", ["APIService"], "1.22", "apiregistration.k8s.io/v1"),
    ("authentication.k8s.io/v1beta1", ["TokenReview"], "1.22", "authentication.k8s.io/v1"),
    ("authorization.k8s.io/v1beta1", ["SubjectAccessReview", "LocalSubjectAccessReview", "SelfSubjectAccessReview"], "1.22", "authorization.k8s.io/v1"),
    ("certificates.k8s.io/v1beta1", ["CertificateSigningRequest"], "1.22", "certificates.k8s.io/v1"),
    ("coordination.k8s.io/v1beta1", ["Lease"], "1.22", "coordination.k8s.io/v1"),
    ("extensions/v1beta1", ["Ingress"], "1.22", "networking.k8s.io/v1"),
    ("networking.k8s.io/v1beta1", ["Ingress", "IngressClass"], "1.22", "networking.k8s.io/v1"),
    ("rbac.authorization.k8s.io/v1beta1", ["ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"], "1.22", "rbac.authorization.k8s.io/v1"),
    ("scheduling.k8s.io/v1beta1", ["PriorityClass"], "1.22", "scheduling.k8s.io/v1"),
    ("storage.k8s.io/v1beta1", ["CSIDriver", "CSINode", "StorageClass", "VolumeAttachment"], "1.22", "storage.k8s.io/v1"),
    # v1.16
    ("extensions/v1beta1", ["Deployment", "DaemonSet", "ReplicaSet", "NetworkPolicy", "PodSecurityPolicy"], "1.16", "apps/v1 / networking.k8s.io/v1"),
    ("apps/v1beta1", None, "1.16", "apps/v1"),
    ("apps/v1beta2", None, "1.16", "apps/v1"),
]


def _v(s):
    try:
        a, b = str(s).lstrip("v").split(".")[:2]
        return int(a), int(b)
    except ValueError:
        return (1, 99)


def check(resources, files, target=DEFAULT_TARGET):
    """Findings for resources using API versions removed at/before `target` (K8S-API-001)
    or removed in a later release (K8S-API-002, deprecated)."""
    if target not in TARGETS:
        target = DEFAULT_TARGET
    tv = _v(target)
    out = []
    for r in resources:
        api, kind = r.get("apiVersion") or "", r["kind"]
        for gv, kinds, removed, repl in REMOVED:
            if api != gv or (kinds and kind not in kinds):
                continue
            t = files.get(r["source"], "")
            line = next((i for i, ln in enumerate(t.split("\n")[r["tplStart"] - 1:r["tplEnd"]], r["tplStart"]) if "apiVersion" in ln), r["tplStart"])
            gone = _v(removed) <= tv
            rid = "K8S-API-001" if gone else "K8S-API-002"
            out.append(dict(
                sev=CATALOG[rid]["severity"], key=rid, rule=rid, category="Kubernetes", resource=r["id"],
                title=f"{kind} uses {api}: removed in v{removed}" + ("" if gone else f" (target is v{target})"),
                detail=(f"Kubernetes v{target} no longer serves `{api}`; this resource fails to install." if gone
                        else f"Still served on v{target}, but removed in v{removed}: it works today and breaks when the cluster is upgraded.")
                       + f" Use **{repl}**.",
                fix=f"apiVersion: {repl}", tpl=dict(file=r["source"], line=line),
                out=dict(file="__rendered__", line=r["outStart"]),
            ))
            break
    return out
