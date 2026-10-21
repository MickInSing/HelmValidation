# Helm Chart Walkthrough

A local web app (and CI check) that walks you through a Helm chart step by step, explains every piece, and checks it against Kubernetes, Helm and CKS best practice.

* **Three views of every chart.**
  * **Chart**: every file and rendered resource, in install order.
  * **Helm concepts**: the Chart Template Guide topics, as this chart uses them.
  * **Infrastructure**: network, identity, secrets, storage, logging, security and platform.
* **Rules catalog.** 61 checks with IDs, severities, fixes and references, on a **Best practices** page stamped with the ruleset version and last-updated date. It covers CKS (22), Kubernetes (7), Helm (12) and **Learnings** (20).
* **Deprecated / removed API check** against a target Kubernetes version.
* **Exceptions & notes** (`.helm-visualiser.yaml`): accept a finding, with a reason and an expiry date.
* **Scan history** in Postgres (summaries only), **Grafana** dashboards and Prometheus **/metrics**.
* **Watched repos**: optional scheduled rescans.
* **Compare** two branches, tags or commits: new, fixed and accepted findings.
* **PR check**: a GitHub Action that comments the score and diff on every chart PR.
* Charts from **Git addresses**, uploads, a mounted folder or the bundled sample, with ArgoCD-style values.

## Quick start (OrbStack / Docker)

```bash
mkdir -p ~/charts                       # optional: charts the app can open without uploading
cd helm-visualiser
docker compose up -d --build
open http://localhost:8080              # the visualiser
open http://localhost:3000              # Grafana (anonymous read-only; admin/admin to edit)
```

The stack is the app, Postgres 17 (scan history), Prometheus v3.15 (app metrics) and Grafana 13.2 with the datasources and dashboard already provisioned. All ports are bound to 127.0.0.1. Set `POSTGRES_PASSWORD`, `GRAFANA_DB_PASSWORD` and `GRAFANA_ADMIN_PASSWORD` in your shell before the first `up` if this isn't just your laptop.

## Home page

| Tab | What's there |
|---|---|
| **Scan a chart** | Drop/choose a chart, open a Git address, pick from `~/charts`, or try the sample. Set the release, namespace and **target Kubernetes version**, and tick **Don't record** for a one-off private scan. |
| **Best practices** | The rules catalog, with live metrics: 30-day stats from the history database, or totals since the server started if there is none (a status line says which). Filter by CKS / Kubernetes / Helm, search, see how often each rule fails (last 30 days). Shows **ruleset version · last updated · Helm version**. Link straight to a rule: `/?home=rules&rule=CKS-POD-002`. |
| **History** | Recent scans: repo, ref, score, findings, status, trigger (ui / api / schedule / pr). Click a Git scan to reopen it. |
| **Watched repos** | Add a repo + chart with a frequency (hourly / 6h / daily / weekly). Pause, run now, remove. |

## Inside a chart

* **Home** (top left, or `h`) goes back to the home tabs without closing the chart; **← Back to chart** returns to it.
* **Infrastructure → Pods**: see the Pods view below.
* **Chart / Helm concepts / Infrastructure** tabs in the sidebar (keys `1` `2` `3`).
* **Template / Rendered / Side by side** code views (`t` cycles).
* **Diagram zoom & pan**: scroll to zoom, drag to pan, double-click to zoom in, `+` / `-` / `0` (fit), `f` or ⇕ for a taller diagram. Large charts get a wider canvas instead of squashed nodes, and the active node is kept in view.
* Every finding shows its **rule ID** (click for the catalog entry). Accepted findings are struck through, with the reason, owner and expiry date.
* **Values**: supply what ArgoCD would (parameters, values, valueFiles, or paste the whole `Application`), or preview with placeholders.
* **Compare** (Git charts): scan another branch, tag or commit; see the score change and the new, fixed and newly accepted findings; copy the result as Markdown.
* **Watch** (Git charts): add the chart to the scheduled rescans.
* **Share link**: a URL that reopens the same chart and view.

## Learnings: public security & performance guidance

Twenty extra checks (`LRN-SEC-*`, `LRN-PERF-*`) drawn from the [OWASP Kubernetes Top 10 (2025)](https://kubernetes-top10.owasp.org/), the [Kubernetes Security Checklist](https://kubernetes.io/docs/concepts/security/security-checklist/), [NSA/CISA hardening guidance](https://kubernetes.io/blog/2021/10/05/nsa-cisa-kubernetes-hardening-guidance/), the [Prometheus security model](https://prometheus.io/docs/operating/security/), [Grafana hardening](https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-security-hardening/), [CloudNativePG security](https://cloudnative-pg.io/docs/devel/security) and [Helm provenance](https://helm.sh/docs/topics/provenance/). Only things a chart scan can actually detect are included.

| ID | Learning | Source |
|---|---|---|
| LRN-SEC-001 | No bindings to cluster-admin or anonymous / all-authenticated groups | OWASP K02 · NSA/CISA |
| LRN-SEC-002 | Pod Security baseline: no hostPort, unsafe sysctls, Unmasked procMount, unconfined AppArmor, custom SELinux | Pod Security Standards |
| LRN-SEC-003 | Namespaces the chart creates enforce Pod Security Admission | OWASP K04 |
| LRN-SEC-004 | No credentials or private keys in ConfigMaps | K8s Security Checklist · OWASP K03 |
| LRN-SEC-005 | No literal secrets in values.yaml defaults | OWASP K03 |
| LRN-SEC-006 | No passwords embedded in URLs (env or ConfigMaps) | OWASP K03 |
| LRN-SEC-007 | NetworkPolicies restrict egress, not just ingress | K8s Checklist · NSA/CISA · OWASP K05 |
| LRN-SEC-008 | Prometheus / Grafana / Alertmanager / exporters not exposed via LoadBalancer, NodePort or an unauthenticated Ingress | Prometheus security model · OWASP K06 |
| LRN-SEC-009 | Prometheus `--web.enable-admin-api` / `--web.enable-lifecycle` off | Prometheus security model |
| LRN-SEC-010 | Grafana anonymous access off, or Viewer-only | Grafana docs · OWASP K09 |
| LRN-SEC-011 | Grafana admin password from a Secret, not default or plaintext | Grafana docs · OWASP K09 |
| LRN-SEC-012 | Grafana hardening: `cookie_secure`, `allow_embedding` off, authenticated `/metrics` | Grafana hardening |
| LRN-SEC-013 | Database connections don't set `sslmode=disable` / `ssl=false` | CloudNativePG security · OWASP K03 |
| LRN-SEC-014 | Chart dependencies from HTTPS or OCI, never http:// | Helm provenance · OWASP K07 |
| LRN-PERF-001 | Memory limit equals memory request | K8s Security Checklist |
| LRN-PERF-002 | HPA targets request the resource they scale on | Kubernetes HPA docs |
| LRN-PERF-003 | Replicated workloads spread across nodes/zones | Topology spread docs |
| LRN-PERF-004 | Liveness probe isn't a copy of the readiness probe | Kubernetes probes docs |
| LRN-PERF-005 | Prometheus, Grafana, Alertmanager and databases keep state on persistent volumes | Prometheus storage docs |
| LRN-PERF-006 | CloudNativePG: ≥2 instances, backups configured, superuser access off | CloudNativePG docs |

Grafana settings are read from `GF_*` env vars and from a `grafana.ini` in a ConfigMap (the Grafana Helm chart's layout).

## Pods view (Infrastructure → Pods)

Toggle **Architecture | Pods** at the top right of the Infrastructure diagram. The Pods view shows what the rendered chart asks Kubernetes to run:

* **Edge → Services → Namespace → Config & storage**, with port mappings on the arrows.
* **Workloads and their pods:**
  * a card per minimum replica, plus dashed cards for what the HPA can add (e.g. 2–5, cpu 70%);
  * StatefulSets get ordinal names and per-replica volumes, DaemonSets show "one on every node", and Jobs and CronJobs show dashed runs with their schedule.
* **Inside each pod:** containers (main, sidecar, init) with image, ports, CPU and memory, hardening, probes and finding badges; mounted ConfigMaps, Secrets and volumes; and the ServiceAccount (flagged if a token is mounted).
* **Overlays:** the NetworkPolicy fence around the namespace, PDB chips, a warning when replicas aren't spread, and pods laid out across zones when a zone spread rule is set.
* **Current chart | With fixes:** shows the pods after the fix planner's preview (it runs one with every previewable fix if you haven't).
* **Click a pod:** its details and findings appear below, and the code panel jumps to its template.
* **Official logos** (Kubernetes, Helm, Prometheus, Grafana, PostgreSQL, Redis, NGINX, Argo): the image build downloads them from Simple Icons, CC0 (`SIMPLE_ICONS_VERSION`). Without network at build time, a neutral badge is shown instead. Trademarks belong to their owners.

* **Operator-created pods (external):** when the chart contains a custom resource an operator turns into pods, those pods are drawn in orange, dashed, under "Created by operators". Supported: CloudNativePG `Cluster` / `Pooler`, Zalando `postgresql`, Prometheus Operator `Prometheus` / `Alertmanager`, and Strimzi `Kafka`. The view shows the instance count, roles, storage, and the Services and Secrets the operator creates.
  * **Connections:** an arrow runs from each workload that references those Secrets or Services, directly or through a ConfigMap. It is labelled with the port and the reference, and coloured by the workload's egress NetworkPolicy: **allowed**, **blocked** (connections would time out), **check policy** (ipBlock or label expressions), or **no egress policy**.
  * Secrets the operator creates are no longer listed as "must already exist".
* **With fixes highlights the change in place:**
  * a green bar lists every changed resource and its rules; click one to jump to it;
  * changed workloads get a green outline and a "Fixed here" line;
  * anything a fix added (hardening, probes, PDB, spread, new pods, new resources, TLS) is green with a "+".

This is the chart's *request*, not live cluster state: no node names, pod status or restarts.

## Shortcuts and layout

* **Hardening score** (left panel): **Fix planner →** opens the planner for this chart; **Show fixes on Pods** opens Infrastructure → Pods → With fixes. Clicking the score ring opens the planner too.
* **Adjustable frames:** drag the bar between the diagram and the panels below, or between the explanation and the code. Double-click a bar to reset it. Your sizes are remembered in this browser.

## Fix planner (Best practices tab)

1. **Pick a chart**: the one you have open, or any Git chart from Watched / History (it's scanned on the spot).
2. **Pick the fixes**: the chart's failing rules, grouped by framework. Rules marked **preview** can be applied to the rendered chart; **prompt only** rules need a template decision and go straight into the prompt. Quick-select high + critical, all previewable, all, or clear. **Severity toggles** (Critical / High / Medium / Low / Info) show or hide each level: turning one on selects its rules, turning it off clears them. By default only Critical and High are on.
3. **Preview impact**: the fixes are applied to a copy of the *rendered* manifests (like Helm's `--post-renderer`), and the result is re-checked. You see:
   * the score before and after, and the findings fixed (and any introduced);
   * every change with its **risk**, e.g. *read-only root FS breaks apps that write outside /tmp*, *drop ALL breaks ports < 1024*, *default-deny blocks the ingress controller*;
   * a **side-by-side** of each changed or new resource, current vs with fixes.
4. **Claude prompt**: copy or download a Markdown prompt with the rules, why they matter, the exact changes, the risks to handle, the target rendered YAML and the current chart source (secrets redacted). It asks Claude to implement the fixes in **templates and values with secure defaults**, keep backwards compatibility, record anything not fixed in `.helm-visualiser.yaml`, bump `Chart.yaml` `version` (minor if values were added, else patch), and re-run the check.
5. **Git commands**: a ready-made branch name, plus clone (or `gh repo fork` if you can't push), branch, verify, commit, push and `gh pr create`. The visualiser never holds a write token; the PR check action then comments the before/after score on the PR.

The preview shows what the cluster would receive, not template edits. Placeholder values (resource sizes, oauth2-proxy URLs, TLS secret names) are flagged in the risks for Claude to replace.

## Exceptions and notes: `.helm-visualiser.yaml`

Put it in the chart folder, or the repo root to cover every chart (see `examples/.helm-visualiser.yaml`):

```yaml
notes: |
  Shown at the top of the walkthrough.
exceptions:
  - rule: CKS-HOST-001              # rule ID from the Best practices page
    resource: DaemonSet/node-agent  # optional: Kind/name or Kind; omit for the whole chart
    container: agent                # optional
    reason: Needs host networking to collect node metrics
    expires: 2027-03-31             # required, max ~13 months: accepted risk gets reviewed
    owner: platform-team            # optional
```

Accepted findings don't count towards the score. Expired, unreasoned or open-ended exceptions are flagged and ignored. The summary step lists every exception and how many findings it matched.

## Scan history and privacy

Stored per scan: repo (host/org/repo), ref, commit, chart path, chart name/version, time, duration, status, **error class** (e.g. `needs-values`, `git-auth`), score, counts by severity, failed **rule IDs with resource kind**, dependency categories, API versions, and the tool, ruleset and Helm versions.

**Never stored:** file contents, values, rendered YAML, resource names, hostnames, env vars, tokens, raw error text (Helm errors can echo values), or upload file names (uploads are recorded as `upload`).

Retention is 180 days (`SCAN_RETENTION_DAYS`). Without `DATABASE_URL` everything still works, just without History, Watch and Grafana. If the database goes down, scans carry on.

## Grafana dashboard

*Helm visualiser: scan history* (provisioned from `monitoring/grafana/dashboards/helm-visualiser.json`):

* **Overview:** scans, repositories, average score, render failures, scans per day by status, score trend per repository.
* **Rules:** top failing rules (what to train people on); findings by framework and severity.
* **Repositories:** never passing (best score < 70), stale (> 30 days), render failures by cause, platform dependencies across charts, deprecated/removed API usage.
* **Versions:** API versions in rendered charts; tool / ruleset / Helm versions.
* **Health (Prometheus):** scan rate, p50/p95 scan duration, database up.

The JSON works in any Grafana: point a `grafana-postgresql-datasource` with uid `helmviz-pg` at the database (read-only user), and a Prometheus datasource with uid `helmviz-prom` at a Prometheus that scrapes `/metrics`.

## PR check (GitHub Action)

In a chart repo, add `.github/workflows/helm-check.yml` (copy `examples/pr-check.yml`):

```yaml
- uses: MickInSing/helm-visualiser@main
  with:
    charts-dir: charts
    kube-version: "1.36"
    fail-on-new: high          # fail if the PR adds high/critical findings
    # fail-under: 70
    registry-token: ${{ secrets.GITHUB_TOKEN }}
```

It checks out the PR and its base, scans every chart in both (in a container with no network and a read-only filesystem), and posts one PR comment that it keeps updated. The comment shows the score change and the new, fixed and accepted findings. The job fails on your thresholds. Locally, run the same check with:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/mickinsing/helm-visualiser python /app/app/cli.py \
  scan --head /work --base /work/../main-checkout --kube 1.36 --fail-on-new high
```

## API

| Endpoint | |
|---|---|
| `POST /api/scan` | `{"url": "https://github.com/org/repo/tree/main/charts/app", "kubeTarget": "1.36", "base": "main", "failUnder": 70, "noRecord": false}` returns score, counts, findings (rule, severity, resource, file:line), externals, plus a compare if `base` is set. Private repos: `X-Git-Token` header. |
| `GET /api/compare?url=&path=&base=&head=` | Diff of two refs, including Markdown. |
| `GET /api/rules` | Catalog + ruleset version + fail rates. |
| `GET /api/history`, `/api/stats`, `/api/repos` | History, 30-day stats, watched repos (`POST`/`DELETE` to manage). |
| `GET /metrics` | Prometheus: `helmviz_scans_total`, `helmviz_scan_duration_seconds`, `helmviz_findings_total`, `helmviz_git_fetch_total`, `helmviz_db_up`, `helmviz_watched_repos`, `helmviz_build_info`. |

## Open a chart from Git

Paste a browser address: a repo (`https://github.com/org/repo`), a folder (`…/tree/main/charts/app`) or a file (`…/blob/main/charts/app/values.yaml`). GitLab and Bitbucket addresses work too. Several charts means you get a picker. For private repos use the token field (used once, never stored), or give the server `GIT_TOKEN`, which scheduled scans need.

Safety: https only; allowed hosts only (`GIT_ALLOWED_HOSTS`; add your GitHub Enterprise host); shallow clone with a 60 s timeout and a 200 MB cap; symlinks checked out as plain files.

## Charts that need ArgoCD values

If `helm template` fails because the chart `fail`s without Argo parameters, the **Values** panel opens with:

* a form for each required value;
* **"Just show me the diagram"**, which fills placeholders and bypasses `fail`/`required` in a scratch copy;
* the chart's values files to tick;
* an overrides box that takes YAML, `key=value` lines, or a whole ArgoCD `Application`.

External dependencies (ArgoCD values, `lookup`, `.Capabilities`, operators/CRDs, sync waves, pre-existing Secrets) appear as dashed nodes.

## Repo layout

```
app/                    server, analyser, rules, views, db, git, CLI, UI (static/)
sample-chart/           demo chart bundled into the image
monitoring/             Prometheus config, Grafana provisioning + dashboard, Postgres init
deploy/chart/           Helm chart for the visualiser (CNPG database, NetworkPolicy, hardened pod)
deploy/argocd/          ArgoCD Application for deploy/chart
action.yml              reusable PR-check action
examples/               PR workflow + .helm-visualiser.yaml examples
.github/workflows/      CI: multi-arch image -> GHCR -> pin tag for Argo
```

## Publish to GitHub

```bash
git init -b main && git add . && git commit -m "Helm chart visualiser"
gh repo create MickInSing/helm-visualiser --private --source . --push
```

Each push to `main` builds `linux/amd64` + `linux/arm64`, pushes `ghcr.io/mickinsing/helm-visualiser:sha-<commit>` / `:main` / `:latest`, stamps the commit and build date into the image (shown in the UI and `/metrics`), and pins the new tag in `deploy/chart/values.yaml` so Argo rolls it out. GHCR images start private: make the package public, or use pull secrets and `registry-token`.

## Deploy with ArgoCD (CNPG for the database)

Prerequisite: the CloudNativePG operator is installed in the cluster.

```bash
kubectl apply -n argocd -f deploy/argocd/application.yaml
```

The chart creates a CNPG `Cluster` (`database.cnpg.*`: 1 instance and 2Gi by default; set `instances: 3` for HA, and configure `backup` for real data). The app reads the `uri` from the CNPG-generated `<release>-db-app` Secret. Set `database.mode: external` with `database.external.secretName` to use an existing Postgres instead. The NetworkPolicy allows the app to reach DNS, its own CNPG pods on 5432 and HTTPS to public Git hosts, and nothing else. Scheduled rescans are safe with several replicas.

Grafana in the cluster is a later step. The dashboard JSON in `monitoring/` is ready to drop into a Grafana sidecar ConfigMap.

**There is no login.** Keep the ingress internal and put SSO in front (oauth2-proxy annotations are stubbed in `values.yaml`).

## Notes

* Uses **Helm 4.3.1**. For Helm 3 behaviour: `docker compose build --build-arg HELM_VERSION=3.18.4`.
* Deprecated-API data comes from the official migration guide (removals up to v1.32; none listed for v1.33–v1.36). Target versions 1.25–1.36.
* The checks are a learning and review aid, not a replacement for admission policies (Kyverno/Gatekeeper), kube-bench or image scanning.
