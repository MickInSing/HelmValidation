# Helm Chart Walkthrough

A small local web app. Upload a Helm chart and it walks you through it step by step:

1. **Chart.yaml**: identity and versions
2. **values.yaml**: the defaults every template reads
3. **_helpers.tpl**: named templates and labels
4. **Every rendered resource, in Helm's install order.** Each step highlights the template lines, the `.Values` it reads (and where they live in values.yaml), the helpers it includes, and the rendered manifest.
5. **NOTES.txt**, then a **summary** with `helm lint` output and every finding.

The diagram shows how the resources connect (Service → Deployment, RoleBinding → Role/SA, Ingress → Service, HPA → Deployment and so on). Each resource is checked against CKS hardening practices: securityContext, runAsNonRoot, privilege escalation, read-only root FS, dropped capabilities, seccomp, resources, image pinning, SA token automount, host namespaces, hostPath, RBAC wildcards and secret access, plaintext secret env vars, NetworkPolicy, and Ingress TLS. Each finding points to the exact line and includes a fix snippet.

## Run on OrbStack (Docker)

```bash
mkdir -p ~/charts                     # put chart folders or .tgz/.zip files here
cd helm-visualiser
docker compose up -d --build          # or: CHARTS_DIR=~/code/helm docker compose up -d --build
open http://localhost:8080          # or http://helm-visualiser.orb.local:8080
```

Click **Try the sample chart** to see it work, or drop in your own chart. A chart folder works directly (drag it in or use **Choose chart folder**), as does a packaged archive:

```bash
helm package ./mychart              # -> mychart-0.1.0.tgz
# or: helm pull bitnami/nginx       # any packaged chart works
# or: zip -r mychart.zip mychart/
```

If your browser blocks file uploads (common on managed laptops), use **Open from your charts folder**. The container reads `~/charts` read-only, so no upload is needed. The small grey line under the buttons should say `script loaded · server v3`. If it says `script not loaded`, the page's JavaScript is being blocked.

The container runs hardened: non-root UID 10001, read-only root filesystem, `/tmp` on tmpfs, all capabilities dropped, no-new-privileges and a 256 MB memory limit. It's bound to 127.0.0.1 only.

## Three views

Switch with the tabs at the top of the sidebar, or keys `1` `2` `3`.

* **Chart**: the step-by-step walkthrough of every file and rendered resource, with CKS checks.
* **Helm concepts**: one step per topic in the [Chart Template Guide](https://helm.sh/docs/chart_template_guide/) (built-in objects, values, functions and pipelines, flow control, variables, named templates, files, NOTES.txt, subcharts, .helmignore, debugging, YAML techniques, data types). Each shows how often *this* chart uses it, highlights every place in the code, flags anti-patterns (unused values, non-deterministic functions, missing .helmignore) and links to the docs. The diagram is Helm's render pipeline.
* **Infrastructure**: the same resources regrouped by concern: network and ingress, compute and scaling, identity and authentication, secrets and config, storage and data, logging and observability, security posture, and Kubernetes platform. Each row has a status and links to its evidence line. Things the cluster must provide (ingress controller, metrics-server, operators) and things only **inferred** (a database from `DB_*` env vars, a node log agent) are dashed and marked `?`. Click a resource node to open it in the Chart view.

## Charts that need ArgoCD (or other outside) values

Some charts refuse to render with plain `helm template`. They use `fail` or `required` to demand values that ArgoCD passes at deploy time. When that happens the **Values** panel opens with:

* **A form for each value the chart needs.** These are detected from `fail`/`required` in the templates and from the error message. Type real values, or click **Fill empty with placeholders**.
* **"Just show me the diagram".** One click fills placeholders (`setme-…`, highlighted orange in the code) and bypasses `fail`/`required` in a scratch copy, so you get a picture even when you don't know the values. Your chart is never modified.
* **Values files** shipped in the chart (`values-prod.yaml`, ...), to tick like Argo `valueFiles`.
* **Overrides**: YAML, `key=value` lines (Argo parameters / `--set`), or **paste the whole ArgoCD `Application`**. Its `helm.parameters`, `values`, `valuesObject` and `valueFiles` are applied the way Argo would.

## External dependencies

Anything the chart relies on that Helm doesn't provide appears as a dashed orange **External** node, wired to the resources that need it, with its own walkthrough step:

* Values that must come from ArgoCD / deploy time
* `lookup` calls. These read the live cluster and are always empty in `helm template`.
* `.Capabilities` checks. Output depends on the cluster's APIs and version.
* Third-party operators whose CRDs the chart uses (Prometheus Operator, cert-manager, External Secrets, Istio, Argo, ...)
* ArgoCD sync-wave / hook annotations
* Secrets, ConfigMaps, ServiceAccounts and PVCs the chart references but doesn't create (the `existingSecret` pattern)

## Repo layout

```
app/                    Python server, analyser, views and UI (static/)
sample-chart/           demo chart bundled into the image
Dockerfile              Helm 4 + Python, non-root, read-only root FS
docker-compose.yml      local run on OrbStack/Docker
deploy/chart/           Helm chart for deploying the visualiser itself
deploy/argocd/          ArgoCD Application pointing at deploy/chart
.github/workflows/      CI: build multi-arch image -> GHCR -> pin tag for Argo
```

## Publish to GitHub

```bash
cd helm-visualiser
git init -b main
git add .
git commit -m "Helm chart visualiser"
gh repo create MickInSing/helm-visualiser --private --source . --push
#   or create the repo on github.com, then:
#   git remote add origin https://github.com/MickInSing/helm-visualiser.git && git push -u origin main
```

Each push to `main` runs **.github/workflows/build.yml**, which:

1. Builds `linux/amd64` + `linux/arm64` (cluster nodes and Apple Silicon).
2. Pushes `ghcr.io/mickinsing/helm-visualiser:sha-<commit>`, `:main` and `:latest` (plus `:1.2.3` for `v1.2.3` git tags).
3. Commits the new `sha-…` tag into `deploy/chart/values.yaml`, so ArgoCD rolls it out.

Pull requests build but don't push. If `main` has branch protection that blocks the bot's commit, allow `github-actions[bot]` or switch step 3 to opening a PR.

**Image visibility:** GHCR packages start **private**. Either make it public (GitHub → Packages → helm-visualiser → Package settings), or create a pull secret in the cluster and set `imagePullSecrets` (instructions in `deploy/chart/values.yaml`).

## Deploy with ArgoCD

```bash
kubectl apply -n argocd -f deploy/argocd/application.yaml
```

Argo creates the `helm-visualiser` namespace with Pod Security `restricted` labels and syncs `deploy/chart`. Per-cluster settings (ingress host, SSO annotations, pull secret) go in the Application's `valuesObject`. If the repo is private, add it in Argo first (Settings → Repositories, or `argocd repo add`).

The chart passes its own checks: dedicated SA with no token and no RBAC, non-root, read-only root FS, all capabilities dropped, seccomp, resource limits, probes, and a NetworkPolicy that denies all egress and only allows ingress from the namespaces you list.

**There is no login.** Anyone who can reach the UI can make the server run `helm template` on an uploaded chart (sandboxed: read-only, no network, no API token). Keep the ingress internal and put SSO in front (oauth2-proxy annotations are stubbed in values.yaml).

Try it locally without Argo:

```bash
helm lint deploy/chart
helm template hv deploy/chart | less
kubectl create ns helm-visualiser && helm install hv deploy/chart -n helm-visualiser
```

Load `deploy/chart` into the visualiser itself. It makes a good worked example of a hardened chart.

## Keys

`←`/`→` (or `k`/`j`) move between steps. `t` switches between Template and Rendered. Click a diagram node to jump to its step. Click any chip or "Show in template" to jump to that line.

## Notes

* Charts with `dependencies:` need a `charts/` folder (`helm dependency build` before packaging). The app tries to fetch them, which needs network access.
* Uses **Helm 4** (4.3.1). Change it with `docker compose build --build-arg HELM_VERSION=3.18.4` if you need Helm 3 behaviour.
* The checks are a learning aid, not a replacement for kube-bench, kubesec, Trivy or Kyverno/Gatekeeper policies.
