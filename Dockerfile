# syntax=docker/dockerfile:1
# Helm binary comes from the multi-arch alpine/helm image (works on Apple Silicon + Intel).
ARG HELM_VERSION=4.3.1
FROM alpine/helm:${HELM_VERSION} AS helm

FROM python:3.12-alpine
ARG GIT_SHA=dev
ARG BUILD_DATE=""
COPY --from=helm /usr/bin/helm /usr/local/bin/helm
WORKDIR /app
COPY requirements.txt .
# git: open charts straight from a repository address
RUN apk add --no-cache git \
 && pip install --no-cache-dir -r requirements.txt \
 && adduser -D -u 10001 app
COPY app/ /app/app/
COPY sample-chart/ /app/sample-chart/
# Official logos (Simple Icons, CC0 SVGs; each mark belongs to its owner) - fetched at build time so the app never
# calls out at runtime. A failed download just means the UI shows a neutral fallback badge.
ARG SIMPLE_ICONS_VERSION=16.30.0
RUN mkdir -p /app/app/static/logos && cd /app/app/static/logos \
 && for s in kubernetes helm prometheus grafana postgresql redis nginx argo; do \
      wget -q -T 15 -O "$s.svg" "https://cdn.jsdelivr.net/npm/simple-icons@${SIMPLE_ICONS_VERSION}/icons/$s.svg" || rm -f "$s.svg"; \
    done \
 && printf 'Logos from Simple Icons v%s (https://simpleicons.org), CC0-1.0. Trademarks belong to their owners; used only to identify the software.\n' "$SIMPLE_ICONS_VERSION" > ATTRIBUTION.txt
# Make sure the non-root user can read everything, whatever permissions the files had on the host
RUN chmod -R a+rX,go-w /app

# Practise what we preach: non-root, helm caches in /tmp (tmpfs at runtime)
ENV HOME=/tmp HELM_CACHE_HOME=/tmp/helm/cache HELM_CONFIG_HOME=/tmp/helm/config HELM_DATA_HOME=/tmp/helm/data \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080 \
    GIT_SHA=${GIT_SHA} BUILD_DATE=${BUILD_DATE}
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
CMD ["python", "/app/app/server.py"]
