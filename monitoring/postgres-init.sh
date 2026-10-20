#!/bin/sh
# Read-only login for Grafana. Runs once, when the Postgres volume is first created.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v pw="${GRAFANA_DB_PASSWORD:-grafana-ro-local}" <<'SQL'
CREATE ROLE grafana_ro LOGIN PASSWORD :'pw';
GRANT CONNECT ON DATABASE helmviz TO grafana_ro;
GRANT USAGE ON SCHEMA public TO grafana_ro;
-- tables are created later by the app (as helmviz): grant SELECT on them automatically
ALTER DEFAULT PRIVILEGES FOR ROLE helmviz IN SCHEMA public GRANT SELECT ON TABLES TO grafana_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO grafana_ro;
SQL
