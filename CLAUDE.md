# CLAUDE.md

## Development Environment

- **One-time host setup**: `docker volume create pnpm-store` (creates the shared external volume mounted into `api-dev` and `frontend-dev` for a deduped pnpm content-addressable store)
- `make up` / `make down` - Start/stop all services
- `make build` - Build all Docker images
- `make logs` - View container logs
- `make stop-all` - Full container cleanup
- `make pull` - Pull latest images
- Access at <https://localhost:443>
- Default credentials: `john.doe@codeclarity.io` / `ThisIs4Str0ngP4ssW0rd?`
- IMPORTANT: Hot-reload is enabled. API, frontend, plugins, and services reload on save in containers. No need to restart containers or use `pnpm dev`.

## Architecture Overview

- **Frontend**: Vue.js 3 + TypeScript + Tailwind CSS + Reka UI (port 443)
- **API**: NestJS + TypeScript + TypeORM
- **Backend**: Go microservices + Bun ORM
- **Databases**: PostgreSQL with 3 databases: `codeclarity` (app data), `knowledge` (vuln data), `config` (plugin metadata)
- **Message Queue**: RabbitMQ for async task processing
- **Go module paths**: `github.com/CodeClarityCE/plugin-*`, `github.com/CodeClarityCE/utility-types`
- **Message flow**: API Request -> Dispatcher -> Downloader (if git needed) -> Dispatcher -> Plugins (stage execution) -> Dispatcher (results)

### Restart semantics & orphan recovery

`make down` removes the RabbitMQ container, which in dev has **no data volume** by
design (`make down && make up` is the deliberate way to clear a wedged queue), so
**all in-flight messages are lost** on restart. Postgres persists (named volume),
so analysis rows survive — leaving them `started`/`ongoing` with nothing to drive
them. Recovery is therefore DB-driven, not queue-durable:

- The dispatcher's **reaper** (`backend/services/dispatcher/reaper.go`) runs a
  one-shot **startup recovery pass** (queue is known-empty, so every non-terminal
  analysis is re-driven) plus a periodic interval pass (`REAPER_INTERVAL`, default
  60s; stuck threshold `REAPER_STEP_TIMEOUT`, default 30m).
- **Stage-0 / pre-download** analyses are recovered by re-running the **downloader**
  first (`redriveStageZero` in `receive.go`); later stages re-dispatch in place
  (they read the SBOM from the DB). Re-running the downloader is idempotent.
- Recovery is **bounded**: a genuine download failure marks the analysis `failure`
  (downloader `receive.go`), so the reaper stops re-driving it; only lost-message /
  crash cases are retried. Non-terminal analyses older than `RECOVERY_MAX_AGE`
  (default 24h) are **retired** (marked `failure`) instead of re-driven, so a large
  backlog of abandoned analyses isn't re-downloaded on every restart.

### Database connection pooling

All services/plugins/API connect through a **pgbouncer** transaction pooler (`PG_DB_HOST=pgbouncer`,
`PG_DB_PORT=6432`), never directly to Postgres. This multiplexes the many per-replica client pools
onto a small server-side connection set, so replica count no longer drives `max_connections`.

- **Per-instance pool bounds** are env-overridable: `DB_MAX_OPEN_CONNS` (default 15),
  `DB_MAX_IDLE_CONNS` (3), `DB_CONN_MAX_LIFETIME_SECONDS` (300), `DB_CONN_MAX_IDLE_SECONDS` (60)
  for the Go services/plugins (applied via `DatabaseConfig.ApplyPool` in
  `backend/utilities/boilerplates/`), and `PG_DB_POOL_MAX` (10) for each NestJS API DataSource.
- **Pooler config**: dev is inline in `.cloud/docker/docker-compose.yaml`; prod uses
  `deployment/config/pgbouncer.ini` with `auth_query` (multi-role) + TLS. Prod prereqs: regenerate
  certs so the SAN includes `pgbouncer` (`make setup-pg-certs`) and keep `PGBOUNCER_AUTH_PASSWORD`
  (`.env.database`) in sync with `deployment/config/userlist.txt`.
- **Budget**: `default_pool_size(20) × (roles × databases)` stays under `max_connections`
  (300 dev / 200 prod, kept as headroom). Target replicas: downloader×8, js-sbom/vuln-finder/license-finder×4.

## Testing

- **Frontend**: `cd frontend && pnpm test:unit` (Vitest) / `pnpm test:e2e` (Cypress)
- **API**: `cd api && pnpm test` (Jest) / `pnpm test:e2e`
- **Backend plugins**: `cd backend/plugins/<name> && go test ./tests/`
- **Linting**: `cd frontend && pnpm lint` / `cd api && pnpm lint`

## Database Commands

- `make knowledge-setup` - Initialize knowledge DB
- `make knowledge-update` - Update vulnerability data (needs NVD API key)
- `make download-dumps` / `make dump-database` / `make restore-database` - Dump management
- `make create-knowledge-indexes` - GIN indexes for JSONB lookups

Migration workflow: see `.claude/rules/database-migrations.md`.

Production deployment: see `deployment/CLAUDE.md`.

## License

AGPL-3.0. All contributions must be compatible with this license.
