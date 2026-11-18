# CLAUDE.md

## Development Environment

- **Setup**: `git clone --recursive`, then `make hooks` and `make up`. Host needs only git and Docker. `make up` runs the idempotent setup jobs (knowledge restore from the knowledge dump image, migrate, `_test` databases, dev account, default analyzer) before the app starts, so running it again is always safe. A failed job keeps the app stopped; `make logs SERVICE=<job>` shows why
- `make up` / `make down` - Start/stop all services (`down` keeps data)
- `make hooks` - Points the git hooks of the umbrella and every submodule at `.githooks/` (local `core.hooksPath`, relative). Its pre-commit runs the repo's own `.githooks/<hook>` first (api and frontend `pre-push` keep working), then scans the staged changes with gitleaks: the binary on PATH (the devcontainer has it), else the pinned image through Docker, else it refuses the commit. `git commit --no-verify` skips it; CI still scans
- `make build` - Build all Docker images
- `make logs` - View container logs
- `make pull` - Pull latest images
- `make reset CONFIRM=reset` - Wipe the dev stack's volumes, then `make up` again. Without `CONFIRM=reset` on the command line it exits non-zero and changes nothing
- Access at <https://localhost:443>
- Dev account (dev stack only): `john.doe@codeclarity.io` / `ThisIs4Str0ngP4ssW0rd?`
- Knowledge daemon: off in dev by default. Run `KNOWLEDGE_DAEMON_REPLICAS=1 make up` on the host to start it (`service-knowledge`, default 0 replicas); the devcontainer broker does not read the caller's shell, so the variable has no effect through it.
- IMPORTANT: Hot-reload is enabled. API, frontend, plugins, and services reload on save in containers. No need to restart containers or use `pnpm dev`.

### Agent stack in the devcontainer

The devcontainer has its own private Docker daemon and stack, separate from the host's (see `docs/adr/0006-agent-controls-dev-stack-through-a-validating-broker.md`). There is no `docker` CLI in it; `make` targets go through a broker that validates the Compose config first.

- `make up` / `make down` / `make build` / `make pull` / `make ps` / `make reset CONFIRM=reset` / `make migrate` (or `make migrate-codeclarity` and friends, which keep existing data), plus `make restart SERVICE=api`, `make logs SERVICE=api`, `make knowledge-update` and `make dump-knowledge`. `up` and `build` also accept `SERVICE=`.
- First run on an empty daemon: `make up`; the setup jobs do the rest. `make reset CONFIRM=reset` wipes the agent stack's data and runs `up` again; the broker refuses `reset` without that confirmation.
- The stack is on `localhost` from the agent (`:443`, `:3000`, Postgres `:5432`). Query logs in Loki at `localhost:3100` by `service` or `container` label, and use `make logs` as the fallback.
- A rejected `up` names the service, key and value. A new Compose key or bind mount needs a change to `.devcontainer/broker/policy.go` (and, for a bind, `.devcontainer/docker-compose.yml`), then a devcontainer rebuild by a developer.
- The dev stack's Compose files are listed once, in `.cloud/docker/compose-files.txt`. The broker and `.cloud/scripts/compose.sh` both read it, the broker on every request, so adding a file there needs no rebuild (its services still have to pass the policy).

## Architecture Overview

- **Frontend**: Vue.js 3 + TypeScript + Tailwind CSS + Reka UI (port 443)
- **API**: NestJS + TypeScript + TypeORM
- **Backend**: Go microservices + Bun ORM
- **Databases**: PostgreSQL with 4 databases: `codeclarity` (app data), `knowledge` (vuln data), `config` (one row of knowledge source watermarks: `nvd_last`, `gcve_last`, `osv_last`), `plugins` (plugin metadata). API migrations own the schema of all four.
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
- A `started` step whose plugin queue (`dispatcher_<plugin>`) has had no consumer for
  `STALLED_PLUGIN_GRACE` (seconds, default 180) fails its analysis with a reason naming
  the plugin (`stalled_plugin.go`). Startup recovery skips this check.

### Database connection pooling

All services/plugins/API connect through a **pgbouncer** transaction pooler (`PG_DB_HOST=pgbouncer`,
`PG_DB_PORT=6432`), never directly to Postgres. This multiplexes the many per-replica client pools
onto a small server-side connection set, so replica count no longer drives `max_connections`.

- **Per-instance pool bounds** are env-overridable: `DB_MAX_OPEN_CONNS` (default 15),
  `DB_MAX_IDLE_CONNS` (3), `DB_CONN_MAX_LIFETIME_SECONDS` (300), `DB_CONN_MAX_IDLE_SECONDS` (60)
  for the Go services/plugins (applied via `DatabaseConfig.ApplyPool` in
  `backend/utilities/boilerplates/`), and `PG_DB_POOL_MAX` (10) for each NestJS API DataSource.
- **Pooler config**: dev is inline in `.cloud/docker/docker-compose.yaml`; prod uses
  `deployment/config/pgbouncer.ini` with `auth_query` (multi-role) + TLS. The prod `generate-secrets` job
  (`deployment/scripts/generate-secrets.sh`) writes pgbouncer's `userlist.txt`, the `pgbouncer_auth` password and
  its certificate (SAN includes `pgbouncer`) into the secrets volume on first start; nothing is kept in sync by hand.
- **Budget**: dev keeps `default_pool_size(20) × (roles × databases)` under `max_connections` 300. Prod caps
  pgbouncer at `max_db_connections(20) × 4 databases = 80` server connections, under `max_connections`
  (`PG_MAX_CONNECTIONS`, default 100), whatever the replica count.
- **Replicas**: prod runs one replica of every service and plugin, sized for the reference machine (ADR 0012).
  For more, see "Larger instances" in `deployment/README.md` (downloader×8, each analysis plugin×4).
- **Memory**: prod's default containers' memory limits add up to at most 6.5 GiB (the reference machine's 8 GiB minus
  1.5 GiB for the OS); `.cloud/scripts/measure/memory-budget.sh` checks it with GOMEMLIMIT and `rabbitmq.conf`.

## Testing

- **Frontend**: `cd frontend && pnpm test:unit` (Vitest) / `pnpm test:e2e` (Playwright)
- **API**: `cd api && pnpm test` (Jest) / `pnpm test:e2e`
- **Backend plugins**: `cd backend/plugins/<name> && go test ./tests/`
- **Linting**: `cd frontend && pnpm lint` / `cd api && pnpm lint`
- **Formatting (root)**: root CI's `prettier` job checks every tracked Markdown, YAML and JSON file outside the submodules (`.prettierignore` skips tool-written ones) with the Prettier root `package.json` pins; fix with `node_modules/.bin/prettier --write <files>`, or check as CI does with `git ls-files -z '*.md' '*.yml' '*.yaml' '*.json' | xargs -0 sh .cloud/scripts/prettier-check.sh`
- **Fresh install (dev)**: `.cloud/scripts/tests/fresh-install/dev.sh` runs `make up` twice on an empty Docker daemon, logs in as the dev account and runs the Default Analyzer on an uploaded npm project; CI only (`fresh-install-dev` job), never against a stack you use

## CI (GitHub Actions)

Pipeline logic lives once, in reusable workflows in `CodeClarityCE/.github` (its README documents each workflow, its inputs and the caller template). Each repo's `.github/workflows/ci.yml` is a short caller referencing them at the moving `v1` tag; third-party actions and images are pinned by SHA or digest.

- **Moving `v1`**: central changes land on `.github`'s `develop`, then merge to its `main` through a PR, and only then does `v1` move, always to a commit on `main`. The central repo's own `ci` turns its fixtures' version check off (`version-check: false`), so its `develop` -> `main` PRs need no fixture bump; callers keep the check. See "Moving `v1`" in `.github`'s README.
- **Toolchains**: Go steps run in the digest-pinned `golang:1.27.4` image with `GOTOOLCHAIN=local`; the digest lives in `.github`'s `go-checks.yml`, keep it in sync with the Dockerfiles and `go.mod`. Node steps run in the Dockerfile's `toolchain` target, so `package.json` `packageManager` stays the single source of truth for pnpm. Go image repos test with `GOWORK=off` like the image build, so they pass only after `scripts/release-all.sh` has bumped utility versions.
- **`ci` gate**: the required check on `main` is a job named `ci` in the caller itself, since called jobs report as `<caller job> / <job>`. The caller also sets concurrency (cancel in progress for PRs only). Rulesets, `scripts/release-all.sh` and the callers all depend on that name.
- **Permissions**: a caller job using `go-image.yml` or `node-image.yml` grants `contents: write`, `id-token: write` and `attestations: write`, because GitHub validates the skipped release jobs too. It also passes `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` by name under `secrets:` (not `secrets: inherit`): reusable workflows only get secrets their caller passes, even ones stored in the `release` environment.
- **Releases**: PRs to `main` must bump the version (`config.json` / `package.json`). On `main`, release jobs run only when the repo variable `CI_RELEASE` is `true`, in the `release` environment (main only) that holds `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN`. They build amd64 and arm64 natively, attest provenance, then create the tag and release at the built commit; an existing tag is never re-released.
- **New repos**: a repo whose caller can release ships nothing until `CI_RELEASE` is on; turn it on with `docs/ci-release-test.md`. `scripts/release-all.sh` stops on such a repo while it is off.
- **Secret scan**: `workflow-lint.yml` has a `secret scan` job in every caller: gitleaks from a digest-pinned image with `.github`'s `.gitleaks.toml` (default rules plus GitLab, GitHub and Slack token rules with no entropy floor, matching push protection), over a PR's commits or a push's. A finding fails `ci`; the log names rule, file, line and fingerprint, never the value. Tests build token-shaped values at run time or use ones like `glpat-test-token`. A known dev key or fixture goes in the repo's `.gitleaksignore`: its fingerprint under a `#` line saying why. `.githooks/gitleaks.toml` and `gitleaks.env` copy the central rules and image; `gitleaks-sync.test.sh` fails when they differ from `v1`, so change the version in `.github`, `.githooks/gitleaks.env` and the devcontainer Dockerfile together
- **Dependabot**: weekly grouped updates into `develop` with a 3-day cooldown; `github.com/CodeClarityCE/*` is bumped only by `scripts/release-all.sh`.

Why it is built this way: `docs/adr/0009-ci-on-github-actions-via-central-reusable-workflows.md`. Org setup: `scripts/setup-github-actions-org.sh`.

## Database Commands

- `make knowledge-update` - Update vulnerability data (needs NVD API key); in the devcontainer the broker reads it from the gitignored `.cloud/env/.env.secrets`. See `docs/knowledge-dump.md`
- `make knowledge-update-osv` - Update only OSV advisories; also works in the devcontainer
- `make up` restores knowledge + config from the `codeclarityce/knowledge-dump` image when the knowledge database is empty. `make restore-database` restores a local dump set from `deployment/dump` into empty `knowledge` and `config` databases, after verifying its manifest; see `docs/knowledge-dump.md`
- `make dump-knowledge` - Dumps `knowledge` + `config` with a manifest, only after the read-only completeness gate passes; also works in the devcontainer. `WAIVE=<checks> REASON=<why>` waives named source checks during an upstream outage, recorded in the manifest. See `docs/knowledge-dump.md`

Empty `knowledge` and `config` databases need no dump: running the API migrations creates every base table and the `config` row with null watermarks, so the first knowledge update does a full fetch.

Migration workflow: see `.claude/rules/database-migrations.md`.

Production deployment: see `deployment/README.md`.

## License

AGPL-3.0. All contributions must be compatible with this license.

## Agent skills

### Issue tracker

GitHub Issues: cross-cutting work in `CodeClarityCE/codeclarity-dev`, single-area work in that submodule's repo. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one root `GLOSSARY.md` and `docs/adr/`. See `docs/agents/domain.md`.
