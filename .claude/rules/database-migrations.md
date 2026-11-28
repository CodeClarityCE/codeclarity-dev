---
paths:
  - "api/**"
---

# Database Migration Strategy

## Four Databases

API migrations (`api/src/migrations/<database>/`) are the only source of schema for all four. The Go services read and write data with Bun but only create databases, never tables.

- **codeclarity** - App data (analyses, projects, users, organizations)
- **knowledge** - Vulnerability, package and license data, plus per-source sync state (`knowledge_source_sync`)
- **config** - One row of knowledge source watermarks (`nvd_last`, `gcve_last`, `osv_last`, `kev_last`)
- **plugins** - Plugin metadata

## Running migrations

Migrations run one way, in the one-shot `migrate` Compose job: `src/scripts/migrate.ts` (compiled to `dist/scripts/migrate.js` in the production image). With no arguments it migrates codeclarity, knowledge, plugins and config in that order; named databases run in that same order. It connects straight to Postgres (`db:5432`), not pgbouncer, and when `PG_DB_ADMIN_USER` is set it connects as that admin and runs `SET ROLE` to each database's owning role.

- After the migrations, on every run and with or without the admin, it creates the package follower's `cc_follower` role when missing and applies its grants (`docs/database-pooling.md`); a migrate that cannot do that fails.
- `make up` runs the job, and the API and services wait for it to succeed. The API image's start command only serves requests.
- `make migrate` / `make migrate-<db>` run the same job (through the broker in the devcontainer). Nothing runs on the host.
- Dev does not use `synchronize` unless `DB_FORCE_SYNC=true`.

## Beta baselines

At beta 1 every alpha migration of each database was squashed into one baseline holding the schema of a fresh last alpha install (deployment `v0.0.32-alpha`, API `v0.0.57-alpha`; ADR 0018): `CreateCodeclarityBetaBaseline1796200000000`, `CreateKnowledgeBetaBaseline1796200000000`, `CreatePluginsBetaBaseline1796200000000` and `CreateConfigBetaBaseline1796200000000`. Each runs the `.sql` file next to it (`nest build` copies it into `dist/`) through `src/migrations/beta-baseline.ts`. Migrations written after that release (organization tokens, the js-patching removal) stay ordinary migrations on top.

- On an empty database the baseline builds that schema, with the knowledge source sync rows and the one config row a fresh install gets.
- On a database the last alpha migrated (its last migration is recorded) it changes nothing and deletes the squashed migrations' rows, so the migrations table matches a fresh install. A restored knowledge dump built at or after the last alpha counts as that.
- On any other database with tables (an older alpha, or a knowledge dump built before the last alpha) it throws, and the migrate job fails without changing that database. Reverting a baseline throws.
- Never edit a baseline: a schema change goes in a new migration.
- `api/test/migrations/beta-baseline.e2e-spec.ts` compares a fresh install from each baseline with `api/test/migrations/fixtures/last-alpha/<db>.schema.json` (recorded from the last alpha's migrations by `snapshot-last-alpha.ts`) and covers the takeover and the refusal. `<db>.migrations.sql` is the last alpha's migrations table, which `.cloud/scripts/tests/fresh-install/knowledge-dump-fixture.sh` also uses.
- The knowledge service's completeness gate expects the knowledge and config migrations listed in `backend/services/knowledge/src/validation/migrations.go`; keep it equal to `api/src/migrations`.

## Migration Workflow

1. Modify TypeORM entities in `api/src/`
2. Generate: `cd api && pnpm migration:generate src/migrations/MigrationName`
3. Migrations go into `api/src/migrations/`
4. Apply it with `make migrate` (or `make migrate-<db>`)
