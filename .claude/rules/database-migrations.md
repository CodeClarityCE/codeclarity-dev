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

- `make up` runs the job, and the API and services wait for it to succeed. The API image's start command only serves requests.
- `make migrate` / `make migrate-<db>` run the same job (through the broker in the devcontainer). Nothing runs on the host.
- Dev does not use `synchronize` unless `DB_FORCE_SYNC=true`.

## Bootstrapping from empty

The baselines `CreateCodeclarityBaseline1754640000000`, `CreateKnowledgeBaseline1754600000000` and `CreateConfigBaseline1754600000000` sort before every other migration of their database. On an empty database they create the tables of the 2025-05-27 dumps (codeclarity: `user`, `organization`, `analyzer`, `project`, `analysis` and the rest of the app tables; knowledge: `cwe`, `js_version`, `licenses`, `nvd`, `osv`, `package`; `config` plus its one row with null watermarks), and the later migrations build the rest from there. When any of those tables exists they do nothing, and reverting them does nothing, so restored and upgraded databases are unaffected. Run knowledge before config, as the migrate job does: the source sync backfill then finds no config row and starts every watermark at null.

- New base tables still go in a new migration, not in a baseline.
- `api/test/migrations/knowledge-baseline.e2e-spec.ts` and `codeclarity-baseline.e2e-spec.ts` check that an empty build matches the old dump restored and migrated (fixtures in `api/test/migrations/fixtures/`).

## Migration Workflow

1. Modify TypeORM entities in `api/src/`
2. Generate: `cd api && pnpm migration:generate src/migrations/MigrationName`
3. Migrations go into `api/src/migrations/`
4. Apply it with `make migrate` (or `make migrate-<db>`)
