---
paths:
  - "api/**"
---

# Database Migration Strategy

## Four Databases

API migrations (`api/src/migrations/<database>/`) are the only source of schema for all four. The Go services read and write data with Bun but only create databases, never tables.

- **codeclarity** - App data (analyses, projects, users, organizations)
- **knowledge** - Vulnerability, package and license data, plus per-source sync state (`knowledge_source_sync`)
- **config** - One row of knowledge source watermarks (`nvd_last`, `gcve_last`, `osv_last`)
- **plugins** - Plugin metadata

## Development vs Production

- **Development**: TypeORM `synchronize: true` auto-syncs schema from entities
- **Production**: Migrations only (`migrationsRun: true`, auto-applied on container startup)
- **Initial setup**: Restore the dumps in `deployment/dump/` then migrate, or migrate empty databases (see below)

## Bootstrapping knowledge and config from empty

The baselines `CreateKnowledgeBaseline1754600000000` and `CreateConfigBaseline1754600000000` sort before every other knowledge and config migration. On an empty database they create the tables of the 2025-05-27 dumps (`cwe`, `js_version`, `licenses`, `nvd`, `osv`, `package`; `config` plus its one row with null watermarks), and the later migrations build the rest from there. When any of those tables exists they do nothing, and reverting them does nothing, so restored and upgraded databases are unaffected. Run knowledge before config, as `run-migrations.ts` does: the source sync backfill then finds no config row and starts every watermark at null.

- New base tables still go in a new migration, not in a baseline.
- `api/test/migrations/knowledge-baseline.e2e-spec.ts` checks that an empty build matches the old dump restored and migrated (fixtures in `api/test/migrations/fixtures/`).

## Migration Workflow

1. Modify TypeORM entities in `api/src/`
2. Generate: `cd api && pnpm migration:generate src/migrations/MigrationName`
3. Migrations go into `api/src/migrations/`
4. Dev uses synchronize so migration is tested on next prod deploy

## Production Deployment

- **New install**: `cd deployment && make setup-database` (restore dumps + run migrations)
- **Existing DB**: `cd deployment && make migrate-existing` (migrations only, no restore)
- Use `migrate-existing` to avoid restore errors on populated databases
