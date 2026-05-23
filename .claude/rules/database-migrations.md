# Database Migration Strategy

## Three Databases

- **codeclarity** - App data (analyses, projects, users, organizations) - managed by TypeORM
- **knowledge** - Vulnerability and package databases - managed by Bun ORM (Go)
- **config** - Configuration and plugin metadata - managed by TypeORM

## Development vs Production

- **Development**: TypeORM `synchronize: true` auto-syncs schema from entities
- **Production**: Migrations only (`migrationsRun: true`, auto-applied on container startup)
- **Initial setup**: Schema initialized from dump files in `deployment/dump/`

## Migration Workflow

1. Modify TypeORM entities in `api/src/`
2. Generate: `cd api && pnpm migration:generate src/migrations/MigrationName`
3. Migrations go into `api/src/migrations/`
4. Dev uses synchronize so migration is tested on next prod deploy

## Production Deployment

- **New install**: `cd deployment && make setup-database` (restore dumps + run migrations)
- **Existing DB**: `cd deployment && make migrate-existing` (migrations only, no restore)
- Use `migrate-existing` to avoid restore errors on populated databases
