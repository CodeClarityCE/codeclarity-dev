# CLAUDE.md

## Development Environment

- `make up` / `make down` - Start/stop all services
- `make build` - Build all Docker images
- `make logs` - View container logs
- `make stop-all` - Full container cleanup
- `make pull` - Pull latest images
- Access at <https://localhost:443>
- Default credentials: `john.doe@codeclarity.io` / `ThisIs4Str0ngP4ssW0rd?`
- IMPORTANT: Hot-reload is enabled. API, frontend, plugins, and services reload on save in containers. No need to restart containers or use `yarn dev`.

## Architecture Overview

- **Frontend**: Vue.js 3 + TypeScript + Tailwind CSS + Reka UI (port 443)
- **API**: NestJS + TypeScript + TypeORM
- **Backend**: Go microservices + Bun ORM
- **Databases**: PostgreSQL with 3 databases: `codeclarity` (app data), `knowledge` (vuln data), `config` (plugin metadata)
- **Message Queue**: RabbitMQ for async task processing
- **Go module paths**: `github.com/CodeClarityCE/plugin-*`, `github.com/CodeClarityCE/utility-types`
- **Message flow**: API Request -> Dispatcher -> Downloader (if git needed) -> Dispatcher -> Plugins (stage execution) -> Dispatcher (results)

## Testing

- **Frontend**: `cd frontend && yarn test:unit` (Vitest) / `yarn test:e2e` (Cypress)
- **API**: `cd api && yarn test` (Jest) / `yarn test:e2e`
- **Backend plugins**: `cd backend/plugins/<name> && go test ./tests/`
- **Linting**: `cd frontend && yarn lint` / `cd api && yarn lint`

## Database Commands

- `make knowledge-setup` - Initialize knowledge DB
- `make knowledge-update` - Update vulnerability data (needs NVD API key)
- `make download-dumps` / `make dump-database` / `make restore-database` - Dump management
- `make create-knowledge-indexes` - GIN indexes for JSONB lookups

### Migrations (API / TypeORM)

- `cd api && yarn migration:generate src/migrations/MigrationName` - Generate from entity changes
- `cd api && yarn migration:create src/migrations/MigrationName` - Create empty migration
- `cd api && yarn migration:run` / `migration:revert` / `migration:show`
- `cd api && ./generate-migrations.sh` - Generate initial migrations from dev schema

## Production Deployment

- `cd deployment && make update` - Full update with latest containers
- `cd deployment && make setup-database` - New install (restore dumps + run migrations)
- `cd deployment && make migrate-existing` - Existing DB (apply migrations only)

## License

AGPL-3.0. All contributions must be compatible with this license.
