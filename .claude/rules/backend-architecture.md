# Backend Architecture

## Core Services (`backend/services/`)

- **dispatcher** - Central message orchestrator, coordinates analysis workflows
- **downloader** - Downloads source code from Git repositories
- **knowledge** - Manages vulnerability databases (NVD, OSV, EPSS, CWE, GCVE)
- **notifier** - Handles notifications
- **packageFollower** - Tracks package updates

## Analysis Plugins (`backend/plugins/`)

- **js-sbom** - JavaScript SBOM generation
- **php-sbom** - PHP SBOM generation (Composer)
- **vuln-finder** - Multi-language vulnerability detection (JS & PHP)
- **license-finder** - Multi-language license compliance (JS & PHP)
- **js-patching** - Vulnerability patching recommendations
- **codeql** - Static analysis using CodeQL

## Plugin System

- Each plugin is a standalone Go binary with `main.go`
- Plugins communicate via RabbitMQ queues (`dispatcher_<plugin-name>`)
- Configuration via `config.json` files
- Results stored in PostgreSQL with UUID keys
- Stage-based execution with dependency management
- Build/run: `cd backend/plugins/<name> && make build && make up`

## Key Code Patterns

- **Knowledge DB types**: `backend/utilities/types/knowledge_db/` (osv.go, nvd.go, gcve.go)
- **Mirror pattern**: `backend/services/knowledge/src/mirrors/<source>/main.go` with `Update(db, configDB)` entry point
- **Persistence**: `backend/services/knowledge/src/utilities/pgsql/<source>.go` with `BatchUpdate`, `GetUUIDs`, `BatchInsert`
- **Vuln-finder pipeline**: Repository (query DB) -> Matcher (normalize versions) -> Match (range/exact/universal) -> Clean (merge sources) -> ConflictResolver -> Severity -> Output
- **JSONB queries**: Use `@>` operator with GIN index; parameterize via `json.Marshal` to avoid SQL injection
