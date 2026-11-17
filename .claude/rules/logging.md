# Logging Guidelines

## Logger Services (use these, never console.log/console.error)

- **Go services**: `logrus` with structured JSON fields
- **API (NestJS)**: `CodeClarityLogger.forService('service-name')`
- **Frontend (Vue.js)**: `logger` from `@/utils/logger` (`error`, `warn`, `info`, `debug`). Only `error` and `warn` reach the server: they are sent as error reports to `POST /api/logs` while a user is signed in, and the API writes them to Loki with `source: frontend`. `info` and `debug` print to the console in dev builds only. `installLogger(app)` in `main.ts` reports uncaught component errors and unhandled promise rejections. Context keys outside `route`, `component`, `organizationId`, `projectId`, `analysisId` and `stack` are dropped. Error reports are for operators and are not the audit log (see `GLOSSARY.md`)

## Rules

- Always include context fields: userId, projectId, analysisId where available
- Never log sensitive data (passwords, API keys, tokens)
- Use appropriate log levels: error, warn, info, debug

## Monitoring URLs (dev)

- Grafana dashboards: <http://localhost:3001> (admin/admin)
- Alloy collector UI: <http://localhost:12345>
- Loki API: <http://localhost:3100>
- Enable debug logs: `LOG_LEVEL=DEBUG` environment variable
