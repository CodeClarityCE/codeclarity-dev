# Logging Guidelines

## Logger Services (use these, never console.log/console.error)

- **Go services**: `logrus` with structured JSON fields
- **API (NestJS)**: `CodeClarityLogger.forService('service-name')`
- **Frontend (Vue.js)**: `FrontendLogger` - errors auto-sent to backend via `/api/logs`

## Rules

- Always include context fields: userId, projectId, analysisId where available
- Never log sensitive data (passwords, API keys, tokens)
- Use appropriate log levels: error, warn, info, debug

## Monitoring URLs (dev)

- Grafana dashboards: <http://localhost:3001> (admin/admin)
- Alloy collector UI: <http://localhost:12345>
- Loki API: <http://localhost:3100>
- Enable debug logs: `LOG_LEVEL=DEBUG` environment variable
