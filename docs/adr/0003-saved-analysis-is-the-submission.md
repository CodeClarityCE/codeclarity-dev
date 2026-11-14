# A saved analysis is the submission; publishing is best-effort

An analysis is submitted once its row is committed. The RabbitMQ start message is published after commit on a best-effort basis: if publishing fails, the API logs a warning and still returns the analysis id, and the dispatcher's reaper re-drives the `requested` row (on startup, or once it has been stuck past `REAPER_STEP_TIMEOUT`). We accept a delayed start during a broker outage because recovery is already DB-driven (RabbitMQ has no durable volume in dev), and it means a caller such as the experiment runner can never lose track of an analysis it created.

## Considered Options

- Roll back on publish failure (delete the row and throw): leaves nothing behind in the common case, but if the message was in fact sent before the error, the dispatcher receives work for an analysis that no longer exists.
- Transactional outbox table with its own relay: exact delivery, but a second recovery mechanism beside the reaper doing the same job.
