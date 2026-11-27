# Restart semantics and orphan recovery

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
- **Package import wait**: plugins that depend on an SBOM (license-finder, vuln-finder)
  start only once the package follower has recorded that SBOM's package import in the
  analysis config (`package_imports_done`, per language; ADR 0023). An analysis waiting
  on it, either `updating_db` or with a finished SBOM and no record, is recovered like a
  lost dispatch: the startup pass, or the interval pass once the wait exceeds
  `REAPER_STEP_TIMEOUT` (measured from `package_follower_started_on`, else the last step
  activity), re-sends the import to `sbom_packageFollower` from the stored SBOM. An SBOM
  with no packages, or one that is missing or unreadable, is recorded as imported at once.
  If `sbom_packageFollower` has had no consumer for `STALLED_PLUGIN_GRACE`, the waiting
  analysis fails with a reason naming the package follower. `RECOVERY_MAX_AGE` still
  retires any wait that never ends.
