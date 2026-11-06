# Experiment orchestration lives in the API

Experiments are driven by a lease-based background runner in the NestJS API (the pattern `dataset-build.service.ts` established), not by a Go service beside the dispatcher. An experiment is a sequence of ordinary analysis submissions plus GitHub lookups (pinning each entry's HEAD) and result copying, all of which the API already does; the dispatcher's job stays one analysis at a time, unaware that experiments exist. A global in-flight cap keeps the runner from flooding the downloader.

## Consequences

The runner reads analysis status from the database rather than consuming queue messages, so it survives `make down && make up` the same way the reaper does: on restart it re-takes its lease and resumes from the DB state.
