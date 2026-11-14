# Experiments copy tidy rows instead of reading live results

When an experiment run's analysis finishes, the experiment copies a per-run summary row and one row per vulnerability instance into its own tables, and computes dataset-level aggregates from those tables on read. We accept the duplicated data because experiment analyses are ordinary platform analyses (they live in ordinary projects and can be deleted, re-run or garbage-collected), and an experiment's results must stay fixed regardless; aggregates are not stored so a metric fix never needs a re-run.

## Considered Options

- Read the live `result` JSON on every request: no duplication, but results silently change or break when analyses are deleted, and aggregation over hundreds of large JSON blobs is slow.
- Store precomputed aggregates only: cheap to read, but stale the moment metric code changes, and nothing to re-aggregate from.
