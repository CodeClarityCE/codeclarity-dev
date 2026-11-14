# Published experiment results are frozen

ADR 0001 computes aggregates on read so a metric fix never needs a re-run, which also means a number cited in a paper could change silently. A finished experiment can therefore be explicitly published, a one-way step that stores its computed results under a metric version and blocks its deletion; unpublished experiments keep computing on read as in ADR 0001.

## Considered Options

- Keep computing on read and rely on exported files: nothing ties a cited number to the metric code that produced it, and the platform would later show a different value.
- Store aggregates for every experiment: gives up ADR 0001's free metric fixes while results are still being explored.
