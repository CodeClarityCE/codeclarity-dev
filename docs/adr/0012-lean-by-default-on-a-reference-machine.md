# Lean by default, sized for a reference machine

The production stack asked for 16 GB of memory because its sizing came from adding up per-service reservations, not from measurement; idle, the services use a fraction of that. We want an instance to run well on small hardware, so the default production stack is designed and tested for a reference machine, a Raspberry Pi 5 with 8 GB of memory and an SSD. Heavy parts that the Default Analyzer does not need (CodeQL, monitoring) are optional components an operator turns on with a Compose profile, and the memory limits of every default container together stay within a 6.5 GB budget, sized from measurements and enforced in CI on arm64. On small hardware, analyses may take longer, but the web UI stays responsive and nothing runs out of memory.

## Considered Options

- Keep today's default and ship a separate "small" override: two shapes to test and document, and the small one, used less, would break unnoticed.
- Size the default for a large server and document how to shrink it: the shape most operators start from would not fit small machines, and shrinking would be untested.
- A 4 GB reference machine: not ruled out, but deferred until the 8 GB baseline is measured.

## Consequences

- An operator who wants Grafana, Prometheus or CodeQL turns on the `monitoring` or `codeql` profile; upgrades turn monitoring off until they do, as the release notes say.
- Postgres ships tuned for 8 GB. Larger instances raise its settings and replica counts from a documented "Larger instances" example, which is not tested in CI.
- An analyzer that needs a component which is off, or a plugin that is down, is shown as unavailable and refused at submission, instead of waiting 24 hours to fail.
- The knowledge daemon stays on and must fit its share of the budget, at low CPU priority.
- CodeQL is x86_64 only and is not supported on arm64.
- The dev stack is unaffected.
