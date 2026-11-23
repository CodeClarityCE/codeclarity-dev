# No telemetry; operators attach a support bundle to bug reports

Self-hosted instances never send data to us. Our users are security teams, and an instance that calls home without being asked would cost more trust than its crash reports are worth. When an operator reports a bug instead, they run one command that writes a support bundle (component versions, configuration with secrets redacted, recent error logs and error reports) into a file they look over and attach to the issue.

## Considered Options

- Opt-in telemetry: still means hosting a collector, writing a privacy policy and answering the question in every security review, for the few operators who would turn it on.
- An error tracking service such as Sentry, set up by each operator: possible later as an optional component, but not something a bug report can rely on.

## Consequences

- We only hear about the bugs operators report, so the golden journeys, the results gate and the nightly fuzz and monkey runs carry more of the job of finding bugs.
- The bug report template asks for the bundle.
