# A results gate, read through the API, is the correctness test for analyzers

For a scanner the worst bug is a wrong result: a vulnerability, licence or package that silently appears or disappears. Unit tests in each plugin repo cannot catch that, because the result comes out of several plugins, the dispatcher and the knowledge database together. So the main correctness test runs every analyzer over a fixed set of fixture projects against one pinned knowledge dump, on a real instance, reads the findings through the API's results endpoints, and compares them with expected results checked into the umbrella repo. A PR that changes any finding fails until the expected results are updated in the same PR, so every change in what users see is reviewed.

## Considered Options

- Compare each plugin's raw output in its own repo: fast and runs on every plugin PR, but misses bugs between plugins and in the API, and ties the test to plugin internals.
- Measure precision and recall against the Accuracy benchmark only: tells us how good results are, not that a change moved them, and its adjudicated verdicts are too costly to grow quickly.

## Consequences

- The gate runs in the umbrella on pointer bumps and same-named-branch PRs, not on plugin-repo PRs, which keep their own fixture tests.
- A new knowledge dump means updating the pinned dump and the expected results in one reviewed change.
