# Fixtures are stored renamed so GitHub does not scan them

Test and benchmark fixtures are deliberately vulnerable inputs: lockfiles and manifests pinned to old releases so an analysis has something to find. GitHub's dependency graph reads every file with a real manifest or lockfile name, so each fixture raised Dependabot alerts that looked like risk in our own code and buried the alerts that were. Every manifest and lockfile inside a fixture folder (`package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `composer.json`, `composer.lock`) is therefore stored with a `.fixture` suffix. The code that feeds a fixture to an analysis, a plugin's test helper or the umbrella's reference-baseline and benchmark scripts, copies it and restores the real names, so the analysis runs exactly as before. Manifests are renamed too, because a manifest alone also raises alerts. Each repo that stores fixtures has a guard test, run in its own CI, that fails on a real-named file in its fixture folders.

## Considered Options

- Dependabot `exclude-paths`: documented as applying to version updates only, with no documented effect on alerts or the dependency graph.
- Dismissing the fixture alerts once: every new advisory against a pinned package opens a new alert, so the dismissals never end.
- Leaving the alerts open: real alerts get lost among the fixture ones, which hides real risk.

## Consequences

- A new fixture is committed with `.fixture` names from the start; the guard test names any file that is not and the name it should have.
- Reading a fixture by hand means remembering the suffix, and editors no longer recognise the file type by name.
- Alerts already open on fixtures close only once the rename reaches the default branch; until then they are dismissed as test fixtures.
