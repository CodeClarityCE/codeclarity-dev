# Plugins that depend on an SBOM wait for its recorded package import

license-finder and vuln-finder read the package and version rows that the package follower imports for an SBOM. They used to depend only on the SBOM plugins, and what held them back was that the follower usually set the analysis to `updating_db` before the dispatcher handled the SBOM's completion. Nothing guaranteed that order, so they could run on rows not yet written and report unknown licences or miss vulnerabilities, with no error (#403).

Now the follower records each finished package import in the analysis config, under `package_imports_done` with one entry per language. The dispatcher counts an SBOM step as a satisfied dependency only once its language's entry is there. The follower's existing message to `plugins_dispatcher` is what wakes the dispatcher. The check lives in the dependency resolver, so it holds whichever stage the dependent plugins sit in, and the analyzer graph and the plugins are unchanged.

## Considered Options

- Make the follower a declared dependency of the finders in the analyzer graph: the order would show in each analyzer, but the follower is a service with no step, so it would need a step type of its own, an API change and a migration of every analyzer.
- Hold the stage while the analysis is `updating_db`: smallest change, but it is the same race, since the SBOM's completion can still be handled before the follower sets the status.
- Have the dispatcher send the import itself when the SBOM stage ends: the order would sit in one place, but the import messages from js-sbom and php-sbom would have to be removed, which touches two more repos for the same guarantee.

## Consequences

- A waiting analysis has to be recoverable. The reaper re-sends the import from the stored SBOM after `REAPER_STEP_TIMEOUT` or on startup, records an SBOM with nothing to import as done, and fails the analysis when the follower has had no consumer for `STALLED_PLUGIN_GRACE` (`docs/restart-recovery.md`).
- Re-sends are bounded. After `REAPER_IMPORT_RESENDS` (default 3) interval re-sends without the record appearing, counted in the analysis config so a restart keeps the count, the reaper fails the analysis with a reason naming the package follower. A follower that consumes the import but never writes the record, because its UPDATE failed or it predates the record, then fails the analysis after about `REAPER_IMPORT_RESENDS + 1` times `REAPER_STEP_TIMEOUT` instead of re-sending until `RECOVERY_MAX_AGE`. Startup re-sends replace a message lost with the queue, so they do not count, and restarts alone never fail an analysis.
- The dispatcher has to be released no earlier than a follower that writes the record. An older follower never writes it, so every analysis would fail once its re-sends run out.
- A follower import that fails is still recorded as done, as before, so the finders run on whatever rows exist. Retrying a failed import is a separate decision.
