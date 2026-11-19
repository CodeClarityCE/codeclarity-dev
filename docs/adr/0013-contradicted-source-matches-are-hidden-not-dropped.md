# Contradicted source matches are hidden by default, not dropped

A vulnerability instance whose every source match is contradicted by a source of a different source origin is hidden from default views, stats, the grade, notifications and experiment metrics, but every source match is still stored with its source verdict and can be shown with a filter. Only a different source origin can contradict, so NVD and GCVE (both derived from the CVE List) never contradict each other, and an unreviewed advisory with no package data is silence, not contradiction. A record retired by one source contradicts the other sources' matches for the same package. This extends ADR 0007: sources stay independent matchers, and the judgement is a layer on top of their matches.

## Considered Options

- Drop the NVD or GCVE match when OSV disagrees: simplest and gives the same default view, but source quality could no longer be compared, and a wrong OSV record would silently erase a real finding with nothing left to show the user.
- Mark contradicted instances but keep them visible and counted: no hidden data, but most false positives the platform reports today stay in the count and the grade, which is the problem being fixed.
- Let any second source contradict, whatever its origin: catches more false positives, but NVD and GCVE copy the same CVE List data, so letting one overrule the other is a coin toss rather than independent evidence.

## Consequences

Default counts drop when this ships, and experiment results computed before and after it are not comparable, so the experiment metric version is bumped and published results stay frozen under the old version. Every view that hides an instance must say how many it hid and why. Source verdicts are computed at analysis time against that analysis's knowledge, so an older analysis is not re-judged when a source later retires or amends a record; re-running it is how the user picks up the new judgement.
