# CodeClarity

CodeClarity analyses software projects for vulnerable and non-compliant dependencies, one project at a time, and runs experiments that measure exposure across whole cohorts of projects.

## Language

### Analysis

**Analysis**:
One run of an analyzer over one project at one ref (branch, tag or commit).
_Avoid_: Scan (except informally), job

**Analyzer**:
A named, ordered set of plugin stages that an analysis executes.
_Avoid_: Pipeline, workflow

**Submission**:
Handing an analysis to the platform to run. An analysis counts as submitted once it is recorded, even if the platform has not picked it up yet; it is then picked up later.
_Avoid_: Dispatch (the dispatcher's own step), enqueue

### Experiments

**Dataset**:
A named, immutable cohort of repositories ranked by GitHub stars, frozen once built so the same cohort can be referred to later.
_Avoid_: Sample, corpus, study

**Dataset entry**:
One repository of a dataset, at its star rank.
_Avoid_: Sample row, candidate

**Experiment**:
A named, one-shot run of one analyzer over every snapshot of every entry of one dataset, whose configuration (including the snapshot grid) is frozen at creation. Running again later means creating a new experiment.
_Avoid_: Study, campaign, batch

**Snapshot grid**:
The calendar dates an experiment looks back over (a fixed interval and count, shared by every entry), plus HEAD as the last snapshot.
_Avoid_: Timeline, history

**Snapshot**:
One dataset entry at one grid date, pinned to the last default-branch commit on or before that date. Two snapshots that pin the same commit share one analysis. A snapshot from before the entry had a lockfile is observed as empty, not a gap.
_Avoid_: Point, timepoint, version

**Experiment run**:
The outcome of an experiment for one snapshot: the analysis it produced (if any), and whether it ended done, failed or skipped, and why.
_Avoid_: Manifest row, job, attempt

**Vulnerability instance**:
One (vulnerability, affected dependency, workspace) finding within one analysis. A project's load is its count of vulnerability instances.
_Avoid_: Vulnerability (when counting), finding

**Exposure**:
The span during which one (dataset entry, vulnerability, affected package) is present, in any workspace at any vulnerable version, across consecutive snapshots. A bump that stays within vulnerable versions continues the exposure; a failed snapshot leaves a gap without ending it; a return after a fix starts a new exposure (a reintroduction). An exposure still present at HEAD is open.
_Avoid_: Vulnerability lifetime, residence (that is a measure of an exposure)

**Fix**:
The event that ends an exposure, dated to the commit after which no vulnerable version of the package remains.
_Avoid_: Remediation event, patch

**Introduction**:
The event that starts an exposure, dated to the commit at which a vulnerable version of the package first appears. An exposure already present at the first grid date has no introduction, only a start before the grid.
_Avoid_: Onset, adoption

**Dating precision**:
How exactly a fix or introduction is dated: to a commit (a fix probe located it) or to a snapshot interval (probing failed, was ambiguous or ran out of budget).
_Avoid_: Resolution (taken by dependency resolution)

**Fix kind**:
How a fix happened: upgraded (the package still resolves, at safe versions), removed directly (the project dropped it) or removed transitively (it left because a parent package changed).
_Avoid_: Fix type

**Fix probe**:
An SBOM-only analysis of a commit between two snapshots, used to locate the commit of a fix. A fix probe is not an experiment run.
_Avoid_: Bisect run, mining

**Analysis budget**:
An optional cap on the analyses one experiment may submit. Once spent, no further fix probes run; snapshots are never cut.
_Avoid_: Quota, limit

**Hindsight view**:
Reading a snapshot with every vulnerability known today, so it shows exposure that was latent at the time.
_Avoid_: Current view

**As-of view**:
Reading a snapshot with only the vulnerabilities published on or before its grid date, approximating what could have been known then.
_Avoid_: Historical knowledge, time travel

**Published results**:
The results of a finished experiment frozen under a metric version so they can be cited. Corrected metrics produce a new version; earlier versions remain.
_Avoid_: Release, final results

**Figure**:
A named, saved definition of one visual over one experiment's results: what it measures, how it is grouped and filtered, and how it is styled. It is the definition, not the image exported from it.
_Avoid_: Chart, plot, graph (for the saved definition)
