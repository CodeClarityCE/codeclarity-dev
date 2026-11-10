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
A named, one-shot run of one analyzer over every entry of one dataset, whose configuration is frozen at creation. Running again later means creating a new experiment.
_Avoid_: Study, campaign, batch

**Experiment run**:
The outcome of an experiment for one dataset entry: the analysis it produced (if any), and whether it ended done, failed or skipped, and why.
_Avoid_: Manifest row, job, attempt

**Vulnerability instance**:
One (vulnerability, affected dependency, workspace) finding within one analysis. A project's load is its count of vulnerability instances.
_Avoid_: Vulnerability (when counting), finding

### Knowledge

**Knowledge source**:
An external body of vulnerability or weakness data mirrored separately into the knowledge database, such as OSV, NVD or GCVE.
_Avoid_: Dataset (that is a repository cohort), feed

**Source origin**:
The upstream authority a knowledge source's data derives from. Knowledge sources sharing an origin do not corroborate each other.
_Avoid_: Provider

**Source watermark**:
The point up to which a knowledge source is known to be completely synchronized.
_Avoid_: Cursor, last update

**Canonical vulnerability**:
The single identity of a vulnerability, linking every alias it has across knowledge sources.
_Avoid_: CVE (when the identity may have none), vuln ID

**Source match**:
One knowledge source's claim that a canonical vulnerability affects a dependency version, kept whether or not that source is chosen for display.
_Avoid_: Conflict, pair

**Winning source**:
The knowledge source whose data is displayed for a vulnerability instance when several source matches exist.
_Avoid_: Primary source, truth

**Retired record**:
A knowledge record its source no longer asserts because it was rejected, withdrawn or removed, kept with the reason and date.
_Avoid_: Deleted record

**Malicious package advisory**:
A statement that a package or version is intentionally harmful, as opposed to carrying a vulnerability.
_Avoid_: Vulnerability, MAL

**Knowledge dump**:
The published `knowledge` and `config` database files every new install restores, made only after the completeness gate passes.
_Avoid_: Snapshot (that is a dated restore), backup

**Dump manifest**:
The file next to a knowledge dump that records what it holds and the SHA-256 of every file a restore must verify.
_Avoid_: Metadata, index
