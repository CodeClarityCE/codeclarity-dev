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
