# Testing the first release through GitHub Actions

Run this once per repo, when moving its releases from Jenkins to Actions (spec #95, ADR 0009). Until a repo passes it, Jenkins stays its releaser and `CI_RELEASE` stays off.

Go library repos (the utilities) have no image: skip the image and attestation checks for them.

Set these for the repo under test:

```bash
REPO=api                      # GitHub repo name, such as api or plugin-sbom-javascript
IMAGE=codeclarityce/api       # package.json name, or config.json image_name
TAG=v0.0.52-alpha             # the version the release PR bumps to
DOCKER_TAG=${TAG#v}           # Docker tags drop the leading v
```

## Before

- [ ] The repo's caller (`.github/workflows/ci.yml`) is on `main` and its `ci` check is green on `develop`.
- [ ] The `release` environment exists with `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`, limited to `main`:

  ```bash
  gh api repos/CodeClarityCE/$REPO/environments/release --jq '.deployment_branch_policy'
  gh secret list -R CodeClarityCE/$REPO -e release
  ```

  If not, add the repo to `IMAGE_REPOS` in `scripts/setup-github-actions-org.sh` and re-run it.

## Switch the releaser

Do both steps together, so Jenkins and Actions never race on the same tag:

- [ ] Disable the repo's Jenkins job (Jenkins UI: the job's page, **Disable Project**).
- [ ] Turn on the Actions release jobs:

  ```bash
  gh variable set CI_RELEASE -R CodeClarityCE/$REPO --body true
  ```

## Release

- [ ] Open a release PR `develop` -> `main` that bumps the version file (`config.json` or `package.json`). The `version` job summary names the old and new version, the image tags and whether it is a prerelease.
- [ ] Merge it, and only it: GitHub keeps one pending run per concurrency group, so a second push to `main` while this run is queued can drop it. If the run never appears, re-run it from the Actions tab.
- [ ] Watch the main run: `gh run watch -R CodeClarityCE/$REPO $(gh run list -R CodeClarityCE/$REPO -b main -w CI -L 1 --json databaseId -q '.[0].databaseId')`

## Verify

- [ ] The manifest list holds both architectures:

  ```bash
  docker buildx imagetools inspect $IMAGE:$DOCKER_TAG
  ```

  Expect `linux/amd64` and `linux/arm64` (plus their attestation manifests). `latest` has the same digest:

  ```bash
  docker buildx imagetools inspect $IMAGE:latest --format '{{json .Manifest}}' | jq -r .digest
  ```

- [ ] The build provenance attestation verifies:

  ```bash
  gh attestation verify oci://index.docker.io/$IMAGE:$DOCKER_TAG -R CodeClarityCE/$REPO \
    --signer-repo CodeClarityCE/.github
  ```

- [ ] The tag points at the merged commit:

  ```bash
  gh api repos/CodeClarityCE/$REPO/git/ref/tags/$TAG --jq .object.sha
  gh pr view <release PR number> -R CodeClarityCE/$REPO --json mergeCommit -q .mergeCommit.oid
  ```

  Both print the same SHA (a lightweight tag points at the commit itself).

- [ ] The release is a prerelease for an alpha or beta version, with generated notes:

  ```bash
  gh release view $TAG -R CodeClarityCE/$REPO --json isPrerelease,targetCommitish,body
  ```

## Re-run without a bump

- [ ] Push a commit to `main` without bumping the version (or re-run the main run). The run summary says "Release `<tag>` already exists"; the push, merge and release jobs are skipped, and the digest from `docker buildx imagetools inspect` and the release are unchanged.

## After

- [ ] Fast-forward `develop` onto `main`.
- [ ] `scripts/release-all.sh --dry-run` now lists the repo with releaser `actions`.
- [ ] Once a repo has passed, its Jenkinsfile can be deleted in a later PR.

## Rolling back

Turn Actions releases off and re-enable the Jenkins job, again together:

```bash
gh variable delete CI_RELEASE -R CodeClarityCE/$REPO
```
