# Fix probes are SBOM-only analyses, not lockfile-history mining

To date a fix to a commit, the experiment runner submits ordinary analyses with an SBOM-only analyzer at candidate commits between the last snapshot where an exposure was present and the first where it was gone, and narrows down by halving over the lockfile-touching commits. Results are cached per (entry, commit), and one probe can date several fixes. We accept the extra analyses because js-sbom is the only lockfile parser whose accuracy we have verified, and a second parser would disagree with the snapshots it is meant to explain.

## Considered Options

- Port the old harness's lockfile-history mining (fetch and parse root lockfile blobs per commit): far fewer analyses, but needs a lockfile parser outside js-sbom, which would reintroduce the format bugs fixed in plugin-sbom-javascript#24, and it only saw the root lockfile.
- Snapshot resolution only (no probes): free, but a fix is then only known to within one grid interval.
