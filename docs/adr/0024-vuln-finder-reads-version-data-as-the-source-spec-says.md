# The vulnerability finder reads version data as each source's own spec says

When a record's version data is short or odd, the vulnerability finder reads it the way that source's schema defines it, and where the schema leaves room it picks the reading that keeps a possible finding visible. So an OSV SEMVER or ECOSYSTEM range whose interval opens at `introduced: "0"` and is never closed affects every version (the [OSV schema](https://ossf.github.io/osv-schema/) says `"0"` sorts before any other version, and its "Unfixed vulnerability example" reads such a range as "every possible version is affected"), and a GCVE (CVE JSON 5) affected entry with `defaultStatus: "affected"` affects every version its `versions` list does not cover (the [CVE schema](https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json) defines `defaultStatus` as "the default status for versions that are not otherwise listed"), so no list at all means every version. Such a match is an **all-versions match** (see `GLOSSARY.md`): its source match carries the universal evidence and `universal` affected versions, so it can be told apart from a match on a bounded range.

## Considered Options

- Treat these shapes as no package data: no new false positives, but the matcher would silently miss unfixed advisories and every malicious package advisory whose record lists no versions, which is most of them.
- Read GHSA's `database_specific.last_known_affected_version_range` (such as `< 8.3`) as an upper bound on an unfixed OSV range: more precise for those records, but it is a database-specific field, not the OSV schema, and it says the last version known to be affected, not that later ones are fixed. Left as a follow-up for a maintainer to decide.

## Consequences

- A GIT range is skipped: its events are commit hashes, which say nothing about package versions.
- A closing event that cannot be read (like `fixed: "unknown"`) is not "never closed", so it stays no package data.
- A GCVE default is not applied when an `unaffected` entry cannot be read or an entry has `unknown` status, since the matcher cannot tell which versions the default covers. Versions listed `unaffected` under the default are version excluded.
- The UI shows the affected versions of an all-versions match as "all versions" but has no badge for it on the finding itself; that is a follow-up.
