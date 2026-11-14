# Keep every knowledge source independent and retire records instead of deleting them

Every knowledge source stays an independent matcher, and each source match is stored even when another source wins for display, because we compare the quality of the sources against each other. Records a source stops asserting are retired with a reason and date rather than deleted, so as-of views stay reproducible and a vanished vulnerability instance can be explained.

## Considered Options

- OSV as the only authority for npm and Packagist, with NVD and GCVE as enrichment: more precise matching, but the sources could no longer be compared, since only one would produce matches.
- Keep only the winning source's match: less storage, but changing the display order would change every measurement.
- Hard-delete rejected, withdrawn or removed records: simpler queries, but history is lost and as-of analyses would differ from what was knowable at the time.

## Consequences

Product-name matching stays in the vulnerability pipeline despite its lower precision, so do not remove NVD or GCVE matching as a cleanup. Consumers must exclude retired records by default. Retirement applies to advisory records only: EPSS, CWE and license rows are reference data, so rows their source no longer publishes are deleted. Overlap between sources with the same origin is not corroboration, and comparisons must flag any source that was stale or failed at the time of the analysis.
