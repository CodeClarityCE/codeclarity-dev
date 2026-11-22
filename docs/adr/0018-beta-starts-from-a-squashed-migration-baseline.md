# Beta starts from a squashed migration baseline that only the last alpha upgrades to

Beta promises that an instance's data survives every upgrade. Proving that for every alpha release would mean testing dozens of migration paths written before anyone made that promise, so at beta 1 the API migrations of each database are squashed into one baseline whose schema matches the last alpha release. Only an instance on the last alpha upgrades to beta; from beta on, every release is tested by installing release N-1, adding data through the golden journeys, upgrading to N and running the journeys again.

## Considered Options

- Support an upgrade from every alpha release: the promise users would most like, but every old path would need a test, and those migrations were never written to be safe.
- Make beta a clean break with an export and import, or a documented reset: simplest for us, but every alpha operator loses data, which is the opposite of what beta promises.

## Consequences

- An operator on an older alpha first upgrades to the last alpha, then to beta; the release notes say so.
- The upgrade from N-1 is a beta criterion and a required check from beta 1 onwards.
