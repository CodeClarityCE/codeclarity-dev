# The scheduler creates scheduled analyses in the database, not through the API

At each due time of a scheduled analysis, the scheduler service inserts the new analysis into the `codeclarity` database itself and publishes the usual `api_request` message. It does not call the API. Its HTTP call to an `execute` route never worked: the scheduler had no credential, and the route it called let any signed-in user re-run any analysis. A service credential was the alternative, but the scheduler already reads and updates analysis rows, and plugins already insert rows from Go, so writing directly needs no new way to authenticate.

## Considered Options

- A scheduler-to-API service credential and a route that accepts only it: keeps the copy logic in one place, but adds a credential that spans every organization and has to be issued, rotated and scoped.

## Consequences

- The fields copied into a new analysis are defined in Go, against a table whose schema the API migrations own. A new `Analysis` column must be handled in the scheduler too.
- The API has no route that creates an analysis on the scheduler's behalf; the `execute` route is removed.
