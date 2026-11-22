# Monkey runs

Nightly seeded random-interaction Playwright runs on the golden-journey pages of a real instance. The monkey (`frontend/e2e/helpers/monkey.mts`) clicks, types and presses keys at random, picked by a seed, and fails on an uncaught error, an error report (`POST /api/logs`) or a 5xx response. It never clicks controls whose name says delete, remove, sign out, log out, leave or revoke, nor links to other sites or new tabs, and reopens the page when an action leaves it.

The pages are `MONKEY_PAGES` in `frontend/e2e/real-stack/monkey.journey.mts`, one test per page tagged `@monkey`, titled `monkey <page> seed`. They rely on the data the golden journeys leave: a `journey-*` project with results and an advisory, a ticket, an organisation.

The workflow is `.github/workflows/monkey.yml`: it builds the trimmed real stack at the submodule pointers, runs the golden journeys (a failing journey only warns), then `monkey.sh run`. A separate `report` job opens, comments on or closes the `ci-failure` issue `Monkey runs failing`.

## Files

- `monkey.sh`: `run`, `issue-body` and `report`; `monkey.sh` with no arguments prints the usage. `run` picks a seed unless `MONKEY_SEED` is set, prints it, writes it to `DIR/seed` and runs `frontend/.cloud/scripts/e2e-real-stack.sh URL DIR --grep @monkey` with it.

## Replaying a failure

The issue gives the seed and, for each failing page, its problems, the actions taken and the command that replays it. On a machine with Docker and a running stack that has the journeys' data:

```sh
MONKEY_SEED=<seed> MONKEY_STEPS=60 bash scripts/monkey/monkey.sh run https://localhost /tmp/monkey --grep "monkey results seed"
```

A replay repeats the same actions when the page shows the same controls; a stack with other data can lead it elsewhere. The Playwright trace of each failed page is in the run's `monkey` artifact (`npx playwright show-trace <dir>/trace.zip`). Against the agent dev stack, run the journey file directly from `frontend/`: `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium E2E_BASE_URL=https://localhost MONKEY_SEED=<seed> node_modules/.bin/playwright test --project=real-stack e2e/real-stack/monkey.journey.mts --grep "monkey results seed"`.

Once a case is fixed, add `{ page, seed, steps, found }` to `MONKEY_REGRESSIONS` in `monkey.journey.mts`, so every run replays it.
