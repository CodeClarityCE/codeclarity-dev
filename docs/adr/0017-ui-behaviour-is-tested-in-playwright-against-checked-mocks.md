# UI behaviour is tested in Playwright against checked mocks; the real stack runs outside the PR gate

What a user sees on a page is tested in Playwright, against API mocks whose shapes are checked against responses captured from a real API. Vitest is kept for logic (utils, stores, composables, repositories) and mocks only HTTP. jsdom unit tests of rendering kept passing while real pages showed missing pointer cursors and words run together, and the old global mocks of stores and the router meant many unit tests checked their own mocks. Frontend PRs gate on the mocked suite in chromium and one mobile viewport. A few journeys against a trimmed real stack run in the umbrella repo's CI on every pull request and push to `main` and `develop` (in practice submodule pointer bumps) and nightly, because bringing up the stack takes minutes that every frontend PR would otherwise pay.

## Considered Options

- Gate every frontend PR on the real stack: catches mock drift at once, but adds an umbrella checkout and several minutes of image builds and setup jobs to each PR.
- Run the real stack nightly only: cheapest, but a broken pairing of submodules could reach `develop` and stay there for a day.
- Keep UI behaviour in jsdom unit tests: fast, but jsdom computes no layout, cursor or colour contrast, so the bugs users report stay invisible.

## Consequences

A mock can drift from the API between pointer bumps; the contract captures and the umbrella job are what catch it, so captures must be refreshed when an endpoint's shape changes. Firefox and webkit run only nightly or by hand.
