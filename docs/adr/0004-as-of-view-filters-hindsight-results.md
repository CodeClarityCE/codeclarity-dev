# The as-of view filters hindsight results instead of replaying the knowledge DB

Each snapshot is analysed once, against the knowledge DB as it is today (the hindsight view). The as-of view is derived on read by dropping vulnerability instances whose advisory was published after the snapshot's grid date. We accept that this is an approximation: an advisory later withdrawn, re-scored or with a widened affected range shows in its current form, not as it read on the grid date. Pre-disclosure residence time needs the hindsight view anyway, so one analysis serves both.

## Considered Options

- Replay the knowledge DB as of each grid date (the old harness's `knowledge_asof` match-time cutoff): closer to what was knowable, but needs a cutoff threaded through vulnerability matching and doubles the analyses if both views are wanted.
- Hindsight only: simplest, but cannot answer what a project could have known at the time.
