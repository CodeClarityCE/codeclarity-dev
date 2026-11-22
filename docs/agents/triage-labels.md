# Triage Labels

The skills speak in terms of five canonical triage roles. This file maps those roles to the actual label strings used in this repo's issue tracker.

| Label in mattpocock/skills | Label in our tracker | Meaning                                  |
| -------------------------- | -------------------- | ---------------------------------------- |
| `needs-triage`             | `needs-triage`       | Maintainer needs to evaluate this issue  |
| `needs-info`               | `needs-info`         | Waiting on reporter for more information |
| `ready-for-agent`          | `ready-for-agent`    | Fully specified, ready for an AFK agent  |
| `ready-for-human`          | `ready-for-human`    | Requires human implementation            |
| `wontfix`                  | `wontfix`            | Will not be actioned                     |

When a skill mentions a role (e.g. "apply the AFK-ready triage label"), use the corresponding label string from this table.

Edit the "Label in our tracker" column to match whatever vocabulary you actually use.

## Severity and contributor labels

Every non-archived CodeClarityCE repo also has these. Wrong results (a missed or false finding, a wrong license) count as `P1`.

| Label              | Meaning                                                            |
| ------------------ | ------------------------------------------------------------------ |
| `P1`               | Urgent: crash, data loss, security hole or wrong results           |
| `P2`               | Important: a feature is broken or degraded and a workaround exists |
| `P3`               | Minor: cosmetic or low impact                                      |
| `good first issue` | Good for newcomers                                                 |
| `help wanted`      | Extra attention is needed                                          |

`scripts/sync-labels.sh` holds the names, colors and descriptions of all ten labels. `scripts/sync-labels.sh --check` lists what is missing or differs in each repo; without `--check` it creates or edits those labels and leaves every other label alone.
