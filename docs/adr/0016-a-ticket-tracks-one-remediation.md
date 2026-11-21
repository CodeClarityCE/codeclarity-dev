# A ticket tracks one remediation, not one vulnerability

A ticket is the work for one remediation in one project, such as upgrading one top-level dependency, and lists every vulnerability instance that remediation resolves. Developers act on "upgrade X", and one upgrade often resolves several vulnerabilities, so one ticket per vulnerability left several tickets for a single pull request. Remediations are suggested, and the user creates a ticket from one in a click; tickets are never created automatically, and the existing auto-resolve still closes them once the current analysis no longer has their instances.

## Considered Options

- Keep one ticket per vulnerability and group them in the UI: no schema change, but assignment, due dates and the external issue would still be per vulnerability, so the duplicate work stays.
- Create tickets automatically for every remediation: nothing gets missed, but the board floods and teams stop reading it.

## Consequences

Tickets created before this change keep their single vulnerability and are treated as a remediation of it; they are not merged, because merging would lose their history, assignees and external links. A remediation can change as new vulnerabilities appear, so a ticket's list of instances grows or shrinks with each current analysis while its title and assignee stay.
