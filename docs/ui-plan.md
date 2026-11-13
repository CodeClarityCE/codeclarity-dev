# Platform UI/UX plan

Make the platform look and feel like www.codeclarity.io, consolidate a UI that has grown two of everything, and put the research flow first. The decision and its rejected alternatives are in [ADR 0008](adr/0008-platform-takes-identity-from-landing-page.md).

## Principles

- **Identity comes from the landing page:** colour, button shape, accents, voice. The platform keeps its own choices only for density, state colours, the dark theme, and keyboard and focus behaviour.
- **Researchers come first.** The Dataset and Experiment flow gets design priority. Projects and analysis results come second and must not regress.
- **WCAG 2.2 AA** is an acceptance criterion for every UI change. Colour is never the only signal.
- **Desktop only:** viewports 1024px and wider, designed for 1280 to 1920px.
- **Keep the stack** (Vue 3, Tailwind v4, Reka UI, shadcn-vue). Reduce dependencies by deleting duplicates, not by switching.
- **Personality:** the owl and green-highlighted words belong in titles, empty states and onboarding. Data views stay calm and respect `prefers-reduced-motion`.

## Current state (audit, November 2026)

The counts below cover the 367 `.vue` files under `frontend/src`.

| Area          | Finding                                                                                                                                                                                                                                                                                       |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tokens        | shadcn variables in `src/assets/main.css` already set `--primary` to `#1dce79`, but screens bypass them: `bg-theme-primary` appears 137 times vs `bg-primary` 12, alongside 2,842 raw Tailwind palette classes, 434 hex literals and 247 inline `style` attributes. `--destructive` is black. |
| Dark mode     | A `.dark` variable block exists but nothing toggles it. 3 `dark:` usages in total.                                                                                                                                                                                                            |
| Typography    | Lato applied through an inline style on `<body>`, Roboto used ad hoc, 8 different monospace stacks, no font token.                                                                                                                                                                            |
| Components    | Two card systems, two modal systems, three table approaches, two pagination components, two form-field APIs, two toast libraries (`vue-toast-notification`, `vue-sonner`), seven loaders next to shadcn `Skeleton`. 40 of 55 `<style>` blocks are SCSS.                                       |
| Icons         | 928 Iconify icons from 22 sets (mostly Solar and tabler); Lucide inside shadcn.                                                                                                                                                                                                               |
| Charts        | Two d3 generations: generic charts in `base_components/data-display/charts` and the newer Experiment charts in `experiments/charts` (export, captions, table fallback).                                                                                                                       |
| Shell         | 7-item top nav, hidden below 768px.                                                                                                                                                                                                                                                           |
| Accessibility | Focus rings only inside shadcn components, 36 `aria-*` attributes, 7 `<img>` without `alt`. axe-core is installed; Percy is configured but takes no snapshots.                                                                                                                                |
| Brand drift   | `index.html` tile colour `#008491`; it references a `/site.webmanifest` that does not exist.                                                                                                                                                                                                  |

## Landing page reference values

| Role                                    | Value                                                                                               |
| --------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Brand green                             | `#1dce79`, with link hover `#17a561` and button hover `#3fd58d`                                     |
| Green subtle background / border / text | `#d2f5e4` / `#a5ebc9` / `#0c5230`                                                                   |
| Dark surfaces                           | `#111`, code surface `#121315`                                                                      |
| Text / border                           | `#212529` / `#dee2e6`                                                                               |
| Danger                                  | `#dc3545`                                                                                           |
| Radius                                  | cards 0.75rem, buttons 1.25rem                                                                      |
| Shadows                                 | `0 2px 8px rgba(0,0,0,.06)`, `0 8px 24px rgba(0,0,0,.1)`; the primary button shadow is tinted green |
| Motion                                  | 150ms ease-in-out by default; the primary CTA arrow slides on hover                                 |
| Signature                               | key words in headings highlighted in brand green; a green bar marks the active nav item             |

## Phase 1: one design system, research first

Each step below is one issue. A step is done when its files are off the lint allowlist, its Playwright e2e spec passes axe (WCAG 2.2 AA) and keyboard checks, and its screenshot baselines at 1280 and 1920 are approved in review.

### Foundation

1. **Tokens.** Rewrite `main.css` so that every colour, radius and shadow is a semantic token, with light and dark values, using the reference values above.
   - `--destructive` becomes `#dc3545`.
   - Inputs and table controls use a smaller radius than buttons (the density exception).
   - Remove the `theme-*` set with a codemod onto the new tokens.
   - Fix the tile colour and the manifest reference.
2. **Typography.** Make Lato the only `--font-sans`, drop Roboto, add a single `--font-mono`, remove the inline `<body>` style, and add a heading utility for green emphasis.
3. **State colours** (`ready-for-human`: needs the values chosen).
   - An AA-contrast severity ramp (critical, high, medium, low, none) that never uses brand green, always shown with a label or icon.
   - Small semantic sets for snapshot outcome (done, failed, skipped), licence status and patch status.
4. **Icons.** Migrate every icon to Lucide. Keep only `simple-icons` and `devicon` for brand and language logos, bundled locally so the app makes no third-party icon requests.
5. **Components.** shadcn wins wherever there is a duplicate:
   - `Card` replaces InfoCard, StatCard and VerticalCard; `Dialog` replaces CenteredModal and PositionedModal.
   - shadcn `Pagination` and `FormField` replace their counterparts; `Skeleton` replaces the seven loaders; sonner replaces `vue-toast-notification`.
   - Add `Sheet`, `Sidebar`, a stat card and one `DataTable` (tanstack plus shadcn `Table`).
   - Restyle `Button` to the landing page's shape, with the sliding arrow reserved for primary calls to action.
   - Delete each replaced `base_components` item once it has no importers.
6. **Charts.** Move the Experiment chart layer into a shared location as the only chart system, with colours from tokens. Rebuild the generic charts on it and delete them. In the UI, only saved definitions are called "Figures"; everything else is a "chart".
7. **App shell.** A collapsible left sidebar:
   - Dashboard at the top;
   - Research: Datasets, Experiments;
   - Projects: Projects, Results, Tickets;
   - Organisation settings at the bottom.

   Add a `⌘K` command palette built on the existing `command` component. Remove the top nav.

8. **Guardrail.** An ESLint rule, enforced in Jenkins, that rejects the following in new code. Unmigrated files sit on an allowlist that only shrinks.
   - hex literals;
   - raw Tailwind palette classes and `bg-theme-*`;
   - Iconify imports outside the logo sets;
   - imports of deleted `base_components`.
9. **Dependency cleanup.** Remove `vue-toast-notification`, `sass`, `@formkit/auto-animate` and the unused Iconify sets once nothing imports them. Remove Percy (`@percy/*` and its config) in favour of Playwright's built-in screenshots, whose baselines live in git.

### Pages, in order

10. **Datasets.**
11. **Experiments:** list, creation, run progress, results and Figures, Published results.
12. **Results and Projects.**
13. **Dashboard:**
    - a Research section on top: Experiments in progress with snapshot progress, recently finished Experiments, recent Published results;
    - the project overview below;
    - an owl empty state with "Create a Dataset" for organisations with no Datasets.
14. **Settings and organisation pages.**
15. **Login and signup.**

## Phase 2: dark theme and research UX

1. **Dark theme.** It follows the system setting and has a manual toggle, styled after the landing page's `#111` / `#121315` bands with green accents. It needs no per-component work once phase 1 is done, apart from fixing contrast where it falls short.
2. **Experiment flow review.** A UX review of the Experiment screens as rebuilt in phase 1, producing targeted fixes. Candidate areas:
   - progress and failure visibility for long runs;
   - making a frozen configuration visibly read-only;
   - Figure export;
   - citing Published results.

## Out of scope

- Phone layouts.
- Changing the landing page itself.
- Using the darkmode-on font (see ADR 0008).
