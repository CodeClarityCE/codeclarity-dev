# The platform takes its visual identity from the landing page

The platform and www.codeclarity.io felt like two products. The landing page is now the source of the platform's identity: brand green `#1dce79`, near-black `#111` surfaces, pill-shaped primary buttons, green-highlighted words in titles, and the owl's voice. The platform departs from it only where an application has needs a marketing page does not: information density, state colours (severity, licence, snapshot outcome), a dark theme, and keyboard and focus behaviour.

## Considered Options

- **Use the landing page's font (darkmode-on).** It is only licensed through Adobe Fonts, so it cannot ship in a self-hosted AGPL product. The platform keeps Lato, which is open-licensed and self-hosted.
- **Switch to Bootstrap, as the landing page uses.** That means rewriting every screen, with no reduction in dependencies, and Bootstrap is weaker for dense, accessible application components. The platform keeps Vue, Tailwind and Reka UI and copies the look through design tokens, sharing no code with the site.
- **Support phones.** Not for now: the platform supports viewports 1024px and wider.

## Consequences

- Copying the landing page's top navigation is not required. A sidebar falls under the density exception.
- Brand green is never a severity colour, so it keeps meaning "brand and action".
