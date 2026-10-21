# Sigil design system

`design/` is the single source of truth for the desktop GUI (`crates/sigil-gui`) and the admin portal (`web/`). Do not copy values out of it.

## Files

- `tokens.css`: CSS custom properties on `:root`, all prefixed `--sg-`. Colours, hairlines, text tiers, status, radius, spacing, focus, and type.
- `fonts.css`: `@font-face` declarations for the bundled fonts.
- `fonts/`: latin woff2 files and their OFL licenses. Provenance and hashes are in `fonts/README.md`.

## How each app consumes it

- **Portal:** `web/src/index.css` imports `design/tokens.css` and `design/fonts.css`. `web/tailwind.config.js` maps the tokens onto Tailwind utilities (`bg-panel`, `text-text-2`, `border-line`, `font-mono`, and so on). The Vite build copies the fonts and serves them from the same origin.
- **GUI:** `crates/sigil-gui` reads `tokens.css` and `fonts.css` at build time. The fonts are embedded, so the app works offline. The GUI stylesheet refers to tokens only through `var(--sg-*)`.

## Style rules

- Dark only. Do not add a light theme.
- Sharp corners: `--sg-radius` is 0. Inputs may use `--sg-radius-input`, at most 2px.
- Hairlines and borders, not shadows: separate panels with `--sg-line` or `--sg-line-strong`.
- Labels are uppercase IBM Plex Mono with `--sg-tracking-label`, at `--sg-text-label`. Use them for section titles, table headers, badges, and metadata such as SERIAL or FIRMWARE.
- Headings are Inter Tight, large and tight, with `--sg-tracking-heading`.
- The accent (`--sg-accent`) marks the single primary action or the current selection. Do not use it for decoration.
- Buttons are rectangular. Primary: accent fill with `--sg-accent-ink` text. Secondary: hairline outline. Danger: danger outline, or fill for a confirmed destructive action.
- Status is a small square indicator plus uppercase mono text. Tints are for backgrounds only. Use the shared indicator: `StatusBadge` in `web/src/components/ui/status.tsx`, and `.slot-key-state` or `.sg-status` in `crates/sigil-gui/src/theme.css`. Tones are ok, warn, danger, neutral.
- Chips and tags (counts, FIPS, mode, application names) are hairline outlines with mono uppercase text, square corners. The GUI uses `.status-badge`, `.count-badge`, `.application-chip` and `.mode-badge`, which share one rule. The portal uses `Badge` for these.
- Identifiers and timestamps are mono: serials, certificate serials, slots, dates, grant and rotation IDs, audit sequence numbers.
- Tables are dense and data-forward.
- Focus is always visible: 1px accent outline with a 2px offset.

## Timestamps

Show every time in ISO-8601 UTC, to the minute: `2026-09-21 07:23Z`. Omit seconds. Do not use the viewer's locale or time zone. The GUI formats with `sigil_core::time::format_utc_minute`, and the portal with `formatUnix` in `web/src/lib/format.ts`. Both produce the same string for the same instant.

## Contrast

Text tiers on `--sg-bg` pass WCAG AA: text 16.2:1, text-2 7.5:1, text-3 5.8:1. Accent text passes at 8.3:1. Ink on the accent fill passes at 8.3:1. Status colours pass at 4.7:1 or more on the background.

Do not put text on `--sg-accent` other than `--sg-accent-ink`. Do not use `--sg-text-3` for anything an operator must read to act.

## Changing a token

Change it in `tokens.css` only. Re-check the contrast numbers above, then rebuild both apps.
