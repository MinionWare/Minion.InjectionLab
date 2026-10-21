# Minion.InjectionLab help content

This folder is the source of truth for Minion.InjectionLab's help content —
plain Markdown, cross-linked like a small wiki, with `mkdocs.yml` describing
the menu/nav structure.

## Status

Every page now has a `support_id:` YAML frontmatter field (e.g.
`injectionlab.catalog.tautology-login-bypass`) — the ID HelpServer
(`D:\GitHub\HelpServer`) and the app's "?" icons target directly. IDs use
dotted, readable keys rather than numbers, one per topic area:

- `injectionlab.home`, `.welcome`, `.tutorial`, `.difficulty`, `.features`
- `injectionlab.catalog` (the overview) and `injectionlab.catalog.<slug>`
  per attack, matching the file's own slug under `catalog/`
- `injectionlab.challenge-mode`, `.quiz-mode`, `.about`

`mkdocs.yml`'s `nav:` tree doesn't reference these IDs (HelpServer's nav
only ever maps a label to a file path) — it's read as-is, either by real
`mkdocs` (useful for proofreading the site locally: `pip install mkdocs`,
then `mkdocs serve` from a copy of this folder with a `docs_dir` pointing
here) or directly by HelpServer, which supports the mkdocs nav dialect
natively. `site.json` carries this site's title/description/accent/icon.

The in-app wiring (the "❓ Help" nav button, `Help > Feature list`, and
per-screen "?" icons actually calling HelpServer by ID instead of just
shelling out to `index.md`) is tracked separately — this folder is the
content and ID source of truth regardless of when that wiring lands.

## Conventions

- One topic per file. Cross-link with ordinary relative Markdown links
  (`[Difficulty Levels](../getting-started/difficulty-levels.md)`) — these
  resolve correctly both in plain Markdown viewers/GitHub and in mkdocs.
- Every attack-catalog page cross-links back to `catalog/overview.md` and
  out to its real external references (the same ones shown in-app under
  "Where the name comes from") — the goal is a reader can go from "never
  heard of this" to "here's the primary source" without leaving this folder
  except for the actual citations.
- Keep catalog pages shorter than the in-app `HowItWorks`/`WhyTheFixWorks`
  text — their job is to get someone excited and oriented, not to replace
  actually opening the app and playing with the live SQL/C#/PowerShell
  tabs. Send them into the app for the mechanics.
