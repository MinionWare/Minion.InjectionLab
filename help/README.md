# Minion.InjectionLab help content

This folder is the source of truth for Minion.InjectionLab's help content —
plain Markdown, cross-linked like a small wiki, with `mkdocs.yml` describing
the menu/nav structure.

## Status

Content only, for now. Nothing in the app renders these as HTML yet — the
"❓ Help" nav button and `Help > Feature list` menu item currently just shell
out to `index.md` with whatever app Windows has associated with `.md` files.
The real plan is to render these through the existing Minionware help app
(hosted in Blazor), the same one other Minionware products already use —
that app just isn't wired to per-topic **help IDs** yet. When it is:

- Every page here should get an `<!-- id: some-stable-id -->` comment near
  the top (not added yet — do this when the Blazor side is ready to consume
  it) that the app's "?" icons and menu items will target directly, instead
  of opening `index.md` and making the reader navigate from there.
- `mkdocs.yml`'s `nav:` tree is written so it can be read either by real
  `mkdocs` (useful for proofreading the site locally: `pip install mkdocs`,
  then `mkdocs serve` from a copy of this folder with a `docs_dir` pointing
  here) or by a small script that turns it into whatever nav format the
  Blazor help app wants.

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
