---
support_id: injectionlab.challenge-mode
---
# Challenge Mode

Flip "Try it yourself" on in any scenario that has it (every scenario in
the [catalog](catalog/overview.md) does), and the mock form stops showing
you the answer — you're on your own to craft a payload that achieves the
stated goal.

## What you get

- **A goal** — a plain-English statement of what the payload needs to
  achieve (e.g. "log in as `alice` without ever knowing her real
  password").
- **Progressively-revealing hints** — click "💡 Give me a hint" for one at
  a time. How many you're allowed depends on
  [Difficulty](getting-started/difficulty-levels.md): all of them on
  Beginner, about half on Intermediate, just one on Expert.
- **An answer you can reveal** — on Beginner and Intermediate only. Expert
  disables it entirely: you have to crack it yourself.
- **Reset** — clears your attempt and the hints you've revealed, so you
  can start over.

## How grading works

Nothing here executes against a real database. Your input is matched
against the same rule-based classification logic that drives the
decision-path diagram and the "what happens" narration everywhere else in
the app — the same honest, text-based rules, not a hidden answer-checker.

## Tips

- The **sample payloads** shown for every scenario are real, working
  examples — and the text is selectable, so you can copy one straight into
  the form and see exactly what it does before adapting it for the
  challenge.
- If you're stuck, re-reading **"How it works"** for that scenario usually
  gets you there faster than burning another hint.

Back to the **[Feature List](features/overview.md)** or the
**[Attack Catalog](catalog/overview.md)**.
