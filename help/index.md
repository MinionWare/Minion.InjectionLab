# Minion.InjectionLab

**See exactly how SQL injection works — in real T-SQL, real C#, and real PowerShell — without ever touching a real database.**

Most SQL injection material makes you choose: either a deliberately-broken
web app you attack blind with no real explanation (DVWA, WebGoat, the usual
CTF-style labs), or a wall of text that tells you injection is bad without
ever showing you the actual query it builds. Minion.InjectionLab is the
thing in between — a desktop app where you type a payload into a mock form
and watch, live, character by character, exactly what SQL Server would do
with it. No setup, no real connection string, nothing to break. It's all
just strings, built in front of you.

## Why it's worth your time

- **It's honest about difficulty.** Every weak fix in this app is a *real*
  mistake people actually ship — not a straw man. You'll see exactly where
  it breaks, at a difficulty level you control.
- **It doesn't stop at SQL.** Every attack shows the same logic in SQL,
  C#, and PowerShell, so you can recognize the bug whichever language your
  own codebase is in.
- **It grades fixes instead of just toggling them.** A "Partial" fix and a
  "Best" fix are shown side by side, color-coded, with the gap between them
  spelled out — because "add a fix" and "actually fix it" are not the same
  thing, and most real incidents live in that gap.
- **Nothing here is made up.** Every attack's terminology and claims link
  out to OWASP, PortSwigger, Microsoft Learn, or the original academic
  literature — check it yourself any time, it's one click away in the app.

## Where to start

1. **[First Launch](getting-started/welcome.md)** — orientation: what's on
   screen and where things are.
2. **[The Opening Tutorial](getting-started/tutorial-wizard.md)** — a
   from-scratch, nine-step walkthrough that opens automatically the first
   time you run the app. Start here if the term "SQL injection" is new, or
   you just want the concept taught cleanly before diving into specifics.
3. **[Feature List](features/overview.md)** — the full tour of what this
   app can do.
4. **[Attack Catalog](catalog/overview.md)** — thirteen real techniques,
   each with full mechanics, graded fixes, and a "try it yourself"
   challenge.

## The honest disclaimer

This app **never opens a database connection and never executes anything**.
Every "query," every "result," every "leaked row" is a string this app
built and a narration this app wrote, based on how a real SQL Server engine
actually behaves — not a live system reacting to your input. That's by
design: it's what makes this safe to run anywhere, learn from without a lab
environment, and impossible to accidentally point at something real.
