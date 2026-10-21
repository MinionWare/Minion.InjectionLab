---
support_id: injectionlab.welcome
---
# First Launch

Minion.InjectionLab opens on a **welcome screen**, not straight into a
scenario — the mascot icon, a clickable Minionware wordmark, a short "this
never touches a real database" safety note, and two buttons: **Start the
tutorial** and **Browse the attack catalog**. The first time you run the
app, the **[opening tutorial](tutorial-wizard.md)** also pops up
automatically on top of it — a nine-step, assume-nothing walkthrough of
what SQL injection actually is. You only see it unprompted once; after
that, reopen it any time from the nav button or `Help > Show tutorial`.

Click the app icon/title at the top of the left nav any time to come back
to the welcome screen — it's a "home" button, and the entrance animation
replays each time.

## What's on screen

- **Left nav** — click the icon/title to go **home** to the welcome
  screen; the Minionware logo (click it to open
  [minionware.net](../about/minionware.md)); **Toggle theme**,
  **Tutorial**, **Help**, **Quiz mode**; the **Difficulty** selector; and
  below that the full attack list, grouped by category.
- **Main panel**, per attack:
  - A short **premise** — the fictional app/feature the attack targets.
  - A mock form you type a payload into, live.
  - **"Where you're headed"** — a decision-path diagram that classifies
    your input as you type, before you even submit.
  - **"What actually runs"** — SQL, C#, and PowerShell tabs showing the
    real code, plus tabs to compare the Vulnerable version against each
    graded fix.
  - **How it works** / **Why the fix works** / **Where the name comes
    from** — the mechanics, the defense, and the terminology with external
    references.
  - **Sample payloads** (selectable — copy one straight into the form) and
    a **[Challenge](../challenge-mode.md)** panel ("try it yourself").
- **Menu bar** — `File`, `View`, `Help`, and `Minionware`.

## Menu bar reference

| Menu | Item | What it does |
|---|---|---|
| File | Exit | Closes the app. |
| View | Toggle theme | Switches dark/light theme. |
| View | Quiz mode | Opens **[Quiz Mode](../quiz-mode.md)**. |
| Help | Feature list | Opens this help content. |
| Help | Show tutorial | Reopens the opening wizard. |
| Help | About | Version and app info. |
| Minionware | minionware.net | Opens Minionware's site in your browser. |
| Minionware | Other products | Coming soon. |

See the **[Feature List](../features/overview.md)** for the full tour, or
jump straight to the **[Attack Catalog](../catalog/overview.md)**.
