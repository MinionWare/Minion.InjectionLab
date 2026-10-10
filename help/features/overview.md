# Feature List

## 🎓 A real tutorial, not just a wall of text

A nine-step, assume-nothing wizard opens the first time you launch the
app — what SQL injection is, why it matters, and four core techniques
taught through five live, interactive demos. See
**[The Opening Tutorial](../getting-started/tutorial-wizard.md)**.

## 🗂️ Twenty-six real attacks, seven categories, all fully built out

Every single entry in the catalog — no exceptions — gets:

- The real, generated **SQL**, built live as you type.
- The **C#** (ADO.NET) that would produce it.
- The **PowerShell** (`Invoke-Sqlcmd`/`SqlClient`) that would produce it.
- A **"Where you're headed"** decision-path diagram that classifies your
  input live, before you even submit.
- **How it works** / **Why the fix works** narration.
- **Where the name comes from** — the terminology explained, backed by
  real, clickable, externally-verified sources.
- Sample payloads and a full **Challenge Mode**.
- A **Partial** fix alongside the real **Best** fix, graded and
  color-coded (🔴 red for still-vulnerable, 🟡 amber for Partial, 🟢 green
  for Best), with the Partial fix's exact remaining gap spelled out in
  plain English — never a straw man, always a mitigation real teams
  genuinely ship.

See the full **[Attack Catalog](../catalog/overview.md)**.

## ⚖️ Honest about what a "fix" actually fixes

This app doesn't play pretend with a single on/off toggle. Every multi-fix
scenario shows a **Partial** fix side by side with the real **Best** fix —
because in the real world, "we added some filtering" and "we actually fixed
it" get conflated constantly, and that gap is where incidents live. The
Partial fix is never a straw man: it's the kind of mitigation real teams
genuinely ship, with a real, specific, demonstrated gap.

## 🎚️ Three difficulty levels

Beginner, Intermediate, and Expert change how forgiving the weak fixes are
— and how many hints you get in Challenge Mode. See
**[Difficulty Levels](../getting-started/difficulty-levels.md)**.

## 🧪 Try it yourself — Challenge Mode

Every scenario includes a real challenge: a goal, progressively-revealing
hints (budget depends on difficulty), and an answer you can reveal if
you're stuck — except on Expert, where you're on your own. See
**[Challenge Mode](../challenge-mode.md)**.

## 🏆 Quiz Mode — devise your own attack

Three capstone missions, one per difficulty, with open-ended grading —
no single canonical answer, any payload that genuinely achieves the goal
counts. Expert is a full recon-then-exploit chain: no schema given, you
have to discover the real tables and columns yourself before you can
steal anything. See **[Quiz Mode](../quiz-mode.md)**.

## 📚 Nothing here is made up

Every scenario's terminology and claims are backed by real, independently
published sources — OWASP, PortSwigger's Web Security Academy, Microsoft
Learn, vendor security research (NetSPI, GoSecure, PowerUpSQL), or the
original academic classification of SQL injection attack types (Halfond,
Viegas & Orso, 2006). Every link was checked before it was added. Click any
of them in the app to open it in your browser.

## 🖥️ Real syntax validation, not guesswork

Whether a payload is syntactically valid T-SQL is checked with
**Microsoft's own SQL Server parser** (`Microsoft.SqlServer.TransactSql.ScriptDom`),
not a hand-rolled heuristic — so the app's classification of "this breaks
the query" vs. "this is syntactically fine but doesn't achieve a bypass" is
the real answer, not a guess.

## 🎨 Polished, theme-aware, and genuinely yours to explore

- Dark and light themes, toggleable any time.
- Full Minionware branding — the mascot icon, the wordmark, a direct link
  to [minionware.net](../about/minionware.md).
- Nothing is ever executed against a real database, ever. Every "query"
  result, every "leaked row," every narrated outcome is a string this app
  built and a rule-based explanation of what a real engine would do with
  it — which is exactly what makes it safe to run anywhere, with zero setup.

## 🧭 A real menu bar, because you need to be able to close the thing

`File`, `View`, `Help`, and `Minionware` — exit, theme toggle, the
tutorial, about, feature list, and a link out to more Minionware tools.
