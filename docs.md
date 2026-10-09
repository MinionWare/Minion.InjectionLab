# Minion.InjectionLab

A free WPF teaching tool for SQL injection. It never opens a real database
connection or executes anything — it only builds SQL **strings** and narrates,
scenario by scenario, what a real engine would do with them.

## Why this exists

Most SQL injection material is either "here's how to attack a deliberately
vulnerable web app" (DVWA, WebGoat, Juice Shop, PortSwigger labs — all
browser-based, all attacker-focused) or a wall of text (OWASP cheat sheets).
Nothing combines: a desktop app, T-SQL/stored-proc-specific mechanics
(`sp_executesql`, `QUOTENAME`, dynamic SQL in procs), a live on/off fix toggle
per attack, and a "secure the proc" challenge mode. See the project memory
file for the market scan that confirmed the gap.

## Architecture

- **Minion.InjectionLab.Core** — pure data/logic, no WPF references.
  - `Models/AttackScenario.cs` — the shape every attack follows: a premise,
    form fields, a vulnerable SQL builder, a fixed SQL builder, two
    rule-based "simulators" (vulnerable/fixed), teaching prose, sample
    payloads, and optional challenge-mode hints/answer.
  - `Models/SimulationResult.cs` — the narrated outcome (severity + headline
    + detail). This is **always** produced by scenario-specific pattern
    matching against the typed input — never a real query execution.
  - `Scenarios/*.cs` — one file per attack. `TautologyLoginScenario.cs` is
    the reference implementation; copy its shape for new attacks.
  - `Catalog/AttackCatalog.cs` — the registry. Add one line here per new
    scenario file.

- **Minion.InjectionLab.Wpf** — presentation only, MVVM via
  CommunityToolkit.Mvvm.
  - `ViewModels/AttackViewModel.cs` — wraps a scenario with mutable field
    values, the fix on/off flag, and recomputes `GeneratedSql` +
    `SqlSegments` (for highlighting) + `Result` on every keystroke.
  - `ViewModels/SqlSegment.cs` + `Behaviors/HighlightedSqlBehavior.cs` — an
    attached property that renders the generated SQL as `Inlines`, coloring
    the spans that came verbatim from the form fields in red/bold so the
    injected portion is visually obvious against the app's own SQL text.
  - `Themes/Colors.Dark.xaml` / `Colors.Light.xaml` + `Brushes.xaml` +
    `Styles.xaml` — token-based theming. `Brushes.xaml` never changes；
    `ThemeService.Toggle()` swaps which `Colors.*.xaml` dictionary is merged
    at runtime, and every `DynamicResource` brush repaints immediately.

## Adding a new attack scenario

1. Create `Core/Scenarios/<Name>Scenario.cs` with a static `Create()` that
   returns an `AttackScenario`. Reuse `TautologyLoginScenario.cs` as the
   template — same five pieces: premise, fields, vulnerable builder, fixed
   builder, simulators, teaching prose, sample payloads, and (optionally)
   a challenge goal/hints/answer for "Try it yourself" mode.
2. Add it to `AttackCatalog.All`.
3. Nothing in the WPF layer needs to change — the list, form, SQL view,
   simulation panel, and challenge panel are all generic over
   `AttackScenario`.

## Planned attack catalog (status: only Tautology/Login Bypass is built)

Classic/in-band: comment truncation, UNION, stacked queries, numeric
injection, LIKE wildcard abuse, INSERT/UPDATE/DELETE injection, TOP/OFFSET
and HAVING/GROUP BY injection.

Blind/inferential: boolean blind, time-based blind (`WAITFOR DELAY`),
error-based.

Out-of-band: DNS/HTTP exfil via `xp_dirtree` / `OPENROWSET`.

Delivery/obfuscation: second-order, hex/char encoding, Unicode/homoglyph
smuggling, comment/whitespace obfuscation, truncation attacks, and the
"stored payload renders as code on a web page" scenario (the hex-in-the-DB
story — needs a small mock "rendered page" panel to land visually).

Where parameters don't help: identifier injection (table/column/ORDER BY),
dynamic SQL in stored procs (`EXEC(@sql)` vs `sp_executesql`), `QUOTENAME`'s
128-char limit, ownership chaining/`EXECUTE AS`.

Post-injection impact: `xp_cmdshell`, linked-server pivoting, privilege
escalation to sysadmin — shown as narration/mechanics only, not a working
attack recipe.

SQL Server Agent/jobs: injecting via job step parameters, including a CmdExec
step path to Windows admin — this is the "fabu demo" scenario; build it as
a scenario like any other (premise = a job step that builds a command from
a parameter, builder = the resulting command text, simulator = narration of
what runs and as whom).

Non-SQL injection (v1.1): NoSQL (`$where`/`$ne`), LDAP, XPath, ORM bypass
(`FromSqlRaw` + interpolation), header/cookie injection, log injection.

v2 (separate effort): historical SQL Server OS-level issues (old `xp_`
extended-proc buffer overflows, `DBCC` issues) — treat as history + CVE
references, not exploit code.

## Guardrails to keep in mind while adding scenarios

- Builders only ever return **strings**. No `SqlConnection`, no process
  execution, anywhere in this codebase.
- Every scenario carries a disclaimer-appropriate framing: real mechanics,
  explained plainly, for defenders who need to recognize the shape of an
  attack — not copy-paste exploit payloads aimed at systems the reader
  doesn't own. The app-level disclaimer (first-run banner, About screen)
  still needs to be written — tracked as a TODO, not yet built.
- Try-it-yourself challenge grading is rule-based (regex/text checks against
  what the user typed), never a real execution. A "real engine via LocalDB"
  opt-in mode is an explicit v2 idea, not default behavior.

## TODO / not yet built

- First-run disclaimer / About screen.
- Remaining ~25+ scenarios from the catalog above.
- "Secure the stored procedure" challenge mode (separate from per-attack
  try-it-yourself — this is the bigger "harden this whole proc" exercise).
- Mock rendered-page panel for the stored-payload-as-web-content scenario.
- Category grouping in the left nav (currently flat; fine while there's
  only one scenario, needs `CollectionViewSource` grouping once there are
  more).
- App icon / branding polish.
