# Minion.InjectionLab

A free WPF teaching tool for SQL injection. It never opens a real database
connection or executes anything — it only builds SQL/C#/PowerShell **strings**
and narrates, scenario by scenario, what a real engine would do with them.

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
    form fields, a vulnerable SQL/C#/PowerShell builder for each, two
    rule-based "simulators" (vulnerable/fixed), a `BaselineValues` dict (what
    a normal user would type), a `DecisionPaths`/`ClassifyInput` pair (for the
    live "where you're headed" diagram), teaching prose, sample payloads, and
    optional challenge-mode hints/answer.
  - `Models/SimulationResult.cs` — the narrated outcome (severity + headline +
    detail), plus optional `AffectedAssets` (blast-radius lines) and
    `LeakedRows`/`RowCountLabel` (a fake, representative result-set preview
    revealed behind a "View results" button). All of this is **always**
    produced by scenario-specific pattern matching against the typed input —
    never a real query execution.
  - `Models/Severity.cs` — `Success` (legit op worked) / `Blocked` (fix caught
    an attack) / `Info` (ordinary failure) / `Warning` / `Critical` (breach).
  - `Models/PathKind.cs` + `DecisionPathDef.cs` — the three-way taxonomy
    (Safe/Neutral/Malicious) behind the live decision-path diagram.
  - `Scenarios/TautologyLoginScenario.cs` — the reference implementation;
    copy its shape for new attacks. Its `Classify()` helper is shared by
    `ClassifyInput` (live, pre-submit) and both `Simulate*` functions
    (post-submit), so the live diagram and the final narration never disagree.
  - `Catalog/AttackCatalog.cs` — the registry. Add one line here per new
    scenario file.

- **Minion.InjectionLab.Wpf** — presentation only, MVVM via
  CommunityToolkit.Mvvm.
  - `ViewModels/AttackViewModel.cs` — the state machine. Field edits trigger
    `RecomputeCode()` (SQL/C#/PowerShell + `ActivePathKey`) live, on every
    keystroke. **Submit** is a separate, deliberate action (`SubmitCommand`)
    that computes `Result`/`NormalResult` and bumps `ResultVersion` — nothing
    about the outcome is revealed until the user clicks it. Editing a field
    or toggling the fix afterward sets `HasSubmitted = false` again (stale
    until re-submitted).
  - `ViewModels/SqlSegment.cs` — `(Text, IsUserInput)` segments; `BuildSegments`
    walks generated text and marks spans that came verbatim from a field value.
  - **Code display is AvalonEdit** (`ICSharpCode.AvalonEdit`), not plain
    TextBlocks — real syntax highlighting per language:
    - `Resources/SqlHighlighting.xshd` — a minimal hand-written T-SQL
      definition (comments, `'strings'`, `@parameters`, keywords). AvalonEdit
      ships C# and PowerShell highlighting built in; SQL doesn't, hence the
      custom one. `Services/SqlHighlightingLoader.cs` loads it from the
      embedded resource and registers it once.
    - `Behaviors/AvalonEditBehavior.cs` — `BoundText` (AvalonEdit's
      `TextEditor` has no built-in bindable `Text` DP, so this attached
      property pushes `GeneratedSql`/`GeneratedCSharp`/`GeneratedPowerShell`
      into `editor.Document.Text`) and `HighlightSegments` (wires up the
      renderer below).
    - `Behaviors/UserInputBackgroundRenderer.cs` — an `IBackgroundRenderer`
      that paints a yellow highlighter-style **background** wash behind
      `IsUserInput` segments, layered on top of AvalonEdit's own syntax
      colors. Deliberately a background wash, not a foreground color, so it's
      never confused with a syntax highlighter's own string/keyword color
      (a straight red-text marker was tried first and looked like a string
      literal — see session history).
    - Known simplification: the code panes' syntax colors are fixed (tuned
      for a dark pane) regardless of the app's light/dark theme toggle; only
      the pane background/default foreground follow the theme. Fully theming
      AvalonEdit per app-theme is a fair chunk of extra work — TODO if it
      turns out light mode reads poorly.
  - `Behaviors/ImpactBehavior.cs` — the "wow" layer: an attached `Trigger`
    (bumped `ResultVersion`) + `Severity` pair that plays a shake + red glow
    on breach, or a calm green/blue glow + pop on a blocked/successful
    outcome, via `DropShadowEffect` + `TranslateTransform`/`ScaleTransform`
    animations. Not WPF `Style.Triggers` — those can't re-fire on an
    unchanged value (e.g. two breaches in a row), which is why this exists
    as a dedicated behavior keyed off an always-incrementing counter instead.
  - `Themes/Colors.Dark.xaml` / `Colors.Light.xaml` + `Brushes.xaml` +
    `Styles.xaml` — token-based theming. `Brushes.xaml` never changes;
    `ThemeService.Toggle()` swaps which `Colors.*.xaml` dictionary is merged
    at runtime, and every `DynamicResource` brush repaints immediately.
  - `ViewModels/MainViewModel.cs` — holds the global `Difficulty` selector
    (Beginner/Intermediate/Expert), propagated to every `AttackViewModel`;
    affects `HintBudget` (all hints / half / one) and `CanRevealAnswer`
    (Expert can't see the answer button at all).

## Features built so far (all on the one scenario, Tautology/Login Bypass)

- Fix on/off toggle, with SQL/C#/PowerShell all updating live as you type.
- The live "decision path" diagram (sidebar): three branches — Correct
  credentials / Wrong password / SQL injection pattern — the active one
  highlights as you type, before you ever hit Submit.
- A persistent "Correct value: …" hint under each field (from
  `BaselineValues`), and the form's *defaults* are the baseline — opening the
  scenario and hitting Submit with nothing changed shows a real, legitimate
  success, not a meaningless failure.
- Submit is a staged reveal: "A NORMAL USER" vs. "YOU" cards side by side,
  each with its own icon/headline/detail, animated in via `ImpactBehavior`.
- "👁 View results (N rows)" under each outcome card — reveals a fake,
  representative result-set grid (e.g. your own row on success; a dramatic
  "47 rows — the entire Users table" dump on a successful bypass). Collapsed
  by default each submit; click to reveal.
- "Try it yourself" challenge mode: goal, progressive hints, reveal-answer,
  reset — all difficulty-aware.
- Reset scenario (distinct from reset challenge) — fix off, fields back to
  baseline defaults, hints/answer/results all cleared.
- Dark/light theme toggle.

## Adding a new attack scenario

1. Create `Core/Scenarios/<Name>Scenario.cs` with a static `Create()` that
   returns an `AttackScenario`. Reuse `TautologyLoginScenario.cs` as the
   template: premise, fields, vulnerable+fixed builders for SQL (and
   optionally C#/PowerShell), `BaselineValues`, `DecisionPaths` +
   `ClassifyInput` (share one private `Classify()` helper between that and
   both `Simulate*` functions so they can't drift apart), teaching prose,
   sample payloads, and optionally a challenge goal/hints/answer.
2. For the "View results" reveal, set `LeakedRows` + `RowCountLabel` on the
   `SimulationResult`s where it makes sense (a real success, a dramatic
   breach) — leave them null where there's nothing to show (an ordinary
   failure).
3. Add it to `AttackCatalog.All`.
4. Nothing in the WPF layer needs to change — the list, form, code tabs,
   decision-path diagram, submit/result panels, and challenge panel are all
   generic over `AttackScenario`.

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
story — needs a small mock "rendered page" panel to land visually; the
`LeakedRows` grid machinery already built for "View results" can likely
double as the "what got written to the page" preview).

Where parameters don't help: identifier injection (table/column/ORDER BY),
dynamic SQL in stored procs (`EXEC(@sql)` vs `sp_executesql`), `QUOTENAME`'s
128-char limit, ownership chaining/`EXECUTE AS`.

Post-injection impact: `xp_cmdshell`, linked-server pivoting, privilege
escalation to sysadmin — shown as narration/mechanics only, not a working
attack recipe. `SimulationResult.AffectedAssets` already exists for the
"blast radius" lines this needs (e.g. "Login 'webapp' added to sysadmin").

SQL Server Agent/jobs: injecting via job step parameters, including a CmdExec
step path to Windows admin — this is the "fabu demo" scenario; build it as a
scenario like any other (premise = a job step that builds a command from a
parameter, builder = the resulting command text, simulator = narration of
what runs and as whom, `AffectedAssets` = the privilege-escalation blast
radius).

Non-SQL injection (v1.1): NoSQL (`$where`/`$ne`), LDAP, XPath, ORM bypass
(`FromSqlRaw` + interpolation), header/cookie injection, log injection.

v2 (separate effort): historical SQL Server OS-level issues (old `xp_`
extended-proc buffer overflows, `DBCC` issues) — treat as history + CVE
references, not exploit code.

v2 (difficulty depth): right now Difficulty only changes the hint budget
and whether the answer button is available. The original idea was actual
*harder puzzles* per level (e.g. Expert gets a messier/obfuscated starting
query, not just fewer hints) — not yet built; flagged so it doesn't get
lost.

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
- `LeakedRows`/fake result grids are clearly representative/fabricated data
  (never queries anything) — keep them labeled as such if this ever becomes
  ambiguous in a future scenario.

## TODO / not yet built

- First-run disclaimer / About screen.
- Remaining ~25+ scenarios from the catalog above.
- "Secure the stored procedure" challenge mode (separate from per-attack
  try-it-yourself — this is the bigger "harden this whole proc" exercise).
- Mock rendered-page panel for the stored-payload-as-web-content scenario.
- Category grouping in the left nav (currently flat; fine while there's
  only one scenario, needs `CollectionViewSource` grouping once there are
  more).
- Per-theme AvalonEdit syntax colors (currently fixed/dark-tuned regardless
  of app theme — see Architecture note above).
- Difficulty levels that change puzzle *content*, not just hint budget.
- App icon / branding polish.
