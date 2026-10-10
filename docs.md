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
    - **The editors' text is set explicitly from `MainWindow.xaml.cs`, not
      via XAML data binding.** The first attempt bound a custom `BoundText`
      attached property to `GeneratedSql`/etc. in XAML; this produced blank
      or stale text intermittently (reliably reproducible on certain
      scenario/fix-tab combinations, "fixed itself" after navigating away and
      back on others) that was never fully root-caused through code review
      alone — plausibly an AvalonEdit `Document` re-initialization during
      template application racing the binding's first value, but that's a
      hypothesis, not a confirmed diagnosis. Rather than keep patching an
      unreliable mechanism, `MainWindow` now subscribes directly to the
      tracked `AttackViewModel`'s `PropertyChanged` and calls
      `editor.Document.Text = ...` itself whenever `GeneratedSql`/
      `GeneratedCSharp`/`GeneratedPowerShell`/their `*Segments` change, and
      re-subscribes whenever `SelectedAttack` changes. `HighlightSegments`
      stays an attached property (`AvalonEditBehavior`), but is now also set
      explicitly from code (`SetHighlightSegments(...)`), not bound in XAML.
      If a new code pane is ever added, wire it into `SyncCodePanes()`/
      `OnAttackPropertyChanged`, not through a XAML binding.
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

## Opening wizard (Tutorial)

A from-scratch, assume-nothing walkthrough that opens automatically on first
launch (and any time from the "🎓 Tutorial" nav button) via `TutorialWindow`,
a modal owned by `MainWindow`. It's deliberately a separate, simpler model
from the attack catalog:

- `Core/Models/TutorialStep.cs` / `TutorialDemo.cs` — a step is a title + a
  few narration paragraphs + an optional single-field live demo (one
  `BuildSql`/`Explain`/`IsDangerous` set of funcs, not the full SQL+C#+
  PowerShell+multi-fix shape every catalog scenario has to have). That's
  intentional: the wizard teaches the *concept* once, generically; each
  catalog entry then owns one technique's full depth. The "every scenario
  must be identical" consistency rule applies to the attack catalog, not to
  this onboarding content.
- `Core/Tutorial/TutorialContent.cs` — 9 steps: what SQL injection is, the
  core concatenation flaw (with a quote-mark-breaks-the-string demo), then
  four technique demos (tautology login bypass, UNION data exfiltration,
  boolean-blind flip, stacked-query piggyback), then "why this keeps
  happening", the parameterization fix explained conceptually, and a
  wrap-up pointing at the real catalog/difficulty selector/challenge mode.
- `Wpf/ViewModels/TutorialViewModel.cs` — step index + Back/Next/Close
  commands, plus the live demo state (`DemoInput` → recomputed `DemoSql`/
  `DemoExplain`/`DemoIsDangerous` on every keystroke, same recompute-on-type
  pattern as `AttackViewModel`).
- `Services/TutorialService.cs` — a marker file at
  `%AppData%\Minion.InjectionLab\tutorial-seen.flag` gates the *automatic*
  first-launch popup only; the nav button always reopens it regardless.

## Bug: C#-pseudocode guard clauses leaked into the SQL tab

When building the keyword-blacklist Partial fixes, the "guard clause" showing
the filter check (`if (username.Contains("OR")) reject();`) got written into
`BuildSql` — i.e., it showed up in the **SQL tab**, as if it were T-SQL. It
isn't; the filter runs in application code, before any SQL is ever built.
Affected 8 of the 9 blacklist-style Partial fixes (every one except
LikeWildcard, which never had a guard clause in its SQL tab to begin with).

Fixed by removing the guard clause from every `BuildSql` entirely — the SQL
tab now shows either the real, unmodified vulnerable SQL (filter didn't catch
it) or a one-line SQL comment saying the request was rejected before any SQL
was built. The guard logic itself still correctly lives in `BuildCSharp`/
`BuildPowerShell`, which already used real C#/PowerShell syntax. **One
exception**: `DynamicSqlStoredProcScenario`'s check genuinely runs as T-SQL
inside the proc (against a real `@Name` parameter), so its SQL tab shows an
actual, valid `IF @Name LIKE '%UNION%' RETURN;` rather than a comment — that
one scenario is structurally different from the other eight, which are all
ad hoc application-level string checks with nothing SQL-side to show.

**Lesson for future scenarios**: never put "what the application decided to
do" into a `BuildSql`/SQL-tab string unless it's also genuinely something
SQL Server would execute. If in doubt, put it in `BuildCSharp`/
`BuildPowerShell` instead, or as a plain SQL comment explaining what *didn't*
run.

## Every scenario has the same shape (SQL + C# + PowerShell, 2 fixes each)

Earlier iterations left this inconsistent — only 2 of 10 scenarios had
PowerShell, only 7 had more than one fix. That's not "the engine is generic,
content varies," that's incomplete data, and it reads as broken/arbitrary to
someone clicking through the app. All 10 scenarios now have:
- `BuildVulnerableSql`/`BuildVulnerableCSharp`/`BuildVulnerablePowerShell`.
- Exactly 2 `Fixes` entries, each with `BuildSql`+`BuildCSharp`+`BuildPowerShell`+`Simulate`.

For the 3 scenarios that only had a single fix before (StackedQueries,
BooleanBlind, TimeBasedBlind), finding an honest Partial fix required two
real fixes along the way:
- **StackedQueries' `Classify` was incomplete.** It only recognized the
  semicolon+DML/DDL "stacked" pattern; a plain `1007 OR 1=1` against the same
  numeric/unquoted query fell through to `"normal"` and the vulnerable
  simulation claimed "Order 1007 found" — wrong, the real SQL would dump
  every row. Now classifies into `"stacked"` and `"tautology"` as two
  distinct techniques, so the Partial fix (block `;`) has an honest,
  demonstrable gap: it stops stacking but not a bare tautology.
- Where a scenario's own technique has no case-sensitivity dimension (a
  semicolon isn't a keyword), the Partial fix still demonstrates its real
  gap without pretending difficulty changes anything for it — not every
  Partial fix needs `KeywordBlacklist` to be honest.

For DynamicSqlStoredProc and SecondOrder specifically, the C#/PowerShell
calling code is **identical** across the vulnerable/Partial/Best variants —
the vulnerability (and each fix) lives entirely inside the stored procedure
or inside Step 2's SQL text, not in how the app calls it. That's intentional
and worth preserving if these scenarios change: showing the same calling
code three times is the honest reflection of where the bug actually lives.

## Scenarios built so far (10)

Classic/in-band: Tautology/Login Bypass, UNION-Based Injection, Stacked Queries,
Numeric Injection (no quotes needed), LIKE Wildcard Abuse.

Blind/inferential: Boolean-Blind Injection, Time-Based Blind Injection.

Where parameters don't help: Identifier Injection (ORDER BY), Dynamic SQL
Inside a Stored Procedure.

Delivery/obfuscation: Second-Order Injection.

The left nav groups scenarios by `AttackScenario.Category` via
`CollectionViewSource.GetDefaultView` + `PropertyGroupDescription` in
`MainWindow.xaml.cs` (not pure XAML — the default view trick lets the existing
`{Binding Attacks}` keep working unchanged). `Converters/CategoryDisplayConverter.cs`
turns the enum into a friendly header ("Where Parameters Don't Help", etc).

## Features built so far (all scenarios)

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

## Syntax realism: payloads must actually neutralize what follows them (Services/SqlSyntaxChecker.cs)

Several templates put original query text *after* the injection point (e.g.
Tautology's `' AND PasswordHash = '{p}';`, UNION/LIKE's trailing `%';`). A
payload that doesn't comment that out (usually with `--`) wouldn't actually
run cleanly in real SQL Server — it errors out, or just doesn't achieve a
full bypass. The first pass at this used a hand-rolled heuristic
(`raw.TrimEnd().EndsWith("--")`), which is exactly the kind of guess the app
is supposed to *replace* for its users, so it was swapped for real SQL Server
parsing: **`Microsoft.SqlServer.TransactSql.ScriptDom`** (the engine behind
SSDT/SqlPackage) via `Core/Services/SqlSyntaxChecker.HasSyntaxError(sql)` —
`TSql160Parser` parses the actual runtime SQL text and reports genuine parse
errors, so "would this really work" is authoritative, not pattern-matched.
Verified directly against the parser: `' OR 1=1` (no comment, unquoted) is a
real syntax error (the password value gets stranded outside any string
literal); `' OR '1'='1` (no comment, but quoted) is syntactically *valid*
SQL even though it doesn't fully bypass both checks due to operator
precedence — a nuance the old heuristic couldn't have told apart either way.

Scenarios where this matters (Tautology, UnionSelect, DynamicSqlStoredProc,
SecondOrder, LikeWildcard's SQLi branch) classify a syntax error as a
distinct `"malformed"` path — a warning-severity "this would throw a syntax
error" outcome — not the full breach. Each exposes a private
`VulnerableSql(f)` (or, where the vulnerable query is nested inside other
text — the stored-proc and second-order scenarios — a narrower
`RuntimeSql(f)`/`Step2Sql(f)`) that both `BuildVulnerableSql` and `Classify`
call, so there's one source of truth for what actually gets parsed. Scenarios
whose templates don't need a trailing comment to work (StackedQueries,
BooleanBlind, TimeBasedBlind, NumericInjection, OrderByIdentifier — all
numeric/unquoted contexts where the only trailing text is a bare `;`) don't
use the checker at all. **Known limitation**: "is this syntactically valid"
is now authoritative; "does a syntactically-valid attempt achieve a full
bypass" (vs., say, defeating only half of an AND'd condition) is still a
pattern match against known techniques, not a real boolean-logic evaluation
of the WHERE clause — that would be a much bigger undertaking. When writing
a new scenario, check whether the template leaves anything live after the
injection point, and if so, feed the actual runtime SQL through
`SqlSyntaxChecker` before classifying as a full "injection".

## Multiple fixes, graded (Models/FixGrade.cs, FixOption.cs)

Not every attack has exactly one fix. LikeWildcardScenario is the reference
example: parameterizing alone (`FixGrade.Partial`, with a `Gap` explaining
what's still broken) stops SQL injection but not wildcard abuse; escaping `%`/
`_`/`[` on top of that (`FixGrade.Best`) closes both holes. A scenario opts in
by setting `AttackScenario.Fixes` (a list of `FixOption`, each with its own
`BuildSql`/`Simulate`/optional C#+PowerShell builders, a `Grade`, and a `Gap`)
instead of the legacy single `BuildFixedSql`/`SimulateFixed`. Those legacy
fields are now optional — `AttackViewModel` synthesizes a single Best-grade
`FixOption` from them when a scenario doesn't set `Fixes`, so none of the
other 8 scenarios needed to change.

The view model exposes this uniformly as `CurrentFixIndex` (-1 = vulnerable,
0..N-1 = `Fixes[i]`), with `IsFixApplied` kept as a bool wrapper for
backward compatibility with the simple on/off toggle. `MainWindow.xaml` shows
the plain toggle when `HasMultipleFixes` is false, or a segmented
"Compare: ⚠ Vulnerable / Fix A / Fix B" row when true, plus a callout showing
the selected fix's `Gap` if it has one. **Known limitation**: the XAML
currently hard-codes exactly two fix-option buttons (`Fixes[0]`, `Fixes[1]`)
rather than iterating an arbitrary-length list — fine since every multi-fix
scenario currently has exactly two, but revisit (an `ItemsControl` +
`AlternationIndex` binding, same pattern as the decision-path diagram) if a
future scenario needs three or more.

**7 of 10 scenarios now have two fixes** (Tautology, UnionSelect,
NumericInjection, DynamicSqlStoredProc, SecondOrder, OrderByIdentifier,
LikeWildcard), following one of two patterns:
- **Keyword blacklist (Partial) vs. parameterization (Best)** — Tautology,
  UnionSelect, NumericInjection, DynamicSqlStoredProc, SecondOrder. The
  blacklist checks for one exact uppercase keyword (`"OR"`, `"UNION"`,
  `"DROP"`); the Gap is always the same honest point — SQL keywords aren't
  case-sensitive to the engine, so `union`/`or`/`drop` (lowercase) walk
  straight past a naive filter, and each scenario's `SamplePayloads` includes
  a lowercase variant that demonstrates exactly that. This is also why the
  teaching tool's very first design note ("include a failing blacklist —
  it's worth showing why filtering isn't a fix") finally has a concrete,
  reusable implementation.
**The 5 keyword-blacklist Partial fixes are now Difficulty-aware**
(`Core/Services/KeywordBlacklist.cs`), not static. At Beginner, the filter
checks its keyword(s) case-sensitively (a lowercase payload sails through).
At Intermediate, the same keywords, case-insensitively. At Expert, those
keywords plus one or two more related ones, still case-insensitively — but a
payload that needs none of the blocked words (the classic `admin'--`
truncation, which has no "OR" at all) still sails through at every level,
which is the actual point: a blacklist can only ever cover phrasings someone
thought to list. Matching is done on **word boundaries** (`\bOR\b`, not a raw
substring `Contains`), which is both more realistic (real keyword filters do
this) and necessary — a naive case-insensitive substring check would
false-positive on the baseline password itself (`correct-horse-battery-99`
contains "or" inside "c**or**rect"). `FixOption.BuildSql`/`Simulate` both take
`DifficultyLevel` as a second parameter for exactly this; `BuildCSharp`/
`BuildPowerShell` deliberately don't (secondary/illustrative tabs, always show
the Beginner-level version — a known, documented simplification).

- **Allow-list done wrong vs. done right** — OrderByIdentifier specifically:
  Partial uses `Contains` instead of an exact match and then concatenates
  the *raw* input anyway (not a hard-coded safe value) — a very common real
  logic bug — so `"Name; WAITFOR DELAY..."` passes the check (it does
  contain "Name" as a substring) and still runs. Best is an exact-match
  allow-list that substitutes a hard-coded literal, with `QUOTENAME` as
  defense in depth.
- **Partial-vs-Best by missing a different concern entirely** —
  LikeWildcard: parameterizing stops SQL injection but not LIKE's own
  wildcard syntax; escaping `%`/`_`/`[` on top of that closes the remaining
  gap. This is the one scenario where the "partial" fix isn't a fake/naive
  pattern — it's a real, complete fix for a *different* problem than the one
  still open.

**Deliberately left single-fix, with the reasoning written into their
`HowItWorks`/comments**: StackedQueries (blacklisting the one required
character, `;`, doesn't have a clean realistic bypass in this simplified
single-field demo — unlike a keyword, there's no case-variation trick for a
punctuation character), BooleanBlind and TimeBasedBlind (blind techniques
work precisely *because* they don't depend on any one keyword, so there's no
honest "weaker-but-real" mitigation to contrast against parameterization —
inventing one would be dishonest to the lesson).

## Gotcha: `Run.Text` bindings default to TwoWay

Learned twice in this session: a plain `<Run Text="{Binding SomeProperty}"/>`
defaults to a `TwoWay` binding in this WPF version, and crashes at the moment
the `Run` becomes visible if `SomeProperty` (or anything in its path, like a
`KeyValuePair.Key`/`.Value`, or a computed get-only property) has no setter.
Always give `Run.Text` bindings an explicit `Mode=OneTime` or `Mode=OneWay`.
(`TextBlock.Text` does not have this problem — only `Run.Text` does.)

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

## Planned attack catalog (remaining — 9 of ~30+ built so far)

Classic/in-band (built: Tautology, UNION, stacked queries, numeric,
LIKE wildcard): comment truncation, error-based, INSERT/UPDATE/DELETE
injection, TOP/OFFSET and HAVING/GROUP BY injection.

Blind/inferential (built: boolean, time-based): error-based blind variants.

Out-of-band: DNS/HTTP exfil via `xp_dirtree` / `OPENROWSET`.

Delivery/obfuscation (built: second-order): hex/char encoding, Unicode/
homoglyph smuggling, comment/whitespace obfuscation, truncation attacks, and
the "stored payload renders as code on a web page" scenario (the hex-in-the-DB
story — needs a small mock "rendered page" panel to land visually; the
`LeakedRows` grid machinery already built for "View results" can likely
double as the "what got written to the page" preview).

Where parameters don't help (built: ORDER BY identifier injection, dynamic
SQL in a stored proc): `QUOTENAME`'s 128-char limit, ownership chaining/
`EXECUTE AS`.

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
- Per-theme AvalonEdit syntax colors (currently fixed/dark-tuned regardless
  of app theme — see Architecture note above).
- Difficulty levels that change puzzle *content*, not just hint budget.
- App icon / branding polish.
