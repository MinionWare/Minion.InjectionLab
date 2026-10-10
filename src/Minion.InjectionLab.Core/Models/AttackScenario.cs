namespace Minion.InjectionLab.Core.Models;

/// <summary>
/// One entry in the left-hand list: a self-contained teaching unit. Everything here
/// produces TEXT (SQL strings, narration) — nothing is ever executed against a real
/// database or OS.
/// </summary>
public sealed class AttackScenario
{
    public required string Id { get; init; }
    public required AttackCategory Category { get; init; }
    public required string Title { get; init; }
    public required string Premise { get; init; }          // the story: "a product search box on an e-commerce site"
    public required IReadOnlyList<FormField> Fields { get; init; }

    /// <summary>Builds the raw, concatenated SQL a naive app would send.</summary>
    public required Func<IReadOnlyDictionary<string, string>, string> BuildVulnerableSql { get; init; }

    /// <summary>
    /// Builds the parameterized/defended equivalent (SQL text + how params bind). Used directly
    /// for scenarios with exactly one real fix. Scenarios with more than one fix worth comparing
    /// (a Partial one and a Best one, say) should leave this null and populate <see cref="Fixes"/>
    /// instead — the view model synthesizes a single-entry Fixes list from this field when Fixes
    /// is empty, so existing single-fix scenarios never need to change.
    /// </summary>
    public Func<IReadOnlyDictionary<string, string>, string>? BuildFixedSql { get; init; }

    /// <summary>The C# (ADO.NET) that would produce the vulnerable SQL above.</summary>
    public Func<IReadOnlyDictionary<string, string>, string>? BuildVulnerableCSharp { get; init; }

    /// <summary>The C# (ADO.NET) fix — parameters, not concatenation.</summary>
    public Func<IReadOnlyDictionary<string, string>, string>? BuildFixedCSharp { get; init; }

    /// <summary>The PowerShell (e.g. Invoke-Sqlcmd / SqlClient from PS) that would produce the vulnerable SQL.</summary>
    public Func<IReadOnlyDictionary<string, string>, string>? BuildVulnerablePowerShell { get; init; }

    /// <summary>The PowerShell fix — parameters, not string building.</summary>
    public Func<IReadOnlyDictionary<string, string>, string>? BuildFixedPowerShell { get; init; }

    /// <summary>Label for the "live app" mock preview (e.g. "Customer Login", "Product Search").</summary>
    public string MockAppLabel { get; init; } = "Demo App";

    /// <summary>
    /// What a normal, non-malicious user would type here — used to show the "proper call"
    /// result side-by-side with whatever the visitor actually typed, so the contrast is visible.
    /// </summary>
    public IReadOnlyDictionary<string, string>? BaselineValues { get; init; }

    /// <summary>The branches shown in the live "decision path" diagram (null hides it for this scenario).</summary>
    public IReadOnlyList<DecisionPathDef>? DecisionPaths { get; init; }

    /// <summary>Given the current (unsubmitted) field values, returns the Key of the active DecisionPathDef.</summary>
    public Func<IReadOnlyDictionary<string, string>, string>? ClassifyInput { get; init; }

    /// <summary>Rule-based narration of what the vulnerable version would do with this input.</summary>
    public required Func<IReadOnlyDictionary<string, string>, SimulationResult> SimulateVulnerable { get; init; }

    /// <summary>Rule-based narration of what the fixed version does with the same input. See the
    /// note on <see cref="BuildFixedSql"/> — leave null and use <see cref="Fixes"/> for multi-fix scenarios.</summary>
    public Func<IReadOnlyDictionary<string, string>, SimulationResult>? SimulateFixed { get; init; }

    /// <summary>
    /// More than one real fix to compare side by side, each independently graded (Partial/Good/
    /// Best) with its own remaining gap explained. Leave empty and use BuildFixedSql/SimulateFixed
    /// instead when there's really just one fix worth showing.
    /// </summary>
    public IReadOnlyList<FixOption> Fixes { get; init; } = Array.Empty<FixOption>();

    public required string HowItWorks { get; init; }       // mechanics of the attack
    public required string WhyTheFixWorks { get; init; }    // mechanics of the defense
    public required IReadOnlyList<string> SamplePayloads { get; init; }

    /// <summary>Where this attack's name comes from — the term itself, not its mechanics (that's
    /// HowItWorks). Every scenario has one, same as every scenario has at least one reference.</summary>
    public required string TerminologyNote { get; init; }

    /// <summary>Independent, external sources backing this scenario's terminology and claims —
    /// OWASP, PortSwigger, vendor docs, or the original academic literature, never just this app.</summary>
    public required IReadOnlyList<ExternalReference> References { get; init; }

    // ---- Try-it-yourself mode ----
    public string? ChallengeGoal { get; init; }             // "Make the login succeed without a valid password"
    public IReadOnlyList<string>? Hints { get; init; }       // progressively revealing
    public string? ChallengeAnswer { get; init; }
}
