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

    /// <summary>Builds the parameterized/defended equivalent (SQL text + how params bind).</summary>
    public required Func<IReadOnlyDictionary<string, string>, string> BuildFixedSql { get; init; }

    /// <summary>Rule-based narration of what the vulnerable version would do with this input.</summary>
    public required Func<IReadOnlyDictionary<string, string>, SimulationResult> SimulateVulnerable { get; init; }

    /// <summary>Rule-based narration of what the fixed version does with the same input.</summary>
    public required Func<IReadOnlyDictionary<string, string>, SimulationResult> SimulateFixed { get; init; }

    public required string HowItWorks { get; init; }       // mechanics of the attack
    public required string WhyTheFixWorks { get; init; }    // mechanics of the defense
    public required IReadOnlyList<string> SamplePayloads { get; init; }

    // ---- Try-it-yourself mode ----
    public string? ChallengeGoal { get; init; }             // "Make the login succeed without a valid password"
    public IReadOnlyList<string>? Hints { get; init; }       // progressively revealing
    public string? ChallengeAnswer { get; init; }
}
