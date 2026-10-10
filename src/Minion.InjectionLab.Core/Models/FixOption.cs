namespace Minion.InjectionLab.Core.Models;

/// <summary>
/// One real-world fix for a scenario's vulnerability. Some attacks have exactly one solid fix
/// (parameterize it, done); others have several people actually reach for in practice, not all
/// equally complete — this lets a scenario show them side by side instead of pretending there's
/// only ever one "the fix".
/// </summary>
public sealed class FixOption
{
    public required string Label { get; init; }
    public required FixGrade Grade { get; init; }

    /// <summary>What this fix still doesn't cover — null/empty for a Best-grade fix with no known gap.</summary>
    public string? Gap { get; init; }

    public required Func<IReadOnlyDictionary<string, string>, string> BuildSql { get; init; }
    public required Func<IReadOnlyDictionary<string, string>, SimulationResult> Simulate { get; init; }

    public Func<IReadOnlyDictionary<string, string>, string>? BuildCSharp { get; init; }
    public Func<IReadOnlyDictionary<string, string>, string>? BuildPowerShell { get; init; }
}
