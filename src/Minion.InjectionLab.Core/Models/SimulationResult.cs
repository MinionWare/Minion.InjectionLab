namespace Minion.InjectionLab.Core.Models;

/// <summary>
/// The outcome shown under "What the engine sees" / "What happens". This is always
/// produced by scenario-specific, rule-based narration — the app never opens a real
/// connection or executes anything against a database.
/// </summary>
public sealed class SimulationResult
{
    public required Severity Severity { get; init; }
    public required string Headline { get; init; }      // e.g. "Authentication bypassed"
    public required string Detail { get; init; }         // longer explanation of what the engine would do
}
