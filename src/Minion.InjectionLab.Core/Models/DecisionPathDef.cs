namespace Minion.InjectionLab.Core.Models;

/// <summary>
/// One branch in the "decision path" diagram (e.g. "Correct credentials", "Wrong password",
/// "SQL injection pattern"). The scenario's ClassifyInput function decides which Key is live
/// as the user types, and the view highlights that branch.
/// </summary>
public sealed class DecisionPathDef
{
    public required string Key { get; init; }
    public required string Label { get; init; }
    public required string Icon { get; init; }      // emoji, keeps it dependency-free
    public required PathKind Kind { get; init; }
}
