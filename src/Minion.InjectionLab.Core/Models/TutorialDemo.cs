namespace Minion.InjectionLab.Core.Models;

/// <summary>
/// A tiny, self-contained live example embedded in one tutorial step: the reader types into a
/// single field and immediately sees the raw SQL it produces and a plain-English read of what
/// just happened. Deliberately simpler than a full AttackScenario — the tutorial teaches the
/// underlying concept once; the attack catalog covers each technique's full specifics.
/// </summary>
public sealed class TutorialDemo
{
    public required string FieldLabel { get; init; }
    public required string DefaultValue { get; init; }

    /// <summary>The raw, concatenated SQL a naive app would build from this input.</summary>
    public required Func<string, string> BuildSql { get; init; }

    /// <summary>Rule-based narration of what the current input does — same shape as
    /// AttackScenario.SimulateVulnerable, so the Training wizard and the attack catalog render
    /// through the one shared VerdictCard instead of each inventing its own result box. The bool
    /// is whether BuildSql(input) parses as valid T-SQL (via ScriptDom) — always computed by the
    /// caller before Simulate runs, never something a step can forget to check, so a step that
    /// doesn't itself call SqlSyntaxChecker still can't misreport broken SQL as an ordinary result.</summary>
    public required Func<string, bool, SimulationResult> Simulate { get; init; }

    public string? Hint { get; init; }
}
