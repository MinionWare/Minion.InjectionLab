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

    /// <summary>Plain-English narration of what that SQL would actually do.</summary>
    public required Func<string, string> Explain { get; init; }

    /// <summary>Whether the current input achieves the attack this step is teaching.</summary>
    public required Func<string, bool> IsDangerous { get; init; }

    public string? Hint { get; init; }
}
