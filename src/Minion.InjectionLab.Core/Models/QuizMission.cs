namespace Minion.InjectionLab.Core.Models;

/// <summary>
/// A capstone challenge: unlike per-attack Challenge Mode (one fixed goal, one canonical answer),
/// a mission accepts ANY payload shape that genuinely achieves the stated goal — open-ended
/// grading, same as a real pentest, just rule-based instead of a live database.
/// </summary>
public sealed class QuizMission
{
    public required string Id { get; init; }
    public required QuizDifficulty Difficulty { get; init; }
    public required string Title { get; init; }
    public required string Briefing { get; init; }
    public required string Goal { get; init; }
    public required IReadOnlyList<FormField> Fields { get; init; }
    public required IReadOnlyDictionary<string, string> BaselineValues { get; init; }

    public required Func<IReadOnlyDictionary<string, string>, string> BuildSql { get; init; }
    public Func<IReadOnlyDictionary<string, string>, string>? BuildCSharp { get; init; }
    public Func<IReadOnlyDictionary<string, string>, string>? BuildPowerShell { get; init; }

    /// <summary>Graded against the submitted values AND everything discovered so far this attempt
    /// (recon facts from earlier submissions, for Expert-tier multi-stage missions).</summary>
    public required Func<IReadOnlyDictionary<string, string>, IReadOnlySet<string>, QuizOutcome> Evaluate { get; init; }

    public IReadOnlyList<string>? Hints { get; init; }
}
