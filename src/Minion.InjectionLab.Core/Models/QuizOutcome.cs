namespace Minion.InjectionLab.Core.Models;

/// <summary>The result of grading one submitted payload against a QuizMission — rule-based, same
/// as every other classification in this app, never a real database evaluating anything.</summary>
public sealed class QuizOutcome
{
    public required bool Succeeded { get; init; }
    public required string Headline { get; init; }
    public required string Detail { get; init; }

    /// <summary>New facts this submission revealed (e.g. a discovered table or column name) —
    /// accumulated by the view model across attempts within the same mission.</summary>
    public IReadOnlyList<string>? NewlyDiscovered { get; init; }
}
