namespace Minion.InjectionLab.Core.Models;

/// <summary>One screen of the opening wizard: a title, a few paragraphs of narration, and an
/// optional live interactive demo.</summary>
public sealed class TutorialStep
{
    public required string Title { get; init; }
    public required IReadOnlyList<string> Paragraphs { get; init; }
    public TutorialDemo? Demo { get; init; }
}
