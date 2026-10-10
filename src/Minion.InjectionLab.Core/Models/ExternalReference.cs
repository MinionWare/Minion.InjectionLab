namespace Minion.InjectionLab.Core.Models;

/// <summary>A citation to an independent, external source — so a reader can check this app's
/// terminology and claims against something other than this app's own say-so.</summary>
public sealed class ExternalReference
{
    public required string Label { get; init; }
    public required string Url { get; init; }
}
