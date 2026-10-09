namespace Minion.InjectionLab.Core.Models;

/// <summary>
/// One input box on the right-hand scenario form (e.g. "Username", "Product search").
/// </summary>
public sealed class FormField
{
    public required string Key { get; init; }          // dictionary key used by the builders
    public required string Label { get; init; }
    public string? Placeholder { get; init; }
    public string DefaultValue { get; init; } = string.Empty;
    public bool IsMultiline { get; init; }
    public bool IsPassword { get; init; }
}
