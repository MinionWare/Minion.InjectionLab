using System.IO;
using System.Reflection;
using System.Xml;
using ICSharpCode.AvalonEdit.Highlighting;
using ICSharpCode.AvalonEdit.Highlighting.Xshd;

namespace Minion.InjectionLab.Wpf.Services;

/// <summary>
/// Loads this app's own minimal syntax-highlighting definitions (SQL, C#, PowerShell) from
/// embedded .xshd resources, rather than relying on AvalonEdit's bundled definitions — this
/// guarantees all three code tabs use the same comment/string/keyword palette, and that SQL
/// (which AvalonEdit doesn't ship a definition for at all) is covered too.
/// </summary>
public static class CodeHighlightingLoader
{
    private static IHighlightingDefinition? _sql;
    private static IHighlightingDefinition? _csharp;
    private static IHighlightingDefinition? _powerShell;

    public static IHighlightingDefinition Sql => _sql ??= Load("SqlHighlighting.xshd", "SQL", ".sql");
    public static IHighlightingDefinition CSharp => _csharp ??= Load("CSharpHighlighting.xshd", "MinionCSharp", ".cs");
    public static IHighlightingDefinition PowerShell => _powerShell ??= Load("PowerShellHighlighting.xshd", "MinionPowerShell", ".ps1");

    private static IHighlightingDefinition Load(string fileName, string registeredName, string extension)
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resourceName = $"Minion.InjectionLab.Wpf.Resources.{fileName}";

        using var stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new FileNotFoundException($"Embedded resource not found: {resourceName}");
        using var reader = new XmlTextReader(stream);

        var definition = HighlightingLoader.Load(reader, HighlightingManager.Instance);
        HighlightingManager.Instance.RegisterHighlighting(registeredName, new[] { extension }, definition);
        return definition;
    }
}
