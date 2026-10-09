using System.IO;
using System.Reflection;
using System.Xml;
using ICSharpCode.AvalonEdit.Highlighting;
using ICSharpCode.AvalonEdit.Highlighting.Xshd;

namespace Minion.InjectionLab.Wpf.Services;

/// <summary>
/// AvalonEdit ships built-in highlighting for C# and PowerShell, but not SQL — this loads our
/// own minimal .xshd (comments, strings, @parameters, T-SQL keywords) and registers it once.
/// </summary>
public static class SqlHighlightingLoader
{
    private static IHighlightingDefinition? _sql;

    public static IHighlightingDefinition Sql => _sql ??= Load();

    private static IHighlightingDefinition Load()
    {
        var assembly = Assembly.GetExecutingAssembly();
        const string resourceName = "Minion.InjectionLab.Wpf.Resources.SqlHighlighting.xshd";

        using var stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new FileNotFoundException($"Embedded resource not found: {resourceName}");
        using var reader = new XmlTextReader(stream);

        var definition = HighlightingLoader.Load(reader, HighlightingManager.Instance);
        HighlightingManager.Instance.RegisterHighlighting("SQL", new[] { ".sql" }, definition);
        return definition;
    }
}
