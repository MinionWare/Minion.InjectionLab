using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Windows.Media;
using System.Xml;
using ICSharpCode.AvalonEdit.Highlighting;
using ICSharpCode.AvalonEdit.Highlighting.Xshd;

namespace Minion.InjectionLab.Wpf.Services;

/// <summary>
/// Loads this app's own minimal syntax-highlighting definitions (SQL, C#, PowerShell) from
/// embedded .xshd resources, rather than relying on AvalonEdit's bundled definitions — this
/// guarantees all three code tabs use the same comment/string/keyword palette, and that SQL
/// (which AvalonEdit doesn't ship a definition for at all) is covered too.
///
/// The .xshd files only ever define one fixed palette (tuned for the dark theme) — AvalonEdit's
/// highlighting colors aren't WPF DynamicResources, so they don't react to ThemeService on their
/// own. ApplyTheme patches each named color's Foreground in place to a per-theme palette instead
/// of maintaining two parallel .xshd files.
/// </summary>
public static class CodeHighlightingLoader
{
    private static IHighlightingDefinition? _sql;
    private static IHighlightingDefinition? _csharp;
    private static IHighlightingDefinition? _powerShell;

    public static IHighlightingDefinition Sql => _sql ??= Load("SqlHighlighting.xshd", "SQL", ".sql");
    public static IHighlightingDefinition CSharp => _csharp ??= Load("CSharpHighlighting.xshd", "MinionCSharp", ".cs");
    public static IHighlightingDefinition PowerShell => _powerShell ??= Load("PowerShellHighlighting.xshd", "MinionPowerShell", ".ps1");

    private static readonly Dictionary<string, Color> DarkPalette = new()
    {
        ["Comment"] = Color.FromRgb(0x6A, 0x99, 0x55),
        ["String"] = Color.FromRgb(0xCE, 0x91, 0x78),
        ["Keyword"] = Color.FromRgb(0x56, 0x9C, 0xD6),
        ["Type"] = Color.FromRgb(0x4E, 0xC9, 0xB0),
        ["Parameter"] = Color.FromRgb(0x9C, 0xDC, 0xFE),
        ["Variable"] = Color.FromRgb(0x9C, 0xDC, 0xFE),
        ["Number"] = Color.FromRgb(0xB5, 0xCE, 0xA8),
    };

    private static readonly Dictionary<string, Color> LightPalette = new()
    {
        ["Comment"] = Color.FromRgb(0x00, 0x80, 0x00),
        ["String"] = Color.FromRgb(0xA3, 0x15, 0x15),
        ["Keyword"] = Color.FromRgb(0x00, 0x00, 0xFF),
        ["Type"] = Color.FromRgb(0x26, 0x7F, 0x99),
        ["Parameter"] = Color.FromRgb(0x5C, 0x26, 0x99),
        ["Variable"] = Color.FromRgb(0x5C, 0x26, 0x99),
        ["Number"] = Color.FromRgb(0x09, 0x86, 0x58),
    };

    public static void ApplyTheme(AppTheme theme)
    {
        var palette = theme == AppTheme.Dark ? DarkPalette : LightPalette;
        foreach (var definition in new[] { Sql, CSharp, PowerShell })
        foreach (var named in definition.NamedHighlightingColors)
            if (palette.TryGetValue(named.Name, out var color))
                named.Foreground = new SimpleHighlightingBrush(color);
    }

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
