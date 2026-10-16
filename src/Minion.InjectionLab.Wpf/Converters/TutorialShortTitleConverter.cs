using System;
using System.Globalization;
using System.Text.RegularExpressions;
using System.Windows.Data;

namespace Minion.InjectionLab.Wpf.Converters;

/// <summary>Training step bar pills need a short title — strips a leading "Technique n: " prefix,
/// then cuts at the first " — " or ":" so a long step title fits a narrow pill.</summary>
public sealed class TutorialShortTitleConverter : IValueConverter
{
    private static readonly Regex TechniquePrefix = new(@"^Technique\s+\d+:\s*", RegexOptions.Compiled);

    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
    {
        var title = value as string ?? string.Empty;
        title = TechniquePrefix.Replace(title, string.Empty);

        var dashIndex = title.IndexOf(" — ", StringComparison.Ordinal);
        var colonIndex = title.IndexOf(':');
        var cut = dashIndex >= 0 && colonIndex >= 0 ? Math.Min(dashIndex, colonIndex) : Math.Max(dashIndex, colonIndex);
        return cut >= 0 ? title[..cut] : title;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
