using System;
using System.Globalization;
using System.Windows.Data;

namespace Minion.InjectionLab.Wpf.Converters;

/// <summary>Guesses a reference's "kind" label (Intel panel Sources tab) from its URL's domain.</summary>
public sealed class UrlToSourceKindConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
    {
        var url = value as string ?? string.Empty;
        return url switch
        {
            _ when url.Contains("portswigger.net", StringComparison.OrdinalIgnoreCase) => "TRAINING",
            _ when url.Contains(".edu/", StringComparison.OrdinalIgnoreCase) => "ACADEMIC",
            _ when url.Contains("dl.acm.org", StringComparison.OrdinalIgnoreCase) => "ACADEMIC",
            _ when url.Contains("usenix.org", StringComparison.OrdinalIgnoreCase) => "ACADEMIC",
            _ when url.Contains("arxiv.org", StringComparison.OrdinalIgnoreCase) => "ACADEMIC",
            _ => "STANDARD"
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
