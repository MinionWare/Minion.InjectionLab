using System;
using System.Globalization;
using System.Windows.Data;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Wpf.Converters;

/// <summary>Maps a simulation Severity to the short verdict tag shown in the Mission screen's
/// Verdict column ("BREACH", "BLOCKED", etc.) — color comes separately from SeverityToBrushConverter.</summary>
public sealed class SeverityToTagConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
        => value switch
        {
            Severity.Critical => "BREACH",
            Severity.Warning => "SQL ERROR",
            Severity.Blocked => "BLOCKED",
            Severity.Success => "SIGNED IN",
            Severity.Info => "DENIED",
            _ => string.Empty
        };

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
