using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Wpf.Converters;

/// <summary>Maps a defense tile's grade to its color — Partial amber, Best green, Good (and the
/// base/vulnerable case) the neutral accent, mirroring FixGradeToTabStyleConverter's mapping.</summary>
public sealed class GradeToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
    {
        var key = value switch
        {
            FixGrade.Partial => "Brush.Warning",
            FixGrade.Best => "Brush.Blocked",
            _ => "Brush.Accent"
        };
        return Application.Current.FindResource(key);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
