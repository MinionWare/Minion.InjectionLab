using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Wpf.Converters;

public sealed class SeverityToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
    {
        var key = value switch
        {
            Severity.Success => "Brush.Accent",
            Severity.Blocked => "Brush.Blocked",
            Severity.Warning => "Brush.Warning",
            Severity.Critical => "Brush.Critical",
            _ => "Brush.Info"
        };
        return Application.Current.FindResource(key);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
