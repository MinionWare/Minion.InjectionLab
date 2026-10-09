using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace Minion.InjectionLab.Wpf.Converters;

/// <summary>Pass parameter "Invert" to flip true/false.</summary>
public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
    {
        bool b = value is bool v && v;
        if (string.Equals(parameter as string, "Invert", StringComparison.OrdinalIgnoreCase))
            b = !b;
        return b ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
