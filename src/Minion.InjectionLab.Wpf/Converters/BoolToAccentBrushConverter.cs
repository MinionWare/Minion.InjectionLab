using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace Minion.InjectionLab.Wpf.Converters;

/// <summary>True → Brush.Accent, False → Brush.Border. Used for the tutorial's progress dots.</summary>
public sealed class BoolToAccentBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
        => Application.Current.FindResource(value is true ? "Brush.Accent" : "Brush.Border");

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
