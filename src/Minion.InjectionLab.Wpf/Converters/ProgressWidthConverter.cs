using System;
using System.Globalization;
using System.Windows.Data;

namespace Minion.InjectionLab.Wpf.Converters;

/// <summary>[cleared, total] -> a pixel width against a fixed-width track, given as ConverterParameter
/// (defaults to 170, the top bar's CLEARED track — pass a different parameter for other tracks).</summary>
public sealed class ProgressWidthConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
    {
        if (values is not [int cleared, int total] || total <= 0) return 0.0;
        var trackWidth = parameter is string s && double.TryParse(s, out var w) ? w : 170;
        return trackWidth * Math.Clamp((double)cleared / total, 0, 1);
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
