using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Wpf.Converters;

/// <summary>Maps a decision-path's PathKind to the theme brush used to highlight it when active.</summary>
public sealed class PathKindToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
    {
        var key = value switch
        {
            PathKind.Safe => "Brush.Accent",
            PathKind.Malicious => "Brush.Critical",
            _ => "Brush.Warning"
        };
        return Application.Current.FindResource(key);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
