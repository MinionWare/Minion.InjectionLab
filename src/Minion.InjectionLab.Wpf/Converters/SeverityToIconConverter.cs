using System;
using System.Globalization;
using System.Windows.Data;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Wpf.Converters;

public sealed class SeverityToIconConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
        => value switch
        {
            Severity.Success => "✅",
            Severity.Critical => "🔓",
            Severity.Warning => "⚠",
            Severity.Blocked => "🛡",
            _ => "ℹ"
        };

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
