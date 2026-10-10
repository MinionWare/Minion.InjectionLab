using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Wpf.Converters;

/// <summary>Picks the red/amber/green TabItem.Code.* style for a fix tab header, based on how
/// good that fix actually is — so the color itself is part of the grading, not just the label text.</summary>
public sealed class FixGradeToTabStyleConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
    {
        var key = value is FixGrade grade
            ? grade switch
            {
                FixGrade.Partial => "TabItem.Code.Partial",
                FixGrade.Best => "TabItem.Code.Best",
                _ => "TabItem.Code"
            }
            : "TabItem.Code";
        return Application.Current.FindResource(key);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
