using System;
using System.Collections;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace Minion.InjectionLab.Wpf.Converters;

/// <summary>Visible when the bound string/collection is non-null and non-empty (used to hide
/// code tabs or compound-attack panels a scenario hasn't filled in yet).</summary>
public sealed class NotEmptyToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
    {
        bool hasContent = value switch
        {
            null => false,
            string s => s.Length > 0,
            ICollection c => c.Count > 0,
            IEnumerable e => e.GetEnumerator().MoveNext(),
            _ => true
        };
        return hasContent ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
