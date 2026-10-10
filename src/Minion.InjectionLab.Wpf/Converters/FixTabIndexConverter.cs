using System;
using System.Globalization;
using System.Windows.Data;

namespace Minion.InjectionLab.Wpf.Converters;

/// <summary>Maps AttackViewModel.CurrentFixIndex (-1 = vulnerable, 0..N-1 = Fixes[i]) to/from a
/// TabControl.SelectedIndex (0 = vulnerable, 1..N = Fixes[i]) for the fix-comparison tab strip.</summary>
public sealed class FixTabIndexConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
        => (value is int i ? i : -1) + 1;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => (value is int i ? i : 0) - 1;
}
