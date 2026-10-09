using System;
using System.Globalization;
using System.Windows.Data;

namespace Minion.InjectionLab.Wpf.Converters;

/// <summary>Binds IsChecked="{Binding SomeEnum, Converter=..., ConverterParameter=Value}" for segmented toggles.</summary>
public sealed class EnumEqualsConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
        => value?.ToString() == parameter?.ToString();

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
