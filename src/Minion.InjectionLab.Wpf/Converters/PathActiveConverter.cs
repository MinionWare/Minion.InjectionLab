using System;
using System.Globalization;
using System.Windows.Data;

namespace Minion.InjectionLab.Wpf.Converters;

/// <summary>MultiBinding: [0]=this branch's Key, [1]=the AttackViewModel's ActivePathKey. True when they match.</summary>
public sealed class PathActiveConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        => values.Length == 2 && Equals(values[0], values[1]);

    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
