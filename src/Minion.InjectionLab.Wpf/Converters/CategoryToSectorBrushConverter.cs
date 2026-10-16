using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Wpf.Converters;

/// <summary>Maps an AttackCategory to its Mission-select "sector" brush.</summary>
public sealed class CategoryToSectorBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
    {
        var key = value switch
        {
            AttackCategory.ClassicInBand => "Brush.SectorClassic",
            AttackCategory.BlindInferential => "Brush.SectorBlind",
            AttackCategory.IdentifiersAndDynamicSql => "Brush.SectorParamsDontHelp",
            AttackCategory.DeliveryObfuscation => "Brush.SectorDeliveryObfuscation",
            AttackCategory.OutOfBand => "Brush.SectorOutOfBand",
            AttackCategory.PostInjectionImpact => "Brush.SectorPostInjection",
            AttackCategory.SqlServerAgentAndJobs => "Brush.SectorSqlAgent",
            _ => "Brush.TextMuted"
        };
        return Application.Current.FindResource(key);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
