using System;
using System.Globalization;
using System.Windows.Data;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Wpf.Converters;

/// <summary>Friendly group-header text for AttackCategory, used by the left-nav grouping.</summary>
public sealed class CategoryDisplayConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
        => value switch
        {
            AttackCategory.ClassicInBand => "Classic / In-Band",
            AttackCategory.BlindInferential => "Blind / Inferential",
            AttackCategory.OutOfBand => "Out-of-Band",
            AttackCategory.DeliveryObfuscation => "Delivery & Obfuscation",
            AttackCategory.IdentifiersAndDynamicSql => "Where Parameters Don't Help",
            AttackCategory.PostInjectionImpact => "Post-Injection Impact",
            AttackCategory.SqlServerAgentAndJobs => "SQL Server Agent & Jobs",
            AttackCategory.NonSqlInjection => "Non-SQL Injection",
            _ => value?.ToString() ?? string.Empty
        };

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
