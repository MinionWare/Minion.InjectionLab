using System;
using System.Linq;
using System.Windows;

namespace Minion.InjectionLab.Wpf.Services;

public enum AppTheme { Dark, Light }

/// <summary>
/// Swaps the Colors.*.xaml dictionary at runtime. Brushes.xaml uses DynamicResource,
/// so every bound control repaints the instant the dictionary is replaced.
/// </summary>
public static class ThemeService
{
    public static AppTheme Current { get; private set; } = AppTheme.Dark;

    public static void Apply(AppTheme theme)
    {
        var dictionaries = Application.Current.Resources.MergedDictionaries;
        var colorDictUri = theme == AppTheme.Dark
            ? "Themes/Colors.Neon.xaml"
            : "Themes/Colors.Light.xaml";

        var existing = dictionaries.FirstOrDefault(d =>
            d.Source != null && d.Source.OriginalString.Contains("Colors."));

        var replacement = new ResourceDictionary { Source = new Uri(colorDictUri, UriKind.Relative) };

        if (existing != null)
        {
            int index = dictionaries.IndexOf(existing);
            dictionaries.RemoveAt(index);
            dictionaries.Insert(index, replacement);
        }
        else
        {
            dictionaries.Insert(0, replacement);
        }

        Current = theme;
    }

    public static void Toggle() => Apply(Current == AppTheme.Dark ? AppTheme.Light : AppTheme.Dark);
}
