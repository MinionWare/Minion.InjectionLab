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

        ReplaceDictionary(dictionaries, uriSubstring: "Colors.", newUri: colorDictUri);

        // Brushes.xaml wraps each color in a SolidColorBrush via {DynamicResource Color.X} —
        // DynamicResource used on a resource's own property (rather than directly on a live UI
        // element) doesn't reliably re-resolve when the dictionary it points at changes; the brush
        // objects everything actually binds to were staying frozen at their original colors. The
        // fix is to force Brushes.xaml itself to re-parse now that the new Colors dictionary is
        // already in place, so its brushes resolve against it fresh.
        ReplaceDictionary(dictionaries, uriSubstring: "Brushes.xaml", newUri: "Themes/Brushes.xaml");

        Current = theme;
    }

    private static void ReplaceDictionary(System.Collections.ObjectModel.Collection<ResourceDictionary> dictionaries, string uriSubstring, string newUri)
    {
        var existing = dictionaries.FirstOrDefault(d =>
            d.Source != null && d.Source.OriginalString.Contains(uriSubstring));
        var replacement = new ResourceDictionary { Source = new Uri(newUri, UriKind.Relative) };

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
    }

    public static void Toggle() => Apply(Current == AppTheme.Dark ? AppTheme.Light : AppTheme.Dark);
}
