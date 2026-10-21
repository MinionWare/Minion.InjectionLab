using System.Windows;

namespace Minion.InjectionLab.Wpf.Services;

/// <summary>Attached property so any XAML "?" help icon can just declare which article it opens,
/// without a separate Click handler per button — see MainWindow.xaml.cs's single HelpIcon_Click.</summary>
public static class Help
{
    public static readonly DependencyProperty IdProperty =
        DependencyProperty.RegisterAttached("Id", typeof(string), typeof(Help));

    public static void SetId(DependencyObject element, string value) => element.SetValue(IdProperty, value);
    public static string? GetId(DependencyObject element) => (string?)element.GetValue(IdProperty);
}
