using System.Reflection;
using System.Windows;

namespace Minion.InjectionLab.Wpf;

public partial class AboutWindow : Window
{
    public AboutWindow()
    {
        InitializeComponent();
        var version = Assembly.GetExecutingAssembly().GetName().Version;
        VersionText.Text = version is null ? string.Empty : $"v{version.Major}.{version.Minor}.{version.Build}";
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();
}
