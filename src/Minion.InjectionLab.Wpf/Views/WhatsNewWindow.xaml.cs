using System.Windows;

namespace Minion.InjectionLab.Wpf.Views;

public partial class WhatsNewWindow : Window
{
    private readonly string _downloadUrl;

    public WhatsNewWindow(string version, string[] features, string downloadUrl)
    {
        InitializeComponent();
        _downloadUrl = downloadUrl;
        TxVersion.Text = $"v{version}";
        FeatureList.ItemsSource = features;
    }

    private void Download_Click(object sender, RoutedEventArgs e)
    {
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(_downloadUrl) { UseShellExecute = true });
        Close();
    }

    private void Later_Click(object sender, RoutedEventArgs e) => Close();
}
