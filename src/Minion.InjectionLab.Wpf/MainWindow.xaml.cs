using System.Windows;
using Minion.InjectionLab.Wpf.ViewModels;

namespace Minion.InjectionLab.Wpf;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainViewModel();
    }
}
