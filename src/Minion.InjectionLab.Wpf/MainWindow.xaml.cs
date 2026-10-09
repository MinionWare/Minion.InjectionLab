using System.Windows;
using Minion.InjectionLab.Wpf.Services;
using Minion.InjectionLab.Wpf.ViewModels;

namespace Minion.InjectionLab.Wpf;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainViewModel();

        SqlEditor.SyntaxHighlighting = CodeHighlightingLoader.Sql;
        CSharpEditor.SyntaxHighlighting = CodeHighlightingLoader.CSharp;
        PowerShellEditor.SyntaxHighlighting = CodeHighlightingLoader.PowerShell;
    }
}
