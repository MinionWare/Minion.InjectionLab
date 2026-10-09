using System.Windows;
using ICSharpCode.AvalonEdit.Highlighting;
using Minion.InjectionLab.Wpf.Services;
using Minion.InjectionLab.Wpf.ViewModels;

namespace Minion.InjectionLab.Wpf;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainViewModel();

        SqlEditor.SyntaxHighlighting = SqlHighlightingLoader.Sql;
        CSharpEditor.SyntaxHighlighting = HighlightingManager.Instance.GetDefinition("C#");
        PowerShellEditor.SyntaxHighlighting = HighlightingManager.Instance.GetDefinition("PowerShell");
    }
}
