using System.ComponentModel;
using System.Windows;
using System.Windows.Data;
using Minion.InjectionLab.Wpf.Converters;
using Minion.InjectionLab.Wpf.Services;
using Minion.InjectionLab.Wpf.ViewModels;

namespace Minion.InjectionLab.Wpf;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        var viewModel = new MainViewModel();
        DataContext = viewModel;

        SqlEditor.SyntaxHighlighting = CodeHighlightingLoader.Sql;
        CSharpEditor.SyntaxHighlighting = CodeHighlightingLoader.CSharp;
        PowerShellEditor.SyntaxHighlighting = CodeHighlightingLoader.PowerShell;

        // Group the left-nav list by category, on the same default view the ListBox's own
        // {Binding Attacks} ends up using.
        var view = CollectionViewSource.GetDefaultView(viewModel.Attacks);
        view.GroupDescriptions.Add(new PropertyGroupDescription("Scenario.Category", new CategoryDisplayConverter()));
    }
}
