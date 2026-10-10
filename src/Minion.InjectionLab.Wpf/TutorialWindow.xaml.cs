using System.Windows;
using Minion.InjectionLab.Wpf.ViewModels;

namespace Minion.InjectionLab.Wpf;

public partial class TutorialWindow : Window
{
    public TutorialWindow()
    {
        InitializeComponent();
        var viewModel = new TutorialViewModel();
        viewModel.CloseRequested += (_, _) => Close();
        DataContext = viewModel;
    }
}
