using System.Windows;
using Minion.InjectionLab.Wpf.ViewModels;

namespace Minion.InjectionLab.Wpf;

public partial class QuizWindow : Window
{
    public QuizWindow()
    {
        InitializeComponent();
        DataContext = new QuizViewModel();
    }
}
