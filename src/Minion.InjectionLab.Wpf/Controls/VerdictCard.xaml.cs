using System.Windows;
using System.Windows.Controls;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Wpf.Controls;

/// <summary>The one "what just happened" result card — see VerdictCard.xaml for why this is
/// shared between the attack catalog and the Training wizard instead of each page having its
/// own copy.</summary>
public partial class VerdictCard : UserControl
{
    public static readonly DependencyProperty ResultProperty =
        DependencyProperty.Register(nameof(Result), typeof(SimulationResult), typeof(VerdictCard));

    public static readonly DependencyProperty HeaderTextProperty =
        DependencyProperty.Register(nameof(HeaderText), typeof(string), typeof(VerdictCard), new PropertyMetadata("VERDICT"));

    public SimulationResult? Result { get => (SimulationResult?)GetValue(ResultProperty); set => SetValue(ResultProperty, value); }
    public string HeaderText { get => (string)GetValue(HeaderTextProperty); set => SetValue(HeaderTextProperty, value); }

    public VerdictCard() => InitializeComponent();
}
