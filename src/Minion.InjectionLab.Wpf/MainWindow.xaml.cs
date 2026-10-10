using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Data;
using System.Windows.Navigation;
using ICSharpCode.AvalonEdit;
using Minion.InjectionLab.Wpf.Behaviors;
using Minion.InjectionLab.Wpf.Converters;
using Minion.InjectionLab.Wpf.Services;
using Minion.InjectionLab.Wpf.ViewModels;

namespace Minion.InjectionLab.Wpf;

public partial class MainWindow : Window
{
    private AttackViewModel? _trackedAttack;

    public MainWindow()
    {
        InitializeComponent();

        // Height/Width in XAML are a preferred starting size, not a guarantee — on a screen whose
        // work area is shorter (smaller display, taskbar, scaling), CenterScreen would otherwise
        // center a too-tall window so its top sits above y=0, off-screen. Clamp to what actually fits.
        var workArea = SystemParameters.WorkArea;
        Height = Math.Min(Height, workArea.Height);
        Width = Math.Min(Width, workArea.Width);

        var viewModel = new MainViewModel();
        DataContext = viewModel;

        SqlEditor.SyntaxHighlighting = CodeHighlightingLoader.Sql;
        CSharpEditor.SyntaxHighlighting = CodeHighlightingLoader.CSharp;
        PowerShellEditor.SyntaxHighlighting = CodeHighlightingLoader.PowerShell;

        // Group the left-nav list by category, on the same default view the ListBox's own
        // {Binding Attacks} ends up using.
        var view = CollectionViewSource.GetDefaultView(viewModel.Attacks);
        view.GroupDescriptions.Add(new PropertyGroupDescription("Scenario.Category", new CategoryDisplayConverter()));

        // The three code editors are driven explicitly from code-behind rather than XAML data
        // binding to a custom attached property — AvalonEdit's TextEditor has no bindable Text
        // dependency property, and binding through a custom one proved unreliable (blank/stale
        // text on scenario or fix-tab changes; see docs.md). Direct, explicit assignment removes
        // the ambiguity entirely.
        viewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(MainViewModel.SelectedAttack) or null)
                TrackAttack(viewModel.SelectedAttack);
        };
        TrackAttack(viewModel.SelectedAttack);

        Loaded += (_, _) =>
        {
            if (!TutorialService.HasSeenTutorial)
                ShowTutorial();
        };
    }

    private void TutorialButton_Click(object sender, RoutedEventArgs e) => ShowTutorial();

    private void ShowTutorial()
    {
        var tutorial = new TutorialWindow { Owner = this };
        tutorial.Closed += (_, _) => TutorialService.MarkSeen();
        tutorial.ShowDialog();
    }

    private void ExitMenuItem_Click(object sender, RoutedEventArgs e) => Close();

    private void AboutMenuItem_Click(object sender, RoutedEventArgs e)
        => new AboutWindow { Owner = this }.ShowDialog();

    private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        e.Handled = true;
    }

    private void TrackAttack(AttackViewModel? attack)
    {
        if (_trackedAttack != null)
            _trackedAttack.PropertyChanged -= OnAttackPropertyChanged;

        _trackedAttack = attack;

        if (_trackedAttack != null)
            _trackedAttack.PropertyChanged += OnAttackPropertyChanged;

        SyncCodePanes();
    }

    private void OnAttackPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(AttackViewModel.GeneratedSql)
            or nameof(AttackViewModel.GeneratedCSharp)
            or nameof(AttackViewModel.GeneratedPowerShell)
            or nameof(AttackViewModel.SqlSegments)
            or nameof(AttackViewModel.CSharpSegments)
            or nameof(AttackViewModel.PowerShellSegments)
            or null)
        {
            SyncCodePanes();
        }
    }

    private void SyncCodePanes()
    {
        var attack = _trackedAttack;
        SetEditor(SqlEditor, attack?.GeneratedSql, attack?.SqlSegments);
        SetEditor(CSharpEditor, attack?.GeneratedCSharp, attack?.CSharpSegments);
        SetEditor(PowerShellEditor, attack?.GeneratedPowerShell, attack?.PowerShellSegments);
    }

    private static void SetEditor(TextEditor editor, string? text, ObservableCollection<SqlSegment>? segments)
    {
        var newText = text ?? string.Empty;
        if (editor.Document.Text != newText)
            editor.Document.Text = newText;

        AvalonEditBehavior.SetHighlightSegments(editor, segments ?? new ObservableCollection<SqlSegment>());
    }
}
