using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Navigation;
using ICSharpCode.AvalonEdit;
using Minion.InjectionLab.Wpf.Behaviors;
using Minion.InjectionLab.Wpf.Converters;
using Minion.InjectionLab.Wpf.Services;
using Minion.InjectionLab.Wpf.ViewModels;
using Minion.Licensing.Updates;

namespace Minion.InjectionLab.Wpf;

public partial class MainWindow : Window
{
    private AttackViewModel? _trackedAttack;
    private readonly UpdateCheckService _updateCheckService = new("Minion.InjectionLab");
    private UpdateManifest? _pendingUpdateManifest;

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

            // Replays every time the welcome screen comes back (not just the very first time the
            // window loads) — e.g. after clicking the app icon/title in the nav to come "home".
            if (e.PropertyName is nameof(MainViewModel.HasSelectedAttack) or null && !viewModel.HasSelectedAttack)
                PlayWelcomeIntro();
        };
        TrackAttack(viewModel.SelectedAttack);

        Loaded += (_, _) =>
        {
            if (!viewModel.HasSelectedAttack)
                PlayWelcomeIntro();

            _ = CheckForUpdatesAsync();
        };
    }

    private void HomeButton_Click(object sender, RoutedEventArgs e) => ((MainViewModel)DataContext).SelectedAttack = null;

    private void PlayWelcomeIntro()
    {
        AnimatePopIn(WelcomeIconGrid, TimeSpan.Zero);
        AnimatePopIn(WelcomeLogoButton, TimeSpan.FromSeconds(0.35));
        AnimateFadeIn(WelcomeTitleStack, TimeSpan.FromSeconds(0.85));
    }

    private static void AnimatePopIn(FrameworkElement element, TimeSpan delay)
    {
        element.BeginAnimation(UIElement.OpacityProperty, null);
        element.Opacity = 0;

        var opacity = new DoubleAnimation(0, 1, TimeSpan.FromSeconds(1.0)) { BeginTime = delay };
        element.BeginAnimation(UIElement.OpacityProperty, opacity);

        if (element.RenderTransform is ScaleTransform scale)
        {
            scale.BeginAnimation(ScaleTransform.ScaleXProperty, null);
            scale.BeginAnimation(ScaleTransform.ScaleYProperty, null);
            scale.ScaleX = scale.ScaleY = 0.3;

            var easing = new BackEase { EasingMode = EasingMode.EaseOut, Amplitude = 0.6 };
            var grow = new DoubleAnimation(0.3, 1, TimeSpan.FromSeconds(1.4)) { BeginTime = delay, EasingFunction = easing };
            scale.BeginAnimation(ScaleTransform.ScaleXProperty, grow);
            scale.BeginAnimation(ScaleTransform.ScaleYProperty, grow);
        }
    }

    private static void AnimateFadeIn(FrameworkElement element, TimeSpan delay)
    {
        element.BeginAnimation(UIElement.OpacityProperty, null);
        element.Opacity = 0;

        var opacity = new DoubleAnimation(0, 1, TimeSpan.FromSeconds(1.2)) { BeginTime = delay };
        element.BeginAnimation(UIElement.OpacityProperty, opacity);
    }

    private void TutorialButton_Click(object sender, RoutedEventArgs e) => ShowTutorial();

    private void QuizButton_Click(object sender, RoutedEventArgs e)
        => new QuizWindow { Owner = this }.Show();

    private void ShowTutorial()
    {
        var tutorial = new TutorialWindow { Owner = this };
        tutorial.Closed += (_, _) => TutorialService.MarkSeen();
        tutorial.ShowDialog();
    }

    private void ExitMenuItem_Click(object sender, RoutedEventArgs e) => Close();

    private void MinionwareLogo_Click(object sender, RoutedEventArgs e)
        => Process.Start(new ProcessStartInfo("https://minionware.net") { UseShellExecute = true });

    // Interim stand-in for the real help viewer (a Blazor app, not yet wired to per-topic help
    // IDs) — just shell out to the markdown file with whatever app Windows has associated.
    // Walks up from the running exe to find the repo's help/ folder since it isn't published
    // alongside the app yet.
    private void HelpButton_Click(object sender, RoutedEventArgs e)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "help", "index.md")))
            dir = dir.Parent;

        if (dir != null)
            Process.Start(new ProcessStartInfo(Path.Combine(dir.FullName, "help", "index.md")) { UseShellExecute = true });
        else
            MessageBox.Show("Help pages not found — they live in the help/ folder at the repo root.", "Help",
                MessageBoxButton.OK, MessageBoxImage.Information);
    }

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

    // Same deploy-time-config pattern as Minion.Agent's ReadApiBaseUrl -- empty/missing
    // means "don't check," not an error, since running fully offline is a normal,
    // supported setup, not a broken one.
    // Not deploy-time config: this is the same single URL for every install of this app,
    // forever -- unlike Minion.Agent's ApiBaseUrl (which genuinely varies per customer
    // deployment and belongs in a config file), changing this means shipping a new exe
    // anyway, so there's no real benefit to indirecting through a file that can go missing
    // or drift out of sync with the binary.
    private const string UpdateManifestUrl = "https://www.minionware.net/Products/Agent/InjectionLab_NewVersion.json";

    private static string ReadUpdateManifestUrl() => UpdateManifestUrl;

    // Enhancement-only: wrapped whole in try/catch, never surfaces an error, never
    // delays/blocks startup. Only ever shows the banner (UpdateBanner in
    // MainWindow.xaml) -- no modal dialog, so it never gets in the way of whatever
    // the user's doing.
    private async Task CheckForUpdatesAsync()
    {
        try
        {
            var manifestUrl = ReadUpdateManifestUrl();
            if (string.IsNullOrWhiteSpace(manifestUrl))
            {
                return;
            }

            var settings = _updateCheckService.LoadSettings();
            if (!UpdateCheckService.IsDue(settings, DateTime.UtcNow))
            {
                return;
            }

            var manifest = await _updateCheckService.CheckAsync(manifestUrl);
            _updateCheckService.SaveSettings(settings with { LastCheckedAtUtc = DateTime.UtcNow });

            if (manifest is null
                || manifest.LatestVersion == settings.SkippedVersion
                || !UpdateCheckService.IsNewerThanRunning(manifest.LatestVersion))
            {
                return;
            }

            _pendingUpdateManifest = manifest;
            var featureNote = manifest.Features is { Count: > 0 }
                ? $" New: {string.Join(", ", manifest.Features.Take(2).Select(f => f.Title))}{(manifest.Features.Count > 2 ? ", and more" : "")}."
                : "";
            UpdateBannerText.Text = $"Minion.InjectionLab {manifest.LatestVersion} is available.{featureNote}";
            UpdateBannerWhatsNewButton.Visibility = string.IsNullOrWhiteSpace(manifest.ReleaseNotesUrl) ? Visibility.Collapsed : Visibility.Visible;
            UpdateBannerDownloadButton.Visibility = string.IsNullOrWhiteSpace(manifest.DownloadUrl) ? Visibility.Collapsed : Visibility.Visible;
            UpdateBanner.Visibility = Visibility.Visible;
        }
        catch
        {
            // Never let a broken/unreachable manifest affect startup.
        }
    }

    private static void OpenInBrowser(string url) => Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });

    private void UpdateBannerWhatsNew_Click(object sender, RoutedEventArgs e)
    {
        if (_pendingUpdateManifest?.ReleaseNotesUrl is { Length: > 0 } url)
        {
            OpenInBrowser(url);
        }
    }

    private void UpdateBannerDownload_Click(object sender, RoutedEventArgs e)
    {
        if (_pendingUpdateManifest?.DownloadUrl is { Length: > 0 } url)
        {
            OpenInBrowser(url);
        }
    }

    // "Dismiss" means "skip this version" -- it won't ask again until a newer one
    // is published. There's no separate "remind me later" button: the banner isn't
    // a nag dialog blocking anything, so simply leaving it up (or closing the app
    // and reopening before dismissing) already covers that case for free.
    private void UpdateBannerDismiss_Click(object sender, RoutedEventArgs e)
    {
        if (_pendingUpdateManifest is not null)
        {
            var settings = _updateCheckService.LoadSettings();
            _updateCheckService.SaveSettings(settings with { SkippedVersion = _pendingUpdateManifest.LatestVersion });
        }

        UpdateBanner.Visibility = Visibility.Collapsed;
    }
}
