using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Navigation;
using System.Threading.Tasks;
using ICSharpCode.AvalonEdit;
using Minion.InjectionLab.Core.Services;
using Minion.InjectionLab.Wpf.Behaviors;
using Minion.InjectionLab.Wpf.Converters;
using Minion.InjectionLab.Wpf.Services;
using Minion.InjectionLab.Wpf.ViewModels;
using Minion.Licensing.Updates;
using HelpClient = HelpServer.Client.HelpClient;
using HelpClientOptions = HelpServer.Client.HelpClientOptions;

namespace Minion.InjectionLab.Wpf;

public partial class MainWindow : Window
{
    private AttackViewModel? _trackedAttack;
    private readonly UpdateCheckService _updateCheckService = new("Minion.InjectionLab");
    private UpdateManifest? _pendingUpdateManifest;

    // The bundled HelpServer (Services/HelpClient.cs, Services/Help.cs, and the HelpServer/ folder
    // copied alongside this app's own exe — see the .csproj) — same deploy-time-config reasoning
    // as _updateCheckService's manifest URL: this port never varies per install, so it's a const,
    // not a settings file.
    private readonly HelpClient _helpClient = new(new HelpClientOptions
    {
        BaseUrl = "http://localhost:5186",
        ExePath = Path.Combine(AppContext.BaseDirectory, "HelpServer", "HelpServer.exe")
    });

    public MainWindow()
    {
        InitializeComponent();

        // Height/Width in XAML are a preferred starting size, not a guarantee — on a screen whose
        // work area is shorter (smaller display, taskbar, scaling), the window needs to both
        // shrink to fit AND be positioned so every edge lands inside the work area. XAML's
        // WindowStartupLocation="CenterScreen" centers against the monitor's full bounds, not the
        // work area — on a short display that silently puts the window's bottom behind the
        // taskbar, invisible but logically still "on screen" as far as layout is concerned (this is
        // what the Mission screen's reported "cut off at the bottom" turned out to be: the content
        // fit its ScrollViewer with room to spare, but part of that ScrollViewer was rendering
        // beneath the taskbar). Position manually against the work area instead.
        var workArea = SystemParameters.WorkArea;
        Height = Math.Min(Height, workArea.Height);
        Width = Math.Min(Width, workArea.Width);
        WindowStartupLocation = WindowStartupLocation.Manual;
        Left = workArea.Left + (workArea.Width - Width) / 2;
        Top = workArea.Top + (workArea.Height - Height) / 2;

        var viewModel = new MainViewModel();
        DataContext = viewModel;

        SqlEditor.SyntaxHighlighting = CodeHighlightingLoader.Sql;
        CSharpEditor.SyntaxHighlighting = CodeHighlightingLoader.CSharp;
        PowerShellEditor.SyntaxHighlighting = CodeHighlightingLoader.PowerShell;
        TutorialSqlEditor.SyntaxHighlighting = CodeHighlightingLoader.Sql;
        SqlEditor.TextArea.TextView.LineTransformers.Add(new DeadCodeAfterCommentColorizer());

        // The highlighting colors ThemeService.Apply patches in place aren't DynamicResources, so
        // nothing tells these editors to repaint on their own — force it explicitly.
        ThemeService.Changed += _ =>
        {
            foreach (var editor in new[] { SqlEditor, CSharpEditor, PowerShellEditor, QuizSqlEditor, QuizCSharpEditor, QuizPowerShellEditor, TutorialSqlEditor })
                editor.TextArea.TextView.Redraw();
        };

        // AvalonEdit's TextEditor has its own internal ScrollViewer and swallows every mouse-wheel
        // tick for it, even when the code inside doesn't need to scroll — hovering the mouse over
        // the code panel (an easy place to land while trying to scroll the page) silently blocks
        // the outer page scroll entirely. Intercept and forward it to the real page ScrollViewer.
        SqlEditor.PreviewMouseWheel += ForwardMouseWheelToPageScroll;
        CSharpEditor.PreviewMouseWheel += ForwardMouseWheelToPageScroll;
        PowerShellEditor.PreviewMouseWheel += ForwardMouseWheelToPageScroll;
        TutorialSqlEditor.PreviewMouseWheel += ForwardMouseWheelToPageScroll;

        // Same explicit-assignment pattern as the Quiz/Scenario editors above — AvalonEdit's
        // TextEditor has no bindable Text dependency property.
        viewModel.Tutorial.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(TutorialViewModel.DemoSql) or null)
                SetEditor(TutorialSqlEditor, viewModel.Tutorial.DemoSql, null, isSql: true);
        };
        SetEditor(TutorialSqlEditor, viewModel.Tutorial.DemoSql, null, isSql: true);

        QuizSqlEditor.SyntaxHighlighting = CodeHighlightingLoader.Sql;
        QuizCSharpEditor.SyntaxHighlighting = CodeHighlightingLoader.CSharp;
        QuizPowerShellEditor.SyntaxHighlighting = CodeHighlightingLoader.PowerShell;
        QuizSqlEditor.PreviewMouseWheel += ForwardMouseWheelToPageScroll;
        QuizCSharpEditor.PreviewMouseWheel += ForwardMouseWheelToPageScroll;
        QuizPowerShellEditor.PreviewMouseWheel += ForwardMouseWheelToPageScroll;

        viewModel.Quiz.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(QuizViewModel.GeneratedSql) or nameof(QuizViewModel.GeneratedCSharp)
                or nameof(QuizViewModel.GeneratedPowerShell) or null)
            {
                SetEditor(QuizSqlEditor, viewModel.Quiz.GeneratedSql, null, isSql: true);
                SetEditor(QuizCSharpEditor, viewModel.Quiz.GeneratedCSharp, null);
                SetEditor(QuizPowerShellEditor, viewModel.Quiz.GeneratedPowerShell, null);
            }
        };
        SetEditor(QuizSqlEditor, viewModel.Quiz.GeneratedSql, null, isSql: true);
        SetEditor(QuizCSharpEditor, viewModel.Quiz.GeneratedCSharp, null);
        SetEditor(QuizPowerShellEditor, viewModel.Quiz.GeneratedPowerShell, null);

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
            if (e.PropertyName is nameof(MainViewModel.CurrentView) or null && viewModel.IsWelcome)
                PlayWelcomeIntro();
        };
        TrackAttack(viewModel.SelectedAttack);

        Loaded += (_, _) =>
        {
            if (viewModel.IsWelcome)
                PlayWelcomeIntro();

            _ = CheckForUpdatesAsync();
            _ = WarmUpHelpServerAsync();
        };
    }

    // Enhancement-only, same as CheckForUpdatesAsync: wrapped whole in try/catch, never surfaces
    // an error, never blocks startup. Without this, HelpClient only starts HelpServer.exe lazily,
    // on the first Help click that finds nothing listening — so that first click pays for the
    // whole process + Kestrel startup. Doing it here instead, right after the window loads, means
    // by the time anyone actually clicks Help the server's very likely already warm.
    private async Task WarmUpHelpServerAsync()
    {
        try
        {
            if (await _helpClient.IsAvailableAsync()) return;

            var exePath = Path.Combine(AppContext.BaseDirectory, "HelpServer", "HelpServer.exe");
            if (!File.Exists(exePath)) return;

            Process.Start(new ProcessStartInfo(exePath)
            {
                UseShellExecute = false,
                WorkingDirectory = Path.GetDirectoryName(exePath)!,
                CreateNoWindow = true
            });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            // Help just won't be pre-warmed this run; HelpClient's own lazy-start on first use still covers it.
        }
    }

    private void OpenMissedMissions_Click(object sender, RoutedEventArgs e) => ((MainViewModel)DataContext).BrowseCatalogCommand.Execute(null);

    private static void ForwardMouseWheelToPageScroll(object sender, System.Windows.Input.MouseWheelEventArgs e)
    {
        if (e.Handled) return;

        var scrollViewer = FindAncestorScrollViewer((DependencyObject)sender);
        if (scrollViewer == null) return;

        e.Handled = true;
        scrollViewer.ScrollToVerticalOffset(scrollViewer.VerticalOffset - e.Delta);
    }

    private static ScrollViewer? FindAncestorScrollViewer(DependencyObject? element)
    {
        while (element != null)
        {
            element = VisualTreeHelper.GetParent(element);
            if (element is ScrollViewer scrollViewer) return scrollViewer;
        }
        return null;
    }

    private void DifficultyChip_Click(object sender, RoutedEventArgs e)
    {
        var button = (Button)sender;
        button.ContextMenu!.PlacementTarget = button;
        button.ContextMenu.IsOpen = true;
    }

    private void PlayWelcomeIntro()
    {
        if (!SystemParameters.ClientAreaAnimation)
        {
            ShowWelcomeIntroFinalState();
            return;
        }

        AnimatePopIn(WelcomeGlow, WelcomeGlowScale, TimeSpan.Zero, TimeSpan.FromSeconds(1.6), targetOpacity: 0.22, targetScale: 1.0);
        AnimatePopIn(WelcomeMascot, WelcomeMascotScale, TimeSpan.Zero, TimeSpan.FromSeconds(1.4), targetOpacity: 1.0, targetScale: 1.0);
        AnimatePopIn(WelcomeFromRow, WelcomeFromRowScale, TimeSpan.FromSeconds(0.35), TimeSpan.FromSeconds(1.4), targetOpacity: 1.0, targetScale: 1.0);
        AnimateFadeUp(WelcomeTitleStack, WelcomeTitleStackTranslate, TimeSpan.FromSeconds(0.85), TimeSpan.FromSeconds(1.2));
        AnimateFadeUp(WelcomeCtaRow, WelcomeCtaRowTranslate, TimeSpan.FromSeconds(1.25), TimeSpan.FromSeconds(1.0));
        AnimateFadeUp(WelcomeSafetyPill, WelcomeSafetyPillTranslate, TimeSpan.FromSeconds(1.55), TimeSpan.FromSeconds(1.0));

        StartWelcomeIdleLoops(TimeSpan.FromSeconds(1.8));
    }

    private void ShowWelcomeIntroFinalState()
    {
        foreach (var element in new UIElement[] { WelcomeGlow, WelcomeMascot, WelcomeFromRow, WelcomeTitleStack, WelcomeCtaRow, WelcomeSafetyPill })
            element.BeginAnimation(UIElement.OpacityProperty, null);

        WelcomeGlow.Opacity = 0.22;
        WelcomeMascot.Opacity = 1;
        WelcomeFromRow.Opacity = 1;
        WelcomeTitleStack.Opacity = 1;
        WelcomeCtaRow.Opacity = 1;
        WelcomeSafetyPill.Opacity = 1;

        foreach (var scale in new[] { WelcomeGlowScale, WelcomeMascotScale, WelcomeFromRowScale })
        {
            scale.BeginAnimation(ScaleTransform.ScaleXProperty, null);
            scale.BeginAnimation(ScaleTransform.ScaleYProperty, null);
            scale.ScaleX = scale.ScaleY = 1;
        }

        foreach (var translate in new[] { WelcomeTitleStackTranslate, WelcomeCtaRowTranslate, WelcomeSafetyPillTranslate })
        {
            translate.BeginAnimation(TranslateTransform.YProperty, null);
            translate.Y = 0;
        }
    }

    private static void AnimatePopIn(UIElement element, ScaleTransform scale, TimeSpan delay, TimeSpan duration, double targetOpacity, double targetScale)
    {
        element.BeginAnimation(UIElement.OpacityProperty, null);
        element.Opacity = 0;
        var opacity = new DoubleAnimation(0, targetOpacity, duration) { BeginTime = delay };
        element.BeginAnimation(UIElement.OpacityProperty, opacity);

        scale.BeginAnimation(ScaleTransform.ScaleXProperty, null);
        scale.BeginAnimation(ScaleTransform.ScaleYProperty, null);
        scale.ScaleX = scale.ScaleY = 0.3;

        var easing = new BackEase { EasingMode = EasingMode.EaseOut, Amplitude = 0.6 };
        var grow = new DoubleAnimation(0.3, targetScale, duration) { BeginTime = delay, EasingFunction = easing };
        scale.BeginAnimation(ScaleTransform.ScaleXProperty, grow);
        scale.BeginAnimation(ScaleTransform.ScaleYProperty, grow);
    }

    private static void AnimateFadeUp(UIElement element, TranslateTransform translate, TimeSpan delay, TimeSpan duration)
    {
        element.BeginAnimation(UIElement.OpacityProperty, null);
        element.Opacity = 0;
        var opacity = new DoubleAnimation(0, 1, duration) { BeginTime = delay };
        element.BeginAnimation(UIElement.OpacityProperty, opacity);

        translate.BeginAnimation(TranslateTransform.YProperty, null);
        translate.Y = 14;
        var move = new DoubleAnimation(14, 0, duration) { BeginTime = delay, EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } };
        translate.BeginAnimation(TranslateTransform.YProperty, move);
    }

    private void StartWelcomeIdleLoops(TimeSpan startAfter)
    {
        var floatAnim = new DoubleAnimation(0, -10, TimeSpan.FromSeconds(3))
        {
            BeginTime = startAfter,
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut }
        };
        WelcomeMascotFloat.BeginAnimation(TranslateTransform.YProperty, floatAnim);

        var glowPulse = new DoubleAnimation(0.22, 0.32, TimeSpan.FromSeconds(2.5))
        {
            BeginTime = startAfter,
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut }
        };
        WelcomeGlow.BeginAnimation(UIElement.OpacityProperty, glowPulse);

        var shimmer = new DoubleAnimation(0, 1, TimeSpan.FromSeconds(8))
        {
            BeginTime = startAfter,
            RepeatBehavior = RepeatBehavior.Forever
        };
        WelcomeWordmarkShimmer.BeginAnimation(TranslateTransform.XProperty, shimmer);
    }

    private void TutorialButton_Click(object sender, RoutedEventArgs e) => ((MainViewModel)DataContext).OpenTrainingCommand.Execute(null);

    private void QuizButton_Click(object sender, RoutedEventArgs e) => ((MainViewModel)DataContext).OpenQuizCommand.Execute(null);

    private void ExitMenuItem_Click(object sender, RoutedEventArgs e) => Close();

    private void MinionwareLogo_Click(object sender, RoutedEventArgs e)
        => Process.Start(new ProcessStartInfo("https://minionware.net") { UseShellExecute = true });

    private void HelpButton_Click(object sender, RoutedEventArgs e) => _ = OpenHelpAsync("injectionlab.features");

    /// <summary>Shared Click handler for every "?" help icon in the app — each one just declares
    /// its article via the Help.Id attached property (see Services/Help.cs) instead of needing
    /// its own handler method.</summary>
    private void HelpIcon_Click(object sender, RoutedEventArgs e)
    {
        var id = Help.GetId((DependencyObject)sender);
        if (!string.IsNullOrWhiteSpace(id))
            _ = OpenHelpAsync(id);
    }

    private async Task OpenHelpAsync(string id)
    {
        var result = await _helpClient.OpenAsync(id);
        if (!result.Success)
            MessageBox.Show(result.Message, "Help", MessageBoxButton.OK, MessageBoxImage.Information);
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
        SetEditor(SqlEditor, attack?.GeneratedSql, attack?.SqlSegments, isSql: true);
        SetEditor(CSharpEditor, attack?.GeneratedCSharp, attack?.CSharpSegments);
        SetEditor(PowerShellEditor, attack?.GeneratedPowerShell, attack?.PowerShellSegments);
    }

    private static void SetEditor(TextEditor editor, string? text, ObservableCollection<SqlSegment>? segments, bool isSql = false)
    {
        var newText = text ?? string.Empty;
        if (editor.Document.Text != newText)
            editor.Document.Text = newText;

        AvalonEditBehavior.SetHighlightSegments(editor, segments ?? new ObservableCollection<SqlSegment>());

        // Live ScriptDom validation, same engine SQL Server itself would use — squiggles appear
        // the moment a payload doesn't parse and clear the moment it does, exactly like a code
        // editor's own red squiggly, not a guessed-at "contains --" heuristic.
        if (isSql)
            AvalonEditBehavior.SetSyntaxIssues(editor, SqlSyntaxChecker.GetSyntaxIssues(newText));
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
