using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Minion.InjectionLab.Core.Catalog;
using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Wpf.Services;

namespace Minion.InjectionLab.Wpf.ViewModels;

public partial class MainViewModel : ObservableObject
{
    public ObservableCollection<AttackViewModel> Attacks { get; }

    // ── Update banner ─────────────────────────────────────────────────────────
    [ObservableProperty] private Visibility updateBannerVisible = Visibility.Collapsed;
    [ObservableProperty] private string updateVersionText = string.Empty;
    private string _updateDownloadUrl = string.Empty;
    private string _updateVersion = string.Empty;
    private string[] _updateFeatures = [];

    [ObservableProperty]
    private AttackViewModel? selectedAttack;

    /// <summary>Applies to every scenario's challenge mode — set once, carried to whichever attack you're on.</summary>
    [ObservableProperty]
    private DifficultyLevel difficulty = DifficultyLevel.Beginner;

    /// <summary>Drives the welcome screen vs. the scenario view in the main content area — null
    /// until the reader picks something, either from the list or the welcome screen's own button.</summary>
    public bool HasSelectedAttack => SelectedAttack != null;

    public int AttackCount => Attacks.Count;

    public MainViewModel()
    {
        Attacks = new ObservableCollection<AttackViewModel>(
            AttackCatalog.All.Select(a => new AttackViewModel(a)));

        // Open on the welcome screen rather than jumping straight into the first scenario —
        // SelectedAttack starts null on purpose.
    }

    partial void OnSelectedAttackChanged(AttackViewModel? value) => OnPropertyChanged(nameof(HasSelectedAttack));

    partial void OnDifficultyChanged(DifficultyLevel value)
    {
        foreach (var attack in Attacks)
            attack.Difficulty = value;
    }

    [RelayCommand]
    private void ToggleTheme() => ThemeService.Toggle();

    [RelayCommand]
    private void SetDifficulty(string level)
    {
        if (System.Enum.TryParse<DifficultyLevel>(level, out var parsed))
            Difficulty = parsed;
    }

    [RelayCommand]
    private void BrowseCatalog() => SelectedAttack = Attacks.FirstOrDefault();

    [RelayCommand]
    private void DismissUpdate() => UpdateBannerVisible = Visibility.Collapsed;

    [RelayCommand]
    private void OpenDownload()
    {
        if (!string.IsNullOrEmpty(_updateDownloadUrl))
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(_updateDownloadUrl) { UseShellExecute = true });
    }

    [RelayCommand]
    private void ShowWhatsNew()
    {
        var win = new Views.WhatsNewWindow(_updateVersion, _updateFeatures, _updateDownloadUrl)
            { Owner = Application.Current.MainWindow };
        win.ShowDialog();
    }

    public async Task CheckForUpdatesAsync()
    {
        var info = await UpdateService.CheckAsync();
        if (info == null) return;
        _updateDownloadUrl = info.DownloadUrl;
        _updateVersion = info.Version;
        _updateFeatures = info.Features;
        UpdateVersionText = $"v{info.Version} is available";
        UpdateBannerVisible = Visibility.Visible;
    }
}
