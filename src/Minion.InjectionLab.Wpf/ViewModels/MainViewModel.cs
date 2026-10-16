using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Minion.InjectionLab.Core.Catalog;
using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Wpf.Services;

namespace Minion.InjectionLab.Wpf.ViewModels;

public enum AppView { Welcome, MissionSelect, Mission, Training, Quiz }

public partial class MainViewModel : ObservableObject
{
    public ObservableCollection<AttackViewModel> Attacks { get; }

    public ObservableCollection<SectorViewModel> Sectors { get; }

    [ObservableProperty]
    private AttackViewModel? selectedAttack;

    [ObservableProperty]
    private int selectedSectorIndex;

    public SectorViewModel? CurrentSector =>
        SelectedSectorIndex >= 0 && SelectedSectorIndex < Sectors.Count ? Sectors[SelectedSectorIndex] : null;

    partial void OnSelectedSectorIndexChanged(int value) => OnPropertyChanged(nameof(CurrentSector));

    /// <summary>Applies to every scenario's challenge mode — set once, carried to whichever attack you're on.</summary>
    [ObservableProperty]
    private DifficultyLevel difficulty = DifficultyLevel.Beginner;

    [ObservableProperty]
    private AppView currentView = AppView.Welcome;

    /// <summary>Drives the welcome screen vs. the scenario view in the main content area — null
    /// until the reader picks something, either from the list or the welcome screen's own button.</summary>
    public bool HasSelectedAttack => SelectedAttack != null;

    public int AttackCount => Attacks.Count;

    public int ClearedCount => ProgressService.ClearedCount;

    public bool IsWelcome => CurrentView == AppView.Welcome;
    public bool IsMissionSelect => CurrentView == AppView.MissionSelect;
    public bool IsMission => CurrentView == AppView.Mission;
    public bool IsTraining => CurrentView == AppView.Training;
    public bool IsQuiz => CurrentView == AppView.Quiz;
    public bool IsMissionsAreaActive => IsMissionSelect || IsMission;

    public MainViewModel()
    {
        Attacks = new ObservableCollection<AttackViewModel>(
            AttackCatalog.All.Select(a => new AttackViewModel(a)));

        for (int i = 0; i < Attacks.Count; i++)
            Attacks[i].MissionNumber = i + 1;

        Sectors = new ObservableCollection<SectorViewModel>(
            Attacks.GroupBy(a => a.Scenario.Category)
                   .Select(g => new SectorViewModel(g.Key, g.ToList())));
        for (int i = 0; i < Sectors.Count; i++)
            Sectors[i].SectorNumber = i + 1;

        ProgressService.Changed += () => OnPropertyChanged(nameof(ClearedCount));

        // Open on the welcome screen rather than jumping straight into the first scenario —
        // SelectedAttack starts null on purpose.
    }

    partial void OnSelectedAttackChanged(AttackViewModel? value) => OnPropertyChanged(nameof(HasSelectedAttack));

    partial void OnCurrentViewChanged(AppView value)
    {
        OnPropertyChanged(nameof(IsWelcome));
        OnPropertyChanged(nameof(IsMissionSelect));
        OnPropertyChanged(nameof(IsMission));
        OnPropertyChanged(nameof(IsTraining));
        OnPropertyChanged(nameof(IsQuiz));
        OnPropertyChanged(nameof(IsMissionsAreaActive));
    }

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

    /// <summary>Welcome's MISSION SELECT button and the top bar's MISSIONS nav item both land here.</summary>
    [RelayCommand]
    private void BrowseCatalog() => CurrentView = AppView.MissionSelect;

    [RelayCommand]
    private void SelectMission(AttackViewModel attack)
    {
        attack.HasBeenOpened = true;
        SelectedAttack = attack;
        CurrentView = AppView.Mission;
    }

    [RelayCommand]
    private void GoHome()
    {
        SelectedAttack = null;
        CurrentView = AppView.Welcome;
    }

    [RelayCommand]
    private void OpenTraining() => CurrentView = AppView.Training;

    [RelayCommand]
    private void OpenQuiz() => CurrentView = AppView.Quiz;
}
