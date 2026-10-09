using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Minion.InjectionLab.Core.Catalog;
using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Wpf.Services;

namespace Minion.InjectionLab.Wpf.ViewModels;

public partial class MainViewModel : ObservableObject
{
    public ObservableCollection<AttackViewModel> Attacks { get; }

    [ObservableProperty]
    private AttackViewModel? selectedAttack;

    /// <summary>Applies to every scenario's challenge mode — set once, carried to whichever attack you're on.</summary>
    [ObservableProperty]
    private DifficultyLevel difficulty = DifficultyLevel.Beginner;

    public MainViewModel()
    {
        Attacks = new ObservableCollection<AttackViewModel>(
            AttackCatalog.All.Select(a => new AttackViewModel(a)));

        SelectedAttack = Attacks.FirstOrDefault();
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
}
