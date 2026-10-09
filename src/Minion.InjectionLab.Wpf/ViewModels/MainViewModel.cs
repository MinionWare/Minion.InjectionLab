using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Minion.InjectionLab.Core.Catalog;
using Minion.InjectionLab.Wpf.Services;

namespace Minion.InjectionLab.Wpf.ViewModels;

public partial class MainViewModel : ObservableObject
{
    public ObservableCollection<AttackViewModel> Attacks { get; }

    [ObservableProperty]
    private AttackViewModel? selectedAttack;

    public MainViewModel()
    {
        Attacks = new ObservableCollection<AttackViewModel>(
            AttackCatalog.All.Select(a => new AttackViewModel(a)));

        SelectedAttack = Attacks.FirstOrDefault();
    }

    [RelayCommand]
    private void ToggleTheme() => ThemeService.Toggle();
}
