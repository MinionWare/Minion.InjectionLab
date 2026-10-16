using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Wpf.ViewModels;

/// <summary>One catalog category ("sector" in the Mission select screen) and the missions in it.</summary>
public partial class SectorViewModel : ObservableObject
{
    public AttackCategory Category { get; }
    public IReadOnlyList<AttackViewModel> Missions { get; }

    /// <summary>1-based display position, assigned once by MainViewModel at startup ("SECTOR 01" etc).</summary>
    public int SectorNumber { get; set; }

    public string Name => Category switch
    {
        AttackCategory.ClassicInBand => "Classic / In-Band",
        AttackCategory.BlindInferential => "Blind / Inferential",
        AttackCategory.OutOfBand => "Out-of-Band",
        AttackCategory.DeliveryObfuscation => "Delivery & Obfuscation",
        AttackCategory.IdentifiersAndDynamicSql => "Parameters Don't Help",
        AttackCategory.PostInjectionImpact => "Post-Injection Impact",
        AttackCategory.SqlServerAgentAndJobs => "SQL Agent & Jobs",
        _ => Category.ToString()
    };

    public int TotalCount => Missions.Count;

    public int ClearedCount => Missions.Count(m => m.IsCleared);

    public SectorViewModel(AttackCategory category, IReadOnlyList<AttackViewModel> missions)
    {
        Category = category;
        Missions = missions;

        foreach (var mission in missions)
            mission.PropertyChanged += OnMissionPropertyChanged;
    }

    private void OnMissionPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(AttackViewModel.IsCleared))
            OnPropertyChanged(nameof(ClearedCount));
    }
}
