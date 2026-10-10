using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Quiz;

namespace Minion.InjectionLab.Wpf.ViewModels;

/// <summary>Drives Quiz Mode: pick a difficulty, get one mission, submit payloads against it with
/// open-ended grading (unlike per-attack Challenge Mode's single canonical answer).</summary>
public partial class QuizViewModel : ObservableObject
{
    private readonly HashSet<string> _discovered = new();

    [ObservableProperty]
    private QuizDifficulty difficulty = QuizDifficulty.Beginner;

    public ObservableCollection<QuizMission> MissionsInTier { get; private set; } = new();

    [ObservableProperty]
    private QuizMission currentMission = null!;

    public bool HasMultipleMissions => MissionsInTier.Count > 1;

    public ObservableCollection<FieldValueViewModel> Fields { get; private set; } = new();
    public ObservableCollection<string> DiscoveredFacts { get; } = new();

    [ObservableProperty]
    private string generatedSql = string.Empty;

    [ObservableProperty]
    private string? generatedCSharp;

    [ObservableProperty]
    private string? generatedPowerShell;

    [ObservableProperty]
    private QuizOutcome? lastOutcome;

    [ObservableProperty]
    private int attemptCount;

    [ObservableProperty]
    private int revealedHintCount;

    public bool HasHints => CurrentMission.Hints is { Count: > 0 };
    public IEnumerable<string> RevealedHints => CurrentMission.Hints?.Take(RevealedHintCount) ?? Enumerable.Empty<string>();
    public bool HasMoreHints => CurrentMission.Hints != null && RevealedHintCount < CurrentMission.Hints.Count;

    public QuizViewModel()
    {
        OnDifficultyChanged(Difficulty);
    }

    partial void OnDifficultyChanged(QuizDifficulty value)
    {
        MissionsInTier = new ObservableCollection<QuizMission>(QuizContent.All.Where(m => m.Difficulty == value));
        OnPropertyChanged(nameof(MissionsInTier));
        OnPropertyChanged(nameof(HasMultipleMissions));
        LoadMission(MissionsInTier.First());
    }

    [RelayCommand]
    private void SelectMission(QuizMission mission) => LoadMission(mission);

    private void LoadMission(QuizMission mission)
    {
        CurrentMission = mission;

        foreach (var old in Fields)
            old.PropertyChanged -= OnFieldChanged;

        Fields = new ObservableCollection<FieldValueViewModel>(
            mission.Fields.Select(f => new FieldValueViewModel(f, mission.BaselineValues.GetValueOrDefault(f.Key))));
        foreach (var fvm in Fields)
            fvm.PropertyChanged += OnFieldChanged;

        _discovered.Clear();
        DiscoveredFacts.Clear();
        LastOutcome = null;
        AttemptCount = 0;
        RevealedHintCount = 0;

        OnPropertyChanged(nameof(Fields));
        OnPropertyChanged(nameof(HasHints));
        OnPropertyChanged(nameof(RevealedHints));
        OnPropertyChanged(nameof(HasMoreHints));
        Recompute();
    }

    private void OnFieldChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e) => Recompute();

    private IReadOnlyDictionary<string, string> CurrentValues()
        => Fields.ToDictionary(f => f.Field.Key, f => f.Value);

    private void Recompute()
    {
        var values = CurrentValues();
        var mission = CurrentMission;
        GeneratedSql = mission.BuildSql(values);
        GeneratedCSharp = mission.BuildCSharp?.Invoke(values);
        GeneratedPowerShell = mission.BuildPowerShell?.Invoke(values);
    }

    [RelayCommand]
    private void SetDifficulty(string level)
    {
        if (Enum.TryParse<QuizDifficulty>(level, out var parsed))
            Difficulty = parsed;
    }

    [RelayCommand]
    private void Submit()
    {
        AttemptCount++;
        var outcome = CurrentMission.Evaluate(CurrentValues(), _discovered);
        if (outcome.NewlyDiscovered != null)
            foreach (var fact in outcome.NewlyDiscovered)
                if (_discovered.Add(fact))
                    DiscoveredFacts.Add(fact);
        LastOutcome = outcome;
    }

    [RelayCommand]
    private void RevealNextHint()
    {
        if (!HasMoreHints) return;
        RevealedHintCount++;
        OnPropertyChanged(nameof(RevealedHints));
        OnPropertyChanged(nameof(HasMoreHints));
    }

    [RelayCommand]
    private void Reset() => LoadMission(CurrentMission);
}
