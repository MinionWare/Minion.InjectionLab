using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Wpf.ViewModels;

/// <summary>
/// Wraps one AttackScenario with mutable field values, the fix on/off state, and the
/// computed SQL + simulation output. Everything recomputes live as the user types.
/// </summary>
public partial class AttackViewModel : ObservableObject
{
    public AttackScenario Scenario { get; }

    public ObservableCollection<FieldValueViewModel> Fields { get; }

    [ObservableProperty]
    private bool isFixApplied;

    [ObservableProperty]
    private string generatedSql = string.Empty;

    [ObservableProperty]
    private ObservableCollection<SqlSegment> sqlSegments = new();

    [ObservableProperty]
    private SimulationResult? result;

    [ObservableProperty]
    private bool isChallengeMode;

    [ObservableProperty]
    private int revealedHintCount;

    [ObservableProperty]
    private bool isAnswerRevealed;

    [ObservableProperty]
    private ObservableCollection<string> revealedHints = new();

    public bool HasHints => Scenario.Hints is { Count: > 0 };
    public bool HasMoreHints => Scenario.Hints is { } h && RevealedHintCount < h.Count;

    public AttackViewModel(AttackScenario scenario)
    {
        Scenario = scenario;
        Fields = new ObservableCollection<FieldValueViewModel>(
            scenario.Fields.Select(f => new FieldValueViewModel(f)));

        foreach (var f in Fields)
            f.PropertyChanged += (_, __) => Recompute();

        Recompute();
    }

    partial void OnIsFixAppliedChanged(bool value) => Recompute();

    partial void OnIsChallengeModeChanged(bool value)
    {
        if (value) ResetChallenge();
    }

    partial void OnRevealedHintCountChanged(int value)
    {
        RevealedHints = new ObservableCollection<string>(
            Scenario.Hints?.Take(value) ?? Enumerable.Empty<string>());
        OnPropertyChanged(nameof(HasMoreHints));
    }

    [RelayCommand]
    private void RevealNextHint()
    {
        if (Scenario.Hints is { } hints && RevealedHintCount < hints.Count)
            RevealedHintCount++;
    }

    [RelayCommand]
    private void RevealAnswer() => IsAnswerRevealed = true;

    [RelayCommand]
    private void ResetChallenge()
    {
        RevealedHintCount = 0;
        IsAnswerRevealed = false;
        foreach (var f in Fields)
            f.Value = string.Empty;
    }

    private void Recompute()
    {
        var values = Fields.ToDictionary(f => f.Field.Key, f => f.Value ?? string.Empty);

        GeneratedSql = IsFixApplied
            ? Scenario.BuildFixedSql(values)
            : Scenario.BuildVulnerableSql(values);

        Result = IsFixApplied
            ? Scenario.SimulateFixed(values)
            : Scenario.SimulateVulnerable(values);

        SqlSegments = new ObservableCollection<SqlSegment>(
            BuildSegments(GeneratedSql, values.Values.Where(v => !string.IsNullOrEmpty(v))));
    }

    /// <summary>
    /// Naive but effective: walks the generated SQL left to right and marks any span that
    /// matches one of the raw field values as user input, so the view can color it distinctly
    /// from the SQL the app itself wrote.
    /// </summary>
    private static List<SqlSegment> BuildSegments(string sql, IEnumerable<string> rawValues)
    {
        var needles = rawValues.Where(v => v.Length > 0).Distinct().OrderByDescending(v => v.Length).ToList();
        var segments = new List<SqlSegment>();
        int i = 0;

        while (i < sql.Length)
        {
            int bestIndex = -1;
            string? bestNeedle = null;

            foreach (var needle in needles)
            {
                int idx = sql.IndexOf(needle, i, StringComparison.Ordinal);
                if (idx >= 0 && (bestIndex == -1 || idx < bestIndex))
                {
                    bestIndex = idx;
                    bestNeedle = needle;
                }
            }

            if (bestIndex == -1 || bestNeedle == null)
            {
                segments.Add(new SqlSegment(sql[i..], false));
                break;
            }

            if (bestIndex > i)
                segments.Add(new SqlSegment(sql[i..bestIndex], false));

            segments.Add(new SqlSegment(bestNeedle, true));
            i = bestIndex + bestNeedle.Length;
        }

        return segments;
    }
}
