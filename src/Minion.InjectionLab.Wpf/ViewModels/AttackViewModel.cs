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
/// computed SQL/C#/PowerShell + simulation output. Everything recomputes live as the user types.
/// </summary>
public partial class AttackViewModel : ObservableObject
{
    public AttackScenario Scenario { get; }

    public ObservableCollection<FieldValueViewModel> Fields { get; }

    /// <summary>
    /// Always has at least one entry. Scenarios that set Scenario.Fixes (more than one real fix
    /// worth comparing) use those directly; scenarios using the legacy single BuildFixedSql/
    /// SimulateFixed get a single synthesized Best-grade entry wrapping them, so the rest of this
    /// view model never needs to special-case "does this scenario have Fixes or not".
    /// </summary>
    private readonly IReadOnlyList<FixOption> _fixes;
    public IReadOnlyList<FixOption> Fixes => _fixes;
    public bool HasMultipleFixes => _fixes.Count > 1;

    /// <summary>-1 = vulnerable (no fix applied); 0..N-1 = index into Fixes.</summary>
    [ObservableProperty]
    private int currentFixIndex = -1;

    /// <summary>Backward-compatible on/off view of CurrentFixIndex, for the simple toggle switch
    /// used by every scenario with exactly one fix.</summary>
    public bool IsFixApplied
    {
        get => CurrentFixIndex >= 0;
        set => CurrentFixIndex = value ? 0 : -1;
    }

    public bool IsVulnerableSelected => CurrentFixIndex < 0;
    public bool IsFix0Selected => CurrentFixIndex == 0;
    public bool IsFix1Selected => CurrentFixIndex == 1;

    /// <summary>What the currently-selected fix still misses — null when vulnerable, or when the
    /// selected fix has no known gap (Best grade).</summary>
    public string? CurrentFixGap => CurrentFixIndex >= 0 && CurrentFixIndex < _fixes.Count ? _fixes[CurrentFixIndex].Gap : null;

    [ObservableProperty]
    private string generatedSql = string.Empty;

    [ObservableProperty]
    private ObservableCollection<SqlSegment> sqlSegments = new();

    [ObservableProperty]
    private string generatedCSharp = string.Empty;

    [ObservableProperty]
    private ObservableCollection<SqlSegment> cSharpSegments = new();

    [ObservableProperty]
    private string generatedPowerShell = string.Empty;

    [ObservableProperty]
    private ObservableCollection<SqlSegment> powerShellSegments = new();

    public bool HasCodeSamples => Scenario.BuildVulnerableCSharp != null || Scenario.BuildVulnerablePowerShell != null;

    public bool HasDecisionPaths => Scenario.DecisionPaths is { Count: > 0 };

    /// <summary>Live, pre-submit: which DecisionPathDef.Key the current (unsubmitted) input would take.</summary>
    [ObservableProperty]
    private string? activePathKey;

    /// <summary>What happens with YOUR input — only populated once you hit Submit.</summary>
    [ObservableProperty]
    private SimulationResult? result;

    /// <summary>What happens with a normal, non-malicious user's input — the "proper call" comparison.</summary>
    [ObservableProperty]
    private SimulationResult? normalResult;

    public bool HasBaseline => Scenario.BaselineValues is { Count: > 0 };

    /// <summary>Toggled by the "View results" button under the YOU card.</summary>
    [ObservableProperty]
    private bool showResultRows;

    /// <summary>Toggled by the "View results" button under the NORMAL USER card.</summary>
    [ObservableProperty]
    private bool showNormalResultRows;

    /// <summary>False until Submit is clicked (or re-clicked after the input/fix changes) — drives the "fill this in and hit Submit" placeholder.</summary>
    [ObservableProperty]
    private bool hasSubmitted;

    /// <summary>Bumped on every Submit so the view can trigger a "flash"/shake animation off a real change notification.</summary>
    [ObservableProperty]
    private int resultVersion;

    [ObservableProperty]
    private bool isChallengeMode;

    [ObservableProperty]
    private DifficultyLevel difficulty = DifficultyLevel.Beginner;

    [ObservableProperty]
    private int revealedHintCount;

    [ObservableProperty]
    private bool isAnswerRevealed;

    [ObservableProperty]
    private ObservableCollection<string> revealedHints = new();

    public bool HasHints => Scenario.Hints is { Count: > 0 };

    public int HintBudget => Scenario.Hints is not { Count: > 0 } hints ? 0 : Difficulty switch
    {
        DifficultyLevel.Beginner => hints.Count,
        DifficultyLevel.Intermediate => Math.Max(1, (hints.Count + 1) / 2),
        DifficultyLevel.Expert => 1,
        _ => hints.Count
    };

    public bool HasMoreHints => RevealedHintCount < HintBudget;
    public bool CanRevealAnswer => Difficulty != DifficultyLevel.Expert;

    public AttackViewModel(AttackScenario scenario)
    {
        Scenario = scenario;
        Fields = new ObservableCollection<FieldValueViewModel>(
            scenario.Fields.Select(f => new FieldValueViewModel(f,
                scenario.BaselineValues != null && scenario.BaselineValues.TryGetValue(f.Key, out var baseline) ? baseline : null)));

        _fixes = scenario.Fixes.Count > 0
            ? scenario.Fixes
            : new[]
            {
                new FixOption
                {
                    Label = "Parameterized query",
                    Grade = FixGrade.Best,
                    Gap = null,
                    BuildSql = scenario.BuildFixedSql ?? (_ => string.Empty),
                    Simulate = scenario.SimulateFixed ?? (_ => new SimulationResult { Severity = Severity.Blocked, Headline = "Fixed", Detail = "" }),
                    BuildCSharp = scenario.BuildFixedCSharp,
                    BuildPowerShell = scenario.BuildFixedPowerShell
                }
            };

        foreach (var f in Fields)
            f.PropertyChanged += (_, __) => OnFieldEdited();

        RecomputeCode();
    }

    private void OnFieldEdited()
    {
        RecomputeCode();
        HasSubmitted = false; // input changed since the last reveal — stale until they submit again
    }

    partial void OnCurrentFixIndexChanged(int value)
    {
        OnPropertyChanged(nameof(IsFixApplied));
        OnPropertyChanged(nameof(IsVulnerableSelected));
        OnPropertyChanged(nameof(IsFix0Selected));
        OnPropertyChanged(nameof(IsFix1Selected));
        OnPropertyChanged(nameof(CurrentFixGap));
        RecomputeCode();
        HasSubmitted = false; // the fix changed — make them re-submit to see the new outcome
    }

    [RelayCommand]
    private void SetFixIndex(string indexText)
    {
        if (int.TryParse(indexText, out var idx))
            CurrentFixIndex = idx;
    }

    partial void OnIsChallengeModeChanged(bool value)
    {
        if (value) ResetChallenge();
    }

    partial void OnDifficultyChanged(DifficultyLevel value)
    {
        OnPropertyChanged(nameof(HintBudget));
        OnPropertyChanged(nameof(HasMoreHints));
        OnPropertyChanged(nameof(CanRevealAnswer));
        ResetChallenge();
    }

    partial void OnRevealedHintCountChanged(int value)
    {
        RevealedHints = new ObservableCollection<string>(
            Scenario.Hints?.Take(value) ?? Enumerable.Empty<string>());
        OnPropertyChanged(nameof(HasMoreHints));
    }

    [RelayCommand]
    private void ToggleResultRows() => ShowResultRows = !ShowResultRows;

    [RelayCommand]
    private void ToggleNormalResultRows() => ShowNormalResultRows = !ShowNormalResultRows;

    [RelayCommand]
    private void RevealNextHint()
    {
        if (RevealedHintCount < HintBudget)
            RevealedHintCount++;
    }

    [RelayCommand]
    private void RevealAnswer()
    {
        if (CanRevealAnswer)
            IsAnswerRevealed = true;
    }

    [RelayCommand]
    private void ResetChallenge()
    {
        RevealedHintCount = 0;
        IsAnswerRevealed = false;
        foreach (var f in Fields)
            f.Value = string.Empty;
        HasSubmitted = false;
        ShowResultRows = false;
        ShowNormalResultRows = false;
    }

    /// <summary>Puts the scenario back exactly how it looked when you first opened it — fix off, defaults restored.</summary>
    [RelayCommand]
    private void ResetScenario()
    {
        CurrentFixIndex = -1;
        RevealedHintCount = 0;
        IsAnswerRevealed = false;
        HasSubmitted = false;
        ShowResultRows = false;
        ShowNormalResultRows = false;
        foreach (var f in Fields)
            f.Value = f.Field.DefaultValue;
        RecomputeCode();
    }

    /// <summary>The "moment" — runs both the baseline (normal user) and your actual input through the
    /// simulator and reveals both outcomes side by side, with the view animating the reveal.</summary>
    [RelayCommand]
    private void Submit()
    {
        var values = Fields.ToDictionary(f => f.Field.Key, f => f.Value ?? string.Empty);
        ShowResultRows = false;
        ShowNormalResultRows = false;

        var active = CurrentFixIndex >= 0 && CurrentFixIndex < _fixes.Count ? _fixes[CurrentFixIndex] : null;

        Result = active != null ? active.Simulate(values) : Scenario.SimulateVulnerable(values);

        if (Scenario.BaselineValues is { Count: > 0 } baseline)
        {
            NormalResult = active != null ? active.Simulate(baseline) : Scenario.SimulateVulnerable(baseline);
        }

        HasSubmitted = true;
        ResultVersion++;
    }

    private void RecomputeCode()
    {
        var values = Fields.ToDictionary(f => f.Field.Key, f => f.Value ?? string.Empty);
        var rawValues = values.Values.Where(v => !string.IsNullOrEmpty(v));

        var active = CurrentFixIndex >= 0 && CurrentFixIndex < _fixes.Count ? _fixes[CurrentFixIndex] : null;

        GeneratedSql = active != null ? active.BuildSql(values) : Scenario.BuildVulnerableSql(values);
        SqlSegments = new ObservableCollection<SqlSegment>(BuildSegments(GeneratedSql, rawValues));

        var csharpBuilder = active != null ? active.BuildCSharp : Scenario.BuildVulnerableCSharp;
        GeneratedCSharp = csharpBuilder?.Invoke(values) ?? string.Empty;
        CSharpSegments = new ObservableCollection<SqlSegment>(BuildSegments(GeneratedCSharp, rawValues));

        var psBuilder = active != null ? active.BuildPowerShell : Scenario.BuildVulnerablePowerShell;
        GeneratedPowerShell = psBuilder?.Invoke(values) ?? string.Empty;
        PowerShellSegments = new ObservableCollection<SqlSegment>(BuildSegments(GeneratedPowerShell, rawValues));

        // Classification reflects the nature of the typed input itself, not whether a fix is
        // selected — so it's computed here too but independent of CurrentFixIndex.
        ActivePathKey = Scenario.ClassifyInput?.Invoke(values);
    }

    /// <summary>
    /// Naive but effective: walks the generated text left to right and marks any span that
    /// matches one of the raw field values as user input, so the view can color it distinctly
    /// from the code the app itself wrote — works for SQL, C#, and PowerShell alike.
    /// </summary>
    private static List<SqlSegment> BuildSegments(string text, IEnumerable<string> rawValues)
    {
        var needles = rawValues.Where(v => v.Length > 0).Distinct().OrderByDescending(v => v.Length).ToList();
        var segments = new List<SqlSegment>();
        if (text.Length == 0) return segments;
        int i = 0;

        while (i < text.Length)
        {
            int bestIndex = -1;
            string? bestNeedle = null;

            foreach (var needle in needles)
            {
                int idx = text.IndexOf(needle, i, StringComparison.Ordinal);
                if (idx >= 0 && (bestIndex == -1 || idx < bestIndex))
                {
                    bestIndex = idx;
                    bestNeedle = needle;
                }
            }

            if (bestIndex == -1 || bestNeedle == null)
            {
                segments.Add(new SqlSegment(text[i..], false));
                break;
            }

            if (bestIndex > i)
                segments.Add(new SqlSegment(text[i..bestIndex], false));

            segments.Add(new SqlSegment(bestNeedle, true));
            i = bestIndex + bestNeedle.Length;
        }

        return segments;
    }
}
