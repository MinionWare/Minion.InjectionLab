using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Minion.InjectionLab.Core.Catalog;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Wpf.ViewModels;

/// <summary>One row in the "THIS RUN" sidebar (2f) and the debrief list (2g).</summary>
public partial class QuizQuestionResult : ObservableObject
{
    public required int Number { get; init; }
    public required AttackScenario Scenario { get; init; }

    [ObservableProperty]
    private bool isCurrent;

    [ObservableProperty]
    private bool answered;

    [ObservableProperty]
    private bool solved;

    [ObservableProperty]
    private string lastPayload = string.Empty;
}

/// <summary>
/// Drives Quiz Mode: a real, multi-question quiz drawn live from the full attack catalog — not a
/// handful of hand-authored missions. Every one of the 26+ scenarios already carries everything a
/// question needs (a mock form, a live payload, and a DecisionPathDef-based classification), so a
/// question is "solved" the same way the in-app decision-path diagram already works: the submitted
/// input classifies to a <see cref="PathKind.Malicious"/> path. Difficulty controls how much of the
/// scenario's own guidance (title/category, premise, goal+hints) is shown before you solve it —
/// Expert shows only the bare mock form, so recognizing the technique is the whole test.
/// </summary>
public partial class QuizViewModel : ObservableObject
{
    private const int QuestionsPerSession = 6;
    private static readonly Random Random = new();

    [ObservableProperty]
    private QuizDifficulty difficulty = QuizDifficulty.Beginner;

    public ObservableCollection<AttackScenario> Questions { get; private set; } = new();

    public ObservableCollection<QuizQuestionResult> Results { get; private set; } = new();

    public int MissedCount => Results.Count(r => !r.Solved);

    [ObservableProperty]
    private int questionIndex;

    public AttackScenario? CurrentQuestion => QuestionIndex >= 0 && QuestionIndex < Questions.Count ? Questions[QuestionIndex] : null;

    public int QuestionNumber => QuestionIndex + 1;
    public int QuestionCount => Questions.Count;
    public bool IsLastQuestion => QuestionIndex >= Questions.Count - 1;

    /// <summary>Beginner sees the full picture (title, category, goal, hints) — same as Challenge
    /// Mode in the main catalog. Intermediate sees the premise but not which technique it is or
    /// what the goal is. Expert sees only the bare mock form: recognizing what's wrong IS the test.</summary>
    public bool ShowTitleAndCategory => Difficulty == QuizDifficulty.Beginner;
    public bool ShowPremise => Difficulty != QuizDifficulty.Expert;
    public bool ShowGoalAndHints => Difficulty == QuizDifficulty.Beginner;

    [ObservableProperty]
    private int score;

    [ObservableProperty]
    private bool isSessionComplete;

    public ObservableCollection<FieldValueViewModel> Fields { get; private set; } = new();

    [ObservableProperty]
    private string generatedSql = string.Empty;

    [ObservableProperty]
    private string? generatedCSharp;

    [ObservableProperty]
    private string? generatedPowerShell;

    [ObservableProperty]
    private bool hasSubmittedCurrent;

    [ObservableProperty]
    private bool currentSolved;

    [ObservableProperty]
    private string? outcomeHeadline;

    [ObservableProperty]
    private string? outcomeDetail;

    public event EventHandler? QuitRequested;

    public QuizViewModel()
    {
        StartSession();
    }

    [RelayCommand]
    private void Quit() => QuitRequested?.Invoke(this, EventArgs.Empty);

    partial void OnDifficultyChanged(QuizDifficulty value) => StartSession();

    [RelayCommand]
    private void SetDifficulty(string level)
    {
        if (Enum.TryParse<QuizDifficulty>(level, out var parsed))
            Difficulty = parsed;
    }

    [RelayCommand]
    private void StartSession()
    {
        Questions = new ObservableCollection<AttackScenario>(
            AttackCatalog.All.OrderBy(_ => Random.Next()).Take(QuestionsPerSession));
        Results = new ObservableCollection<QuizQuestionResult>(
            Questions.Select((q, i) => new QuizQuestionResult { Number = i + 1, Scenario = q, IsCurrent = i == 0 }));
        QuestionIndex = 0;
        Score = 0;
        IsSessionComplete = false;

        OnPropertyChanged(nameof(Questions));
        OnPropertyChanged(nameof(Results));
        OnPropertyChanged(nameof(QuestionCount));
        OnPropertyChanged(nameof(IsSessionComplete));
        LoadQuestion();
    }

    private void LoadQuestion()
    {
        var scenario = CurrentQuestion;

        foreach (var old in Fields)
            old.PropertyChanged -= OnFieldChanged;

        Fields = scenario == null
            ? new ObservableCollection<FieldValueViewModel>()
            : new ObservableCollection<FieldValueViewModel>(
                scenario.Fields.Select(f => new FieldValueViewModel(f, scenario.BaselineValues?.GetValueOrDefault(f.Key))));
        foreach (var fvm in Fields)
            fvm.PropertyChanged += OnFieldChanged;

        HasSubmittedCurrent = false;
        CurrentSolved = false;
        OutcomeHeadline = null;
        OutcomeDetail = null;

        OnPropertyChanged(nameof(CurrentQuestion));
        OnPropertyChanged(nameof(QuestionNumber));
        OnPropertyChanged(nameof(IsLastQuestion));
        OnPropertyChanged(nameof(ShowTitleAndCategory));
        OnPropertyChanged(nameof(ShowPremise));
        OnPropertyChanged(nameof(ShowGoalAndHints));
        OnPropertyChanged(nameof(Fields));

        foreach (var r in Results)
            r.IsCurrent = r.Number - 1 == QuestionIndex;

        Recompute();
    }

    private void OnFieldChanged(object? sender, PropertyChangedEventArgs e) => Recompute();

    private IReadOnlyDictionary<string, string> CurrentValues()
        => Fields.ToDictionary(f => f.Field.Key, f => f.Value);

    private void Recompute()
    {
        var scenario = CurrentQuestion;
        if (scenario == null) return;

        var values = CurrentValues();
        GeneratedSql = scenario.BuildVulnerableSql(values);
        GeneratedCSharp = scenario.BuildVulnerableCSharp?.Invoke(values);
        GeneratedPowerShell = scenario.BuildVulnerablePowerShell?.Invoke(values);

        // Editing after a submit invalidates that submit's outcome — the recorded Results row
        // (last payload / solved) stays untouched until the next real Submit.
        HasSubmittedCurrent = false;
        OutcomeHeadline = null;
        OutcomeDetail = null;
    }

    [RelayCommand]
    private void Submit()
    {
        var scenario = CurrentQuestion;
        if (scenario == null) return;

        var values = CurrentValues();
        var key = scenario.ClassifyInput?.Invoke(values);
        var path = scenario.DecisionPaths?.FirstOrDefault(p => p.Key == key);
        bool solved = path?.Kind == PathKind.Malicious;

        if (solved && !CurrentSolved)
            Score++;

        HasSubmittedCurrent = true;
        CurrentSolved = solved;

        var sim = scenario.SimulateVulnerable(values);
        OutcomeHeadline = sim.Headline;
        OutcomeDetail = sim.Detail;

        var result = Results[QuestionIndex];
        result.Answered = true;
        result.Solved = solved;
        result.LastPayload = Fields.Count > 0 ? Fields[0].Value : string.Empty;
        OnPropertyChanged(nameof(MissedCount));
    }

    [RelayCommand]
    private void NextQuestion()
    {
        if (IsLastQuestion)
        {
            IsSessionComplete = true;
            OnPropertyChanged(nameof(IsSessionComplete));
            return;
        }

        QuestionIndex++;
        LoadQuestion();
    }
}
