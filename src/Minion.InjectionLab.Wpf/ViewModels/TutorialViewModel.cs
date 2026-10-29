using System;
using System.Collections.Generic;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;
using Minion.InjectionLab.Core.Tutorial;

namespace Minion.InjectionLab.Wpf.ViewModels;

/// <summary>One pill in the Training step bar.</summary>
public sealed class TutorialStepRow
{
    public required int Index { get; init; }
    public required TutorialStep Step { get; init; }
    public required bool IsCurrent { get; init; }
    public required bool IsPast { get; init; }
    public bool HasDemo => Step.Demo != null;
    public int DisplayNumber => Index + 1;
}

/// <summary>Drives the opening wizard: step navigation plus the live single-field demo embedded
/// in whichever step is current.</summary>
public partial class TutorialViewModel : ObservableObject
{
    private readonly IReadOnlyList<TutorialStep> _steps = TutorialContent.Create();

    public event EventHandler? CloseRequested;

    public TutorialViewModel()
    {
        DemoInput = _steps[0].Demo?.DefaultValue ?? string.Empty;
        DotStates = Enumerable.Range(0, StepCount).Select(i => i <= StepIndex).ToList();
        RebuildStepRows();
    }

    public IReadOnlyList<TutorialStepRow> StepRows { get; private set; } = Array.Empty<TutorialStepRow>();

    private void RebuildStepRows()
    {
        StepRows = _steps.Select((s, i) => new TutorialStepRow
        {
            Index = i,
            Step = s,
            IsCurrent = i == StepIndex,
            IsPast = i < StepIndex
        }).ToList();
        OnPropertyChanged(nameof(StepRows));
    }

    [RelayCommand]
    private void SetStep(int index) => StepIndex = index;

    [ObservableProperty]
    private int stepIndex;

    public TutorialStep CurrentStep => _steps[StepIndex];
    public int StepNumber => StepIndex + 1;
    public int StepCount => _steps.Count;
    public bool CanGoBack => StepIndex > 0;
    public bool IsLastStep => StepIndex == _steps.Count - 1;
    public string NextButtonLabel => IsLastStep ? "Start exploring →" : "Next →";

    public bool HasDemo => CurrentStep.Demo != null;
    public string? DemoFieldLabel => CurrentStep.Demo?.FieldLabel;
    public string? DemoHint => CurrentStep.Demo?.Hint;

    /// <summary>Which steps (by index) are at or before the current one — drives the progress dots.</summary>
    public IReadOnlyList<bool> DotStates { get; private set; } = Array.Empty<bool>();

    [ObservableProperty]
    private string demoInput = string.Empty;

    public string DemoSql => CurrentStep.Demo?.BuildSql(DemoInput) ?? string.Empty;

    // Computed once, here, and handed to every step's Simulate — not left for each step to
    // remember to call itself. A step that ignores the flag still can't misreport broken SQL as
    // an ordinary result, because the flag was already computed before Simulate ever ran.
    public SimulationResult? DemoResult => CurrentStep.Demo is { } demo
        ? demo.Simulate(DemoInput, SqlSyntaxChecker.HasSyntaxError(demo.BuildSql(DemoInput)))
        : null;

    partial void OnStepIndexChanged(int value)
    {
        DemoInput = CurrentStep.Demo?.DefaultValue ?? string.Empty;
        DotStates = Enumerable.Range(0, StepCount).Select(i => i <= StepIndex).ToList();

        OnPropertyChanged(nameof(CurrentStep));
        OnPropertyChanged(nameof(StepNumber));
        OnPropertyChanged(nameof(CanGoBack));
        OnPropertyChanged(nameof(IsLastStep));
        OnPropertyChanged(nameof(NextButtonLabel));
        OnPropertyChanged(nameof(HasDemo));
        OnPropertyChanged(nameof(DemoFieldLabel));
        OnPropertyChanged(nameof(DemoHint));
        OnPropertyChanged(nameof(DotStates));
        RebuildStepRows();
    }

    partial void OnDemoInputChanged(string value)
    {
        OnPropertyChanged(nameof(DemoSql));
        OnPropertyChanged(nameof(DemoResult));
    }

    [RelayCommand]
    private void Back()
    {
        if (CanGoBack) StepIndex--;
    }

    [RelayCommand]
    private void Next()
    {
        if (IsLastStep) CloseRequested?.Invoke(this, EventArgs.Empty);
        else StepIndex++;
    }

    [RelayCommand]
    private void Close() => CloseRequested?.Invoke(this, EventArgs.Empty);
}
