using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using ICSharpCode.AvalonEdit;
using Minion.InjectionLab.Core.Services;
using Minion.InjectionLab.Wpf.ViewModels;

namespace Minion.InjectionLab.Wpf.Behaviors;

/// <summary>
/// Attached property that paints the "your input, highlighted" background renderer onto an
/// AvalonEdit TextEditor. The editor's actual text content is set explicitly from
/// MainWindow.xaml.cs instead of via a bindable attached property — AvalonEdit's TextEditor has
/// no built-in bindable Text dependency property, and routing it through a custom one proved
/// unreliable (blank/stale text on scenario or fix-tab changes; see docs.md) — so this is called
/// directly from code (SetHighlightSegments), not bound in XAML.
/// </summary>
public static class AvalonEditBehavior
{
    public static readonly DependencyProperty HighlightSegmentsProperty =
        DependencyProperty.RegisterAttached("HighlightSegments", typeof(ObservableCollection<SqlSegment>), typeof(AvalonEditBehavior),
            new PropertyMetadata(null, OnHighlightSegmentsChanged));

    public static void SetHighlightSegments(DependencyObject element, ObservableCollection<SqlSegment> value) => element.SetValue(HighlightSegmentsProperty, value);
    public static ObservableCollection<SqlSegment> GetHighlightSegments(DependencyObject element) => (ObservableCollection<SqlSegment>)element.GetValue(HighlightSegmentsProperty);

    private static void OnHighlightSegmentsChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not TextEditor editor) return;

        var renderer = editor.TextArea.TextView.BackgroundRenderers
            .OfType<UserInputBackgroundRenderer>()
            .FirstOrDefault();

        if (renderer is null)
        {
            renderer = new UserInputBackgroundRenderer();
            editor.TextArea.TextView.BackgroundRenderers.Add(renderer);
        }

        renderer.Segments = e.NewValue as ObservableCollection<SqlSegment>;
        editor.TextArea.TextView.InvalidateLayer(ICSharpCode.AvalonEdit.Rendering.KnownLayer.Selection);
    }

    public static readonly DependencyProperty SyntaxIssuesProperty =
        DependencyProperty.RegisterAttached("SyntaxIssues", typeof(IReadOnlyList<SqlSyntaxIssue>), typeof(AvalonEditBehavior),
            new PropertyMetadata(null, OnSyntaxIssuesChanged));

    public static void SetSyntaxIssues(DependencyObject element, IReadOnlyList<SqlSyntaxIssue> value) => element.SetValue(SyntaxIssuesProperty, value);
    public static IReadOnlyList<SqlSyntaxIssue> GetSyntaxIssues(DependencyObject element) => (IReadOnlyList<SqlSyntaxIssue>)element.GetValue(SyntaxIssuesProperty);

    private static void OnSyntaxIssuesChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not TextEditor editor) return;

        var renderer = editor.TextArea.TextView.BackgroundRenderers
            .OfType<SquigglyUnderlineRenderer>()
            .FirstOrDefault();

        if (renderer is null)
        {
            renderer = new SquigglyUnderlineRenderer();
            editor.TextArea.TextView.BackgroundRenderers.Add(renderer);
        }

        renderer.Issues = e.NewValue as IReadOnlyList<SqlSyntaxIssue> ?? Array.Empty<SqlSyntaxIssue>();
        editor.TextArea.TextView.InvalidateLayer(ICSharpCode.AvalonEdit.Rendering.KnownLayer.Selection);
    }
}
