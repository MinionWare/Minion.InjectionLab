using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using Minion.InjectionLab.Wpf.ViewModels;

namespace Minion.InjectionLab.Wpf.Behaviors;

/// <summary>
/// Attached property: binds an ObservableCollection&lt;SqlSegment&gt; to a TextBlock and
/// renders it as Inlines, coloring user-supplied text differently from app-authored SQL.
/// </summary>
public static class HighlightedSqlBehavior
{
    public static readonly DependencyProperty SegmentsProperty =
        DependencyProperty.RegisterAttached(
            "Segments",
            typeof(ObservableCollection<SqlSegment>),
            typeof(HighlightedSqlBehavior),
            new PropertyMetadata(null, OnSegmentsChanged));

    public static void SetSegments(DependencyObject element, ObservableCollection<SqlSegment>? value)
        => element.SetValue(SegmentsProperty, value);

    public static ObservableCollection<SqlSegment>? GetSegments(DependencyObject element)
        => (ObservableCollection<SqlSegment>?)element.GetValue(SegmentsProperty);

    private static void OnSegmentsChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not TextBlock textBlock) return;

        Rebuild(textBlock, e.NewValue as ObservableCollection<SqlSegment>);

        if (e.OldValue is ObservableCollection<SqlSegment> oldCollection)
            oldCollection.CollectionChanged -= (_, _) => Rebuild(textBlock, GetSegments(textBlock));

        if (e.NewValue is ObservableCollection<SqlSegment> newCollection)
            newCollection.CollectionChanged += (_, _) => Rebuild(textBlock, GetSegments(textBlock));
    }

    private static void Rebuild(TextBlock textBlock, ObservableCollection<SqlSegment>? segments)
    {
        textBlock.Inlines.Clear();
        if (segments is null) return;

        var codeBrush = (System.Windows.Media.Brush)textBlock.FindResource("Brush.CodeText");
        var injectedBrush = (System.Windows.Media.Brush)textBlock.FindResource("Brush.CodeInjected");

        foreach (var segment in segments)
        {
            var lines = segment.Text.Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                var run = new Run(lines[i])
                {
                    Foreground = segment.IsUserInput ? injectedBrush : codeBrush,
                    FontWeight = segment.IsUserInput ? FontWeights.Bold : FontWeights.Normal
                };
                textBlock.Inlines.Add(run);
                if (i < lines.Length - 1)
                    textBlock.Inlines.Add(new LineBreak());
            }
        }
    }
}
