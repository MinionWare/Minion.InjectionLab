using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using ICSharpCode.AvalonEdit;
using Minion.InjectionLab.Wpf.ViewModels;

namespace Minion.InjectionLab.Wpf.Behaviors;

/// <summary>
/// Attached properties that make an AvalonEdit TextEditor usable from MVVM/XAML: binding its
/// text content (TextEditor has no built-in bindable Text dependency property) and attaching
/// the "your input, highlighted" background renderer.
/// </summary>
public static class AvalonEditBehavior
{
    // Belt-and-suspenders: only reapply the Loaded-time hook once per editor instance.
    private static readonly HashSet<TextEditor> LoadedHooked = new();

    public static readonly DependencyProperty BoundTextProperty =
        DependencyProperty.RegisterAttached("BoundText", typeof(string), typeof(AvalonEditBehavior),
            new PropertyMetadata(string.Empty, OnBoundTextChanged));

    public static void SetBoundText(DependencyObject element, string value) => element.SetValue(BoundTextProperty, value);
    public static string GetBoundText(DependencyObject element) => (string)element.GetValue(BoundTextProperty);

    private static void OnBoundTextChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not TextEditor editor) return;
        ApplyText(editor, e.NewValue as string ?? string.Empty);

        // AvalonEdit's Document can be touched again during template application, which can
        // happen after this callback fires for the very first bound value — reapply once the
        // control is actually loaded so the first value can't get silently lost.
        if (LoadedHooked.Add(editor))
        {
            editor.Loaded += (s, _) => ApplyText((TextEditor)s!, GetBoundText((TextEditor)s!));
        }
    }

    private static void ApplyText(TextEditor editor, string text)
    {
        if (editor.Document.Text != text)
            editor.Document.Text = text;
    }

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
}
