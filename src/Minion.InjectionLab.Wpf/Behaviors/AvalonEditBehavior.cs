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
    public static readonly DependencyProperty BoundTextProperty =
        DependencyProperty.RegisterAttached("BoundText", typeof(string), typeof(AvalonEditBehavior),
            new PropertyMetadata(string.Empty, OnBoundTextChanged));

    public static void SetBoundText(DependencyObject element, string value) => element.SetValue(BoundTextProperty, value);
    public static string GetBoundText(DependencyObject element) => (string)element.GetValue(BoundTextProperty);

    private static void OnBoundTextChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not TextEditor editor) return;
        var newText = e.NewValue as string ?? string.Empty;
        if (editor.Document.Text != newText)
            editor.Document.Text = newText;
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
