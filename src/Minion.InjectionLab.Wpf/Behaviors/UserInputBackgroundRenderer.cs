using System.Collections.ObjectModel;
using System.Windows.Media;
using ICSharpCode.AvalonEdit.Document;
using ICSharpCode.AvalonEdit.Rendering;
using Minion.InjectionLab.Wpf.ViewModels;

namespace Minion.InjectionLab.Wpf.Behaviors;

/// <summary>
/// Draws a highlighter-style background wash behind whichever spans of the editor's text came
/// verbatim from the form fields — layered on top of AvalonEdit's normal syntax highlighting,
/// so "this is your input" stays visible regardless of what color the SQL/C#/PowerShell
/// highlighter assigned the same text (string, keyword, etc).
/// </summary>
public sealed class UserInputBackgroundRenderer : IBackgroundRenderer
{
    private static readonly Brush HighlightBrush = new SolidColorBrush(Color.FromArgb(0xDF, 0xE8, 0xC5, 0x47));

    public ObservableCollection<SqlSegment>? Segments { get; set; }

    public KnownLayer Layer => KnownLayer.Selection;

    public void Draw(TextView textView, DrawingContext drawingContext)
    {
        if (Segments is null || Segments.Count == 0) return;
        textView.EnsureVisualLines();

        int offset = 0;
        foreach (var segment in Segments)
        {
            int length = segment.Text.Length;
            if (segment.IsUserInput && length > 0)
            {
                var builder = new BackgroundGeometryBuilder { CornerRadius = 2, AlignToWholePixels = true };
                builder.AddSegment(textView, new TextSegment { StartOffset = offset, Length = length });
                var geometry = builder.CreateGeometry();
                if (geometry != null)
                    drawingContext.DrawGeometry(HighlightBrush, null, geometry);
            }
            offset += length;
        }
    }
}
