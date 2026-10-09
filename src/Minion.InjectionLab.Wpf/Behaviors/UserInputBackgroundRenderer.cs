using System.Collections.ObjectModel;
using System.Windows.Media;
using ICSharpCode.AvalonEdit.Document;
using ICSharpCode.AvalonEdit.Rendering;
using Minion.InjectionLab.Wpf.ViewModels;

namespace Minion.InjectionLab.Wpf.Behaviors;

/// <summary>
/// Draws a dashed outline box around whichever spans of the editor's text came verbatim from
/// the form fields — layered on top of AvalonEdit's normal syntax highlighting. An outline
/// (rather than a filled background or a foreground color) never changes the text's own syntax
/// color, so it reads as "this is your input" without being mistaken for a string/keyword/error.
/// </summary>
public sealed class UserInputBackgroundRenderer : IBackgroundRenderer
{
    private static readonly Pen OutlinePen = CreatePen();

    private static Pen CreatePen()
    {
        var pen = new Pen(new SolidColorBrush(Color.FromRgb(0xE0, 0x5C, 0xC9)), 1.4)
        {
            DashStyle = DashStyles.Dot
        };
        pen.Freeze();
        return pen;
    }

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
                    drawingContext.DrawGeometry(null, OutlinePen, geometry);
            }
            offset += length;
        }
    }
}
