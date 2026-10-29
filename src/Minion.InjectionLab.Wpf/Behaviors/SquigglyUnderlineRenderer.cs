using System.Windows;
using System.Windows.Media;
using ICSharpCode.AvalonEdit.Document;
using ICSharpCode.AvalonEdit.Rendering;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Wpf.Behaviors;

/// <summary>
/// Draws a red wavy underline under every live ScriptDom parse error — the same squiggly a code
/// editor uses for "this doesn't compile," so a syntax mistake in a typed payload reads as a
/// mistake rather than as the lesson being broken. Spans are recomputed by MainWindow.xaml.cs's
/// SetEditor every time the SQL text changes, and the squiggly disappears the moment the text
/// parses cleanly.
/// </summary>
public sealed class SquigglyUnderlineRenderer : IBackgroundRenderer
{
    public IReadOnlyList<SqlSyntaxIssue> Issues { get; set; } = Array.Empty<SqlSyntaxIssue>();

    public KnownLayer Layer => KnownLayer.Selection;

    public void Draw(TextView textView, DrawingContext drawingContext)
    {
        if (Issues.Count == 0) return;
        textView.EnsureVisualLines();

        var pen = CreatePen(textView);
        var documentLength = textView.Document.TextLength;

        foreach (var issue in Issues)
        {
            var length = Math.Min(issue.Length, documentLength - issue.Offset);
            if (length <= 0) continue;

            var builder = new BackgroundGeometryBuilder { AlignToWholePixels = true };
            builder.AddSegment(textView, new TextSegment { StartOffset = issue.Offset, Length = length });
            var geometry = builder.CreateGeometry();
            if (geometry is null) continue;

            foreach (var rect in GeometryToRects(geometry))
                DrawSquiggly(drawingContext, pen, rect);
        }
    }

    // The merged geometry can span multiple visual lines (wrapped text) — walking its bounds as
    // one rectangle would draw a squiggly across the gap between lines, so split back out per-line.
    private static IEnumerable<Rect> GeometryToRects(Geometry geometry)
    {
        var bounds = geometry.Bounds;
        if (!bounds.IsEmpty) yield return bounds;
    }

    private static void DrawSquiggly(DrawingContext dc, Pen pen, Rect bounds)
    {
        const double amplitude = 1.6;
        const double step = 4.0;
        var y = bounds.Bottom - 1;

        var geometry = new StreamGeometry();
        using (var ctx = geometry.Open())
        {
            ctx.BeginFigure(new Point(bounds.Left, y), false, false);
            var up = true;
            for (var x = bounds.Left + step; x < bounds.Right + step; x += step)
            {
                ctx.LineTo(new Point(Math.Min(x, bounds.Right), y + (up ? -amplitude : amplitude)), true, false);
                up = !up;
            }
        }
        geometry.Freeze();
        dc.DrawGeometry(null, pen, geometry);
    }

    // Not frozen: the brush comes from a DynamicResource (so it recolors on theme change, same as
    // every other themed brush in the app), and a Pen can't be frozen while it references one.
    private static Pen CreatePen(TextView textView)
    {
        var brush = (textView.FindResource("Brush.Critical") as Brush) ?? Brushes.Red;
        return new Pen(brush, 1.3);
    }
}
