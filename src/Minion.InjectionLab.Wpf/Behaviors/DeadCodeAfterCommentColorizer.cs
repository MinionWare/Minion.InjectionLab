using System;
using System.Windows;
using System.Windows.Media;
using ICSharpCode.AvalonEdit.Document;
using ICSharpCode.AvalonEdit.Rendering;

namespace Minion.InjectionLab.Wpf.Behaviors;

/// <summary>
/// SQL-tab only: once a line contains a literal "--", SQL Server treats everything after it (to
/// the end of the line) as a comment — dead code. Renders that span muted + strikethrough, on top
/// of whatever syntax color it already has, so a successful comment-truncation payload visibly
/// "kills" the rest of the query instead of just changing its color.
/// </summary>
public sealed class DeadCodeAfterCommentColorizer : DocumentColorizingTransformer
{
    private static readonly SolidColorBrush DeadBrush = CreateBrush();

    private static SolidColorBrush CreateBrush()
    {
        var brush = new SolidColorBrush(Color.FromRgb(0x4F, 0x55, 0x66));
        brush.Freeze();
        return brush;
    }

    protected override void ColorizeLine(DocumentLine line)
    {
        var text = CurrentContext.Document.GetText(line);
        var idx = text.IndexOf("--", StringComparison.Ordinal);
        if (idx < 0) return;

        ChangeLinePart(line.Offset + idx, line.EndOffset, element =>
        {
            element.TextRunProperties.SetForegroundBrush(DeadBrush);
            element.TextRunProperties.SetTextDecorations(TextDecorations.Strikethrough);
        });
    }
}
