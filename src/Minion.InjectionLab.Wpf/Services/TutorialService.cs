using System;
using System.IO;

namespace Minion.InjectionLab.Wpf.Services;

/// <summary>Tracks whether the opening wizard has been shown before, so it only auto-opens once
/// per machine — the nav button always reopens it on demand regardless of this flag.</summary>
public static class TutorialService
{
    private static readonly string MarkerPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "Minion.InjectionLab", "tutorial-seen.flag");

    public static bool HasSeenTutorial => File.Exists(MarkerPath);

    public static void MarkSeen()
    {
        var dir = Path.GetDirectoryName(MarkerPath)!;
        Directory.CreateDirectory(dir);
        File.WriteAllText(MarkerPath, DateTime.UtcNow.ToString("O"));
    }
}
