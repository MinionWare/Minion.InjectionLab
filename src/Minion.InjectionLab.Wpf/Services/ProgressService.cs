using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Minion.InjectionLab.Wpf.Services;

/// <summary>Tracks which scenarios (by AttackScenario.Id) have been "cleared" — Challenge mode on,
/// and a submit/live result that classified as Malicious at least once. Persisted next to
/// TutorialService's marker so both survive reinstalls the same way.</summary>
public static class ProgressService
{
    private static readonly string StorePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "Minion.InjectionLab", "progress.json");

    private static readonly HashSet<string> Cleared = Load();

    public static bool IsCleared(string scenarioId) => Cleared.Contains(scenarioId);

    public static int ClearedCount => Cleared.Count;

    public static event Action? Changed;

    public static void MarkCleared(string scenarioId)
    {
        if (!Cleared.Add(scenarioId)) return; // already cleared — no-op, no re-save
        Save();
        Changed?.Invoke();
    }

    private static HashSet<string> Load()
    {
        try
        {
            if (!File.Exists(StorePath)) return new HashSet<string>();
            var ids = JsonSerializer.Deserialize<string[]>(File.ReadAllText(StorePath));
            return ids != null ? new HashSet<string>(ids) : new HashSet<string>();
        }
        catch
        {
            // A corrupt or unreadable progress file shouldn't block the app from starting —
            // just start with nothing cleared.
            return new HashSet<string>();
        }
    }

    private static void Save()
    {
        var dir = Path.GetDirectoryName(StorePath)!;
        Directory.CreateDirectory(dir);
        File.WriteAllText(StorePath, JsonSerializer.Serialize(Cleared.ToArray()));
    }
}
