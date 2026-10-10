using System.Text.RegularExpressions;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Services;

/// <summary>
/// The "naive blacklist" partial fix, shared by every scenario that demonstrates one, gets
/// measurably stricter as Difficulty increases — this is the one place that logic lives, so all
/// five scenarios using it behave identically and nobody has to re-derive the rules per file.
/// </summary>
public static class KeywordBlacklist
{
    /// <summary>
    /// Beginner: case-sensitive match on <paramref name="keywords"/> only — a lowercase payload
    /// sails straight through. Intermediate: the same keywords, case-insensitive. Expert: case-
    /// insensitive, plus <paramref name="extraAtExpert"/> if given. Always matched on word
    /// boundaries (like real keyword filters do, to avoid flagging ordinary words that merely
    /// contain the keyword as a substring — e.g. "correct" contains "or") — which is also exactly
    /// why word-boundary filters are themselves a known, separately bypassable pattern in the
    /// real world, not just a simplification here.
    /// </summary>
    public static bool IsBlocked(string text, DifficultyLevel difficulty, string[] keywords, string[]? extraAtExpert = null)
    {
        var active = difficulty == DifficultyLevel.Expert && extraAtExpert is { Length: > 0 }
            ? keywords.Concat(extraAtExpert).ToArray()
            : keywords;

        var options = difficulty == DifficultyLevel.Beginner ? RegexOptions.None : RegexOptions.IgnoreCase;

        return active.Any(k => Regex.IsMatch(text, $@"\b{Regex.Escape(k)}\b", options));
    }
}
