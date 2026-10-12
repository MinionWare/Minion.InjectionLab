using System.Net.Http;
using System.Text.Json;

namespace Minion.InjectionLab.Wpf.Services;

public record UpdateInfo(string Version, string DownloadUrl, string ReleaseNotesUrl, bool IsCritical, string[] Features);

/// <summary>Checks minionware.io for a newer release — ported from IndexConsolidator's
/// UpdateService so every Minion.X app uses the same update-banner mechanism.</summary>
public static class UpdateService
{
    private const string AppVersion = "1.0.0";
    private const string ProductCode = "IL"; // Minion.InjectionLab
    private const string ApiBase = "https://api.minionware.io"; // swap when live

    public static async Task<UpdateInfo?> CheckAsync()
    {
#if DEBUG
        // Mock response — remove once the API is live
        await Task.Delay(400);
        return null; // flip to a real UpdateInfo(...) locally to test the banner/What's New window
#else
        try
        {
            var url = $"{ApiBase}/updates?product={ProductCode}&version={AppVersion}";

            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
            var json = await http.GetStringAsync(url);
            var doc = JsonDocument.Parse(json).RootElement;

            if (doc.TryGetProperty("up_to_date", out var upToDate) && upToDate.GetBoolean())
                return null;

            var features = doc.TryGetProperty("features", out var f)
                ? f.EnumerateArray().Select(x => x.GetString() ?? "").ToArray()
                : Array.Empty<string>();
            return new UpdateInfo(
                doc.GetProperty("current_version").GetString() ?? "",
                doc.GetProperty("download_url").GetString() ?? "",
                doc.GetProperty("release_notes_url").GetString() ?? "",
                doc.TryGetProperty("is_critical", out var crit) && crit.GetBoolean(),
                features);
        }
        catch
        {
            return null; // silently swallow — update check is best-effort
        }
#endif
    }
}
