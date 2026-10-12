using System.IO;
using System.Net.Http;
using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json;
using Minion.Shared.Config;

namespace Minion.InjectionLab.Wpf.Services;

public enum UpdateCheckFrequency { EveryStartup, Daily, Weekly, Never }

public sealed record UpdateFeature(string Title, string Summary, string? HelpUrl);

public sealed record UpdateManifest(string LatestVersion, string? ReleaseDate, string? DownloadUrl, string? ReleaseNotesUrl, List<UpdateFeature>? Features);

// Per-user "how often, and what have I already seen" state -- same
// IJSONHandler/section convention ThemeService already uses for its own
// %APPDATA%\Minion.InjectionLab\AppConfig.json.
public sealed record UpdateCheckSettings(UpdateCheckFrequency Frequency, string? SkippedVersion, DateTime? LastCheckedAtUtc)
{
    public UpdateCheckSettings() : this(UpdateCheckFrequency.EveryStartup, null, null) { }
}

// Fetches the user-hosted update manifest and decides whether it's actually
// time to check and whether what came back is worth telling anyone about.
// Every public entry point here is meant to be wrapped in try/catch by the
// caller (MainWindow's CheckForUpdatesAsync) -- a broken/unreachable manifest
// must never block or visibly disrupt startup.
public sealed class UpdateCheckService
{
    private const string Section = "UpdateCheck";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly IJSONHandler _json;

    public UpdateCheckService()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Minion.InjectionLab");
        Directory.CreateDirectory(dir);
        _json = new JSONHandler(Path.Combine(dir, "AppConfig.json"));
    }

    public UpdateCheckSettings LoadSettings()
    {
        try
        {
            return _json.GetSection<UpdateCheckSettings>(Section);
        }
        catch
        {
            return new UpdateCheckSettings();
        }
    }

    public void SaveSettings(UpdateCheckSettings settings) => _json.WriteOrUpdateSection(Section, settings);

    // Every-startup is always due; Daily/Weekly compare against the last
    // successful check regardless of whether that check found anything new,
    // so a quiet cadence doesn't hit the manifest URL every single launch.
    public static bool IsDue(UpdateCheckSettings settings, DateTime nowUtc)
    {
        if (settings.Frequency == UpdateCheckFrequency.Never) return false;
        if (settings.LastCheckedAtUtc is not { } lastChecked) return true;

        var minInterval = settings.Frequency switch
        {
            UpdateCheckFrequency.Daily => TimeSpan.FromDays(1),
            UpdateCheckFrequency.Weekly => TimeSpan.FromDays(7),
            _ => TimeSpan.Zero,
        };
        return nowUtc - lastChecked >= minInterval;
    }

    public static bool IsNewerThanRunning(string latestVersion)
    {
        var running = Assembly.GetExecutingAssembly().GetName().Version;
        return running is not null && Version.TryParse(latestVersion, out var latest) && latest > running;
    }

    public async Task<UpdateManifest?> CheckAsync(string manifestUrl)
    {
        using var client = new HttpClient();
        return await client.GetFromJsonAsync<UpdateManifest>(manifestUrl, JsonOptions);
    }
}
