// HelpClient.cs: copy this one file into your application (.NET 6 or later, nothing to install).
//
// It asks HelpServer to show a help article by its support ID, and works out what to do when the help is not running.
//
//     var help = new HelpClient(new HelpClientOptions { BaseUrl = "http://localhost:5184", ExePath = @"C:\Tools\Help\HelpServer.exe" });
//     var result = await help.OpenAsync("1001");               // an article
//     var result = await help.OpenAsync("1001", "pricing");    // a section of it
//     if (!result.Success) { MessageBox.Show(result.Message); }
//
// Keep one HelpClient for the life of the application. Read BaseUrl and ExePath from your own configuration file, so that moving the help
// to another port or another server is a change to a setting, not to the program.

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace HelpServer.Client;

/// <summary>What happened to the request.</summary>
public enum HelpOutcome
{
    /// <summary>The article was shown in a help window that was already open.</summary>
    Shown,
    /// <summary>The help opened a new window at the article.</summary>
    Opened,
    /// <summary>The help had no window to use (or it runs on a server), so the article was opened in the default browser here.</summary>
    OpenedInBrowser,
    /// <summary>The help was not running. It was started and will open at the article.</summary>
    Started,
    /// <summary>The help is running but no article has that ID.</summary>
    NotFound,
    /// <summary>The help is not running and could not be started (no ExePath, or the file is missing).</summary>
    NotAvailable,
    /// <summary>The help is on a server that did not accept this Windows account.</summary>
    NotAllowed,
}

/// <summary>The answer. Show <see cref="Message"/> to the person when <see cref="Success"/> is false.</summary>
public sealed record HelpResult(HelpOutcome Outcome, string Message, string? Title = null, string? Url = null)
{
    public bool Success => Outcome is HelpOutcome.Shown or HelpOutcome.Opened or HelpOutcome.OpenedInBrowser or HelpOutcome.Started;
}

/// <summary>Where the help is. These come from the application's own configuration.</summary>
public sealed class HelpClientOptions
{
    /// <summary>The address of the help: the port is the one on the help's Context help page. Examples: http://localhost:5184 or https://help.contoso.com</summary>
    public string BaseUrl { get; set; } = "http://localhost:5184";

    /// <summary>Full path of HelpServer.exe, used to start the help when it is not running. Leave empty if it runs on a server.</summary>
    public string? ExePath { get; set; }

    /// <summary>Bring the help window to the front after showing an article in it.</summary>
    public bool RaiseWindow { get; set; } = true;

    /// <summary>How long to wait for the help to answer before deciding it is not running.</summary>
    public int TimeoutSeconds { get; set; } = 4;
}

public sealed class HelpClient : IDisposable
{
    private readonly HelpClientOptions options;
    private readonly HttpClient http;

    public HelpClient(HelpClientOptions options)
    {
        this.options = options;
        // default credentials: when the help is on a server that asks for a Windows sign-in, the person's own account is sent
        http = new HttpClient(new HttpClientHandler { UseDefaultCredentials = true }) { Timeout = TimeSpan.FromSeconds(Math.Max(1, options.TimeoutSeconds)) };
    }

    /// <summary>Shows the article with this support ID (a number or a readable key), at a section of it if one is given.</summary>
    public async Task<HelpResult> OpenAsync(string id, string? section = null, CancellationToken cancel = default)
    {
        if (string.IsNullOrWhiteSpace(id)) { return new HelpResult(HelpOutcome.NotFound, "There is no help for this."); }
        var url = $"{Base()}/__help/open?id={Uri.EscapeDataString(id.Trim())}" + (string.IsNullOrWhiteSpace(section) ? "" : $"&s={Uri.EscapeDataString(section.Trim())}");
        try
        {
            using var response = await http.GetAsync(url, cancel).ConfigureAwait(false);
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                return new HelpResult(HelpOutcome.NotAllowed, "The help server did not accept your Windows sign-in. Ask whoever looks after the help to give you access.");
            }
            var text = await response.Content.ReadAsStringAsync(cancel).ConfigureAwait(false);
            JsonElement json;
            try { json = JsonDocument.Parse(text).RootElement; }
            catch (JsonException)
            {
                // an empty 404 is HelpServer with context help switched off; anything else is some other program on that port
                return response.StatusCode == HttpStatusCode.NotFound
                    ? new HelpResult(HelpOutcome.NotAvailable, "Context help is switched off in the help (Settings, Context help).")
                    : NotAvailableOrStart(id, section, "That address answered, but it is not HelpServer.");
            }
            if (json.ValueKind != JsonValueKind.Object) { return NotAvailableOrStart(id, section, "That address answered, but it is not HelpServer."); }

            if (json.TryGetProperty("found", out var found) && found.ValueKind == JsonValueKind.False)
            {
                return new HelpResult(HelpOutcome.NotFound, $"There is no help article for {id}.");
            }
            if (!response.IsSuccessStatusCode) { return NotAvailableOrStart(id, section, $"The help answered with an error ({(int)response.StatusCode})."); }

            var title = json.TryGetProperty("title", out var t) ? t.GetString() : null;
            var address = json.TryGetProperty("url", out var u) ? u.GetString() : null;
            var delivered = json.TryGetProperty("delivered", out var d) ? d.GetString() : "none";
            switch (delivered)
            {
                case "window":
                    // the help program asked its own window to move; this program has just been clicked, so Windows lets *it* take the foreground
                    if (options.RaiseWindow && json.TryGetProperty("hwnd", out var h) && h.ValueKind == JsonValueKind.Number) { Raise(h.GetInt64()); }
                    return new HelpResult(HelpOutcome.Shown, "Shown in the help window.", title, address);
                case "launched":
                    return new HelpResult(HelpOutcome.Opened, "Opened the help.", title, address);
                default:
                    // nothing open that the server could use (or it is a server, which cannot open a window on this computer): open it here
                    if (address is null) { return new HelpResult(HelpOutcome.NotAvailable, "The help found the article but gave no address to open."); }
                    return OpenInBrowser(address, title);
            }
        }
        catch (Exception ex) when (ex is (HttpRequestException or OperationCanceledException) && !cancel.IsCancellationRequested)
        {
            return NotAvailableOrStart(id, section, "The help is not running.");
        }
    }

    /// <summary>The address of an article, to put in an e-mail, a log or a hyperlink in the application. Opens through the help's redirect.</summary>
    public string LinkFor(string id, string? section = null) =>
        $"{Base()}/go/{Uri.EscapeDataString(id.Trim())}" + (string.IsNullOrWhiteSpace(section) ? "" : $"?s={Uri.EscapeDataString(section.Trim())}");

    /// <summary>True when the help answers (useful to hide or grey a Help button when it will not work).</summary>
    public async Task<bool> IsAvailableAsync(CancellationToken cancel = default)
    {
        try { using var r = await http.GetAsync(Base() + "/__help/settings", cancel).ConfigureAwait(false); return r.IsSuccessStatusCode; }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException) { return false; }
    }

    public void Dispose() => http.Dispose();

    private string Base() => options.BaseUrl.Trim().TrimEnd('/');

    private HelpResult NotAvailableOrStart(string id, string? section, string reason)
    {
        if (string.IsNullOrWhiteSpace(options.ExePath) || !File.Exists(options.ExePath))
        {
            return new HelpResult(HelpOutcome.NotAvailable, reason + " Help cannot be shown right now.");
        }
        try
        {
            // HelpServer.exe --goto starts the help (on its own configured port) and opens a window at the article
            var start = new ProcessStartInfo(options.ExePath) { UseShellExecute = false, WorkingDirectory = Path.GetDirectoryName(options.ExePath)! };
            start.ArgumentList.Add("--goto"); start.ArgumentList.Add(id.Trim());
            if (!string.IsNullOrWhiteSpace(section)) { start.ArgumentList.Add("--section"); start.ArgumentList.Add(section.Trim()); }
            if (!string.IsNullOrWhiteSpace(options.BaseUrl)) { start.ArgumentList.Add("--url"); start.ArgumentList.Add(Base()); }
            Process.Start(start);
            return new HelpResult(HelpOutcome.Started, "Starting the help…");
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return new HelpResult(HelpOutcome.NotAvailable, $"{reason} It could not be started: {ex.Message}");
        }
    }

    private static HelpResult OpenInBrowser(string address, string? title)
    {
        try { Process.Start(new ProcessStartInfo(address) { UseShellExecute = true }); return new HelpResult(HelpOutcome.OpenedInBrowser, "Opened the help in your browser.", title, address); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return new HelpResult(HelpOutcome.NotAvailable, $"The article could not be opened in a browser: {ex.Message}", title, address);
        }
    }

    // ---- bringing a window to the front (Windows only; best effort: Windows decides who may take the foreground)
    [DllImport("user32.dll")] private static extern bool IsIconic(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hWnd, int cmd);
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hWnd);

    private static void Raise(long handle)
    {
        if (!OperatingSystem.IsWindows() || handle == 0) { return; }
        var h = new IntPtr(handle);
        if (IsIconic(h)) { ShowWindow(h, 9); }   // SW_RESTORE
        SetForegroundWindow(h);
    }
}
