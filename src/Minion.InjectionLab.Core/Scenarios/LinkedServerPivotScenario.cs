using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Linked-server pivoting: the injection never has to touch the sensitive data directly —
/// it just has to reach a server that already trusts this one.</summary>
public static class LinkedServerPivotScenario
{
    private const string Baseline = "RPT-2001";

    private static readonly string[] Keywords = { "OPENQUERY" };
    private static readonly string[] ExpertKeywords = { "OPENROWSET" };

    private static bool ContainsAny(string s, params string[] needles)
    {
        var lower = s.ToLowerInvariant();
        return needles.Any(lower.Contains);
    }

    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var s = f["reference"];
        return s.Contains(';') && ContainsAny(s, "openquery", "openrowset", "exec(") ? "pivot" : "normal";
    }

    public static AttackScenario Create() => new()
    {
        Id = "linked-server-pivot",
        Category = AttackCategory.PostInjectionImpact,
        Title = "Linked-Server Pivoting",
        Premise = "An internal reporting tool queries its own, fairly low-value reporting database — but that " +
                  "database server has a linked server configured to a much more sensitive Finance instance, " +
                  "mapped to a SQL login with real access on the remote side. The reporting login itself has " +
                  "almost no permissions at all.",
        MockAppLabel = "Internal Tools — Report Lookup",
        BaselineValues = new Dictionary<string, string> { ["reference"] = Baseline },
        Fields = new[] { new FormField { Key = "reference", Label = "Report reference", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Normal lookup", Icon = "📄", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "pivot", Label = "Pivots to another server", Icon = "🌉", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT * FROM dbo.Reports WHERE Reference = '{f["reference"]}';",

        BuildVulnerableCSharp = f =>
            "var sql = $\"SELECT * FROM dbo.Reports WHERE Reference = '{reference}'\";\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "using var reader = cmd.ExecuteReader();",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT * FROM dbo.Reports WHERE Reference = '$reference'\"\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql",

        // Two real fixes, not equally complete: blocking OPENQUERY (looks like a fix, isn't one —
        // EXEC(...) AT reaches the same linked server a different way) vs. real parameterization.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block input containing \"OPENQUERY\"",
                Grade = FixGrade.Partial,
                Gap = "At Beginner, checks for the literal uppercase word — lowercase sails through. " +
                      "Intermediate catches any casing. Expert also blocks \"OPENROWSET\" — but SQL Server has a " +
                      "third way to reach a linked server, EXEC(...) AT, that this filter never checks for at any " +
                      "difficulty.",
                BuildSql = (f, d) =>
                {
                    bool blocked = KeywordBlacklist.IsBlocked(f["reference"], d, Keywords, ExpertKeywords);
                    return blocked ? "-- Request rejected by the application; no SQL was ever built." : $"SELECT * FROM dbo.Reports WHERE Reference = '{f["reference"]}';";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["reference"].Contains("OPENQUERY", StringComparison.OrdinalIgnoreCase);
                    var guard = "if (reference.Contains(\"OPENQUERY\", StringComparison.OrdinalIgnoreCase))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"SELECT * FROM dbo.Reports WHERE Reference = '{reference}'\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["reference"].Contains("OPENQUERY", StringComparison.OrdinalIgnoreCase);
                    var guard = "if ($reference -match '(?i)openquery') { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"SELECT * FROM dbo.Reports WHERE Reference = '$reference'\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = KeywordBlacklist.IsBlocked(f["reference"], d, Keywords, ExpertKeywords);
                    if (Classify(f) != "pivot")
                        return new SimulationResult { Severity = Severity.Success, Headline = "Report found", Detail = "Ordinary reference, the filter never engages." };
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Request rejected", Detail = "At this difficulty, the filter happened to catch this specific pivot method." };
                    return new SimulationResult
                    {
                        Severity = Severity.Critical,
                        Headline = "Real card numbers returned — fetched from the Finance server, not this one",
                        Detail = "EXEC(...) AT reaches the exact same linked server as OPENQUERY, through completely " +
                                  "different syntax this filter was never told about. The reporting login's own " +
                                  "near-zero permissions never come into it — the linked server's own credential " +
                                  "mapping does all the work.",
                        AffectedAssets = new[] { "Finance.dbo.Payments — read via a trusted linked-server connection on a different SQL Server instance" }
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
                    "cmd.Parameters.AddWithValue(\"@Reference\", reference);",
                BuildPowerShell = f =>
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"SELECT * FROM dbo.Reports WHERE Reference = @Reference\", $connection\n" +
                    "[void]$cmd.Parameters.AddWithValue('@Reference', $reference)",
                Simulate = (f, _) => new SimulationResult
                {
                    Severity = Classify(f) == "pivot" ? Severity.Blocked : Severity.Success,
                    Headline = Classify(f) == "pivot" ? "Report not found" : "Report found",
                    Detail = Classify(f) == "pivot"
                        ? "The semicolon and everything after it are just literal text inside the parameter value " +
                          "now — there's no SQL left to parse as a second statement, so the linked server is never " +
                          "reached at all."
                        : "Ordinary reference, unaffected by the fix."
                }
            }
        },

        SimulateVulnerable = f => Classify(f) == "pivot"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Real card numbers returned — fetched from the Finance server, not this one",
                Detail = "A stacked statement calls OPENQUERY against the configured linked server. SQL Server " +
                          "doesn't re-check the local login's own permissions for that call — it uses whatever " +
                          "credential the linked server was configured with, which is very often far more " +
                          "privileged than the application's own low-value reporting login.",
                AffectedAssets = new[] { "Finance.dbo.Payments — read via a trusted linked-server connection on a different SQL Server instance" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Report found", Detail = "Ordinary reference, nothing unusual happens." },

        HowItWorks =
            "A linked server is a standing trust relationship between two SQL Server instances, usually set up so " +
            "legitimate cross-database reporting doesn't need its own separate login on the remote side. " +
            "OPENQUERY (and OPENROWSET, and EXEC ... AT) all let one SQL Server instance run a query against " +
            "that linked server — using whatever credential the link itself was configured with, not the " +
            "permissions of whoever is currently connected locally. A stacked-query injection doesn't need to " +
            "find anything sensitive on the local server at all; it just needs to reach a linked server that " +
            "already has access to something better.",

        WhyTheFixWorks =
            "Same mechanism as every other stacked-query fix here: once the reference value is bound as data, a " +
            "semicolon inside it can't end the statement and start a new one, so OPENQUERY (or any other pivot " +
            "syntax) is never reached, regardless of which linked servers are configured.",

        SamplePayloads = new[]
        {
            "RPT-2001'; SELECT * FROM OPENQUERY(FinanceDB, 'SELECT CardNumber FROM Finance.dbo.Payments'); --",
            "RPT-2001'; EXEC('SELECT CardNumber FROM Finance.dbo.Payments') AT FinanceDB; --"
        },

        ChallengeGoal = "Read data from the Finance server through the reporting tool's own lookup field.",
        Hints = new[]
        {
            "The reporting login itself barely has any permissions — think about what OTHER server this one might be configured to trust.",
            "SQL Server can run a query against a linked server with OPENQUERY — you'll still need to stack it as a second statement."
        },
        ChallengeAnswer = "RPT-2001'; SELECT * FROM OPENQUERY(FinanceDB, 'SELECT CardNumber FROM Finance.dbo.Payments'); --",

        TerminologyNote = "Named for the mechanism, not a new injection technique: \"pivoting\" means using one " +
                           "compromised foothold to reach a second, different system — here, across a configured " +
                           "linked-server trust relationship via OPENQUERY/OPENROWSET/EXEC ... AT, rather than " +
                           "anything new about how the injection itself works.",
        References = new[]
        {
            new ExternalReference { Label = "NetSPI — How to Hack Database Links in SQL Server", Url = "https://www.netspi.com/blog/technical-blog/network-pentesting/how-to-hack-database-links-in-sql-server/" },
            new ExternalReference { Label = "Microsoft Learn — Linked Servers (OPENQUERY, OPENROWSET, EXEC AT)", Url = "https://learn.microsoft.com/sql/relational-databases/linked-servers/linked-servers-openquery-openrowset-exec-at" }
        }
    };
}
