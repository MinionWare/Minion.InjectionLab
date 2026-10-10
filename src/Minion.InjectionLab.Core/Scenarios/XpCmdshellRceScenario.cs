using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>xp_cmdshell: the ceiling for SQL injection isn't "read some rows" — on a sysadmin
/// connection with this extended procedure enabled, it's full operating-system command execution.</summary>
public static class XpCmdshellRceScenario
{
    private const string Baseline = "1007";

    private static readonly string[] Keywords = { "XP_CMDSHELL" };
    private static readonly string[] ExpertKeywords = { "SP_CONFIGURE" };

    private static bool ContainsAny(string s, params string[] needles)
    {
        var lower = s.ToLowerInvariant();
        return needles.Any(lower.Contains);
    }

    private static string Classify(IReadOnlyDictionary<string, string> f)
        => ContainsAny(f["orderId"], "xp_cmdshell") && f["orderId"].Contains(';') ? "rce" : "normal";

    public static AttackScenario Create() => new()
    {
        Id = "xp-cmdshell-rce",
        Category = AttackCategory.PostInjectionImpact,
        Title = "xp_cmdshell Remote Code Execution",
        Premise = "The same order-lookup tool as the stacked-queries scenario — except this connection runs as " +
                  "a sysadmin-level login, the kind many legacy apps and internal tools still use because " +
                  "\"it was easier to set up.\" xp_cmdshell, the extended procedure that runs operating-system " +
                  "commands, is only a stacked statement away.",
        MockAppLabel = "Internal Tools — Order Lookup (legacy sysadmin connection)",
        BaselineValues = new Dictionary<string, string> { ["orderId"] = Baseline },
        Fields = new[] { new FormField { Key = "orderId", Label = "Order ID", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Normal lookup", Icon = "📦", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "rce", Label = "OS command executes", Icon = "💻", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT * FROM dbo.Orders WHERE OrderId = {f["orderId"]};",

        BuildVulnerableCSharp = f =>
            "// This connection string uses a sysadmin-level SQL login — common in legacy internal tools\n" +
            "var sql = $\"SELECT * FROM dbo.Orders WHERE OrderId = {orderId}\";\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "using var reader = cmd.ExecuteReader();",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT * FROM dbo.Orders WHERE OrderId = $orderId\"\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql",

        // Two real fixes, not equally complete: blocking the literal word "xp_cmdshell" (looks
        // like a fix, isn't one — sysadmin can just re-enable it first) vs. real parameterization.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block input containing \"xp_cmdshell\"",
                Grade = FixGrade.Partial,
                Gap = "At Beginner, checks for the literal uppercase word — lowercase sails through. " +
                      "Intermediate catches any casing. Expert also blocks \"sp_configure\" — but a sysadmin " +
                      "connection can re-enable xp_cmdshell under a different capitalization trick, through " +
                      "OPENROWSET, or via any number of other sysadmin-only features this filter was never told " +
                      "about. On a sysadmin connection, blacklisting one feature name was never going to be " +
                      "enough.",
                BuildSql = (f, d) =>
                {
                    bool blocked = KeywordBlacklist.IsBlocked(f["orderId"], d, Keywords, ExpertKeywords);
                    return blocked ? "-- Request rejected by the application; no SQL was ever built." : $"SELECT * FROM dbo.Orders WHERE OrderId = {f["orderId"]};";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["orderId"].Contains("xp_cmdshell", StringComparison.OrdinalIgnoreCase);
                    var guard = "if (orderId.Contains(\"xp_cmdshell\", StringComparison.OrdinalIgnoreCase))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"SELECT * FROM dbo.Orders WHERE OrderId = {orderId}\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["orderId"].Contains("xp_cmdshell", StringComparison.OrdinalIgnoreCase);
                    var guard = "if ($orderId -match '(?i)xp_cmdshell') { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"SELECT * FROM dbo.Orders WHERE OrderId = $orderId\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = KeywordBlacklist.IsBlocked(f["orderId"], d, Keywords, ExpertKeywords);
                    if (Classify(f) != "rce")
                        return new SimulationResult { Severity = Severity.Success, Headline = "Order 1007 found", Detail = "Ordinary lookup, the filter never engages." };
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Request rejected", Detail = "At this difficulty, the filter happened to catch this specific phrasing." };
                    return new SimulationResult
                    {
                        Severity = Severity.Critical,
                        Headline = "whoami returned NT AUTHORITY\\SYSTEM — the attacker now has an OS shell",
                        Detail = "The stacked statement called xp_cmdshell directly. Because this connection runs as " +
                                  "sysadmin, the call succeeds outright with no further escalation needed — SQL " +
                                  "injection just became complete control of the underlying Windows host.",
                        AffectedAssets = new[]
                        {
                            "Arbitrary operating-system command execution",
                            "Full compromise of the database server's host OS"
                        }
                    };
                }
            },
            new FixOption
            {
                Label = "✓ Parameterized query",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                    "EXEC sp_executesql N'SELECT * FROM dbo.Orders WHERE OrderId = @OrderId', N'@OrderId INT', @OrderId;\n\n" +
                    $"@OrderId = {f["orderId"]}  -- must parse as INT, or the call fails before touching SQL text",
                BuildCSharp = f =>
                    "using var cmd = new SqlCommand(\"SELECT * FROM dbo.Orders WHERE OrderId = @OrderId\", connection);\n" +
                    "cmd.Parameters.Add(\"@OrderId\", SqlDbType.Int).Value = orderId;",
                BuildPowerShell = f =>
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"SELECT * FROM dbo.Orders WHERE OrderId = @OrderId\", $connection\n" +
                    "[void]$cmd.Parameters.AddWithValue('@OrderId', [int]$orderId)",
                Simulate = (f, _) => Classify(f) == "rce"
                    ? new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "Rejected before it ever reaches the database",
                        Detail = "Neither a semicolon nor a procedure name parses as a valid integer, so the attempt " +
                                  "fails at the type-conversion layer — xp_cmdshell, sysadmin or not, never gets " +
                                  "called at all."
                    }
                    : new SimulationResult { Severity = Severity.Success, Headline = "Order 1007 found", Detail = "Ordinary lookup, unaffected by the fix." }
            }
        },

        SimulateVulnerable = f => Classify(f) == "rce"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "whoami returned NT AUTHORITY\\SYSTEM — the attacker now has an OS shell",
                Detail = "Stacked queries let a second, independent statement ride along after the semicolon — " +
                          "here, a direct call to xp_cmdshell. On a sysadmin connection, that call just works: " +
                          "no privilege escalation needed, no further exploit required. This is the ceiling SQL " +
                          "injection can reach — not \"read some rows,\" but arbitrary commands on the host itself.",
                AffectedAssets = new[]
                {
                    "Arbitrary operating-system command execution",
                    "Full compromise of the database server's host OS"
                }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Order 1007 found", Detail = "Ordinary lookup, nothing unusual happens." },

        HowItWorks =
            "xp_cmdshell is a real, documented SQL Server extended stored procedure that runs a string as an " +
            "operating-system command and returns its output as rows. It's disabled by default and normally only " +
            "runnable by sysadmin — but a huge number of legacy and internal tools still connect using a " +
            "sysadmin-level login for convenience. Combine that with any injectable query capable of stacking a " +
            "second statement, and the injection stops being a database problem entirely: it becomes a direct " +
            "line to the host's own command shell.",

        WhyTheFixWorks =
            "Same mechanism as the stacked-queries fix: once the OrderId value is bound as a typed parameter, a " +
            "semicolon inside it can't end the statement and start a new one, so there's no way to reach " +
            "xp_cmdshell — or anything else — through this input, regardless of what permissions the connection " +
            "itself has.",

        SamplePayloads = new[]
        {
            "1007; EXEC xp_cmdshell 'whoami'--",
            "1007; EXEC xp_cmdshell 'net user hacker Pwnd123! /add'--"
        },

        ChallengeGoal = "Get an operating-system command to execute through the order lookup.",
        Hints = new[]
        {
            "This connection runs as sysadmin — what extended procedure does SQL Server ship for running OS commands?",
            "You'll need to stack a second statement, the same way as the plain stacked-queries scenario."
        },
        ChallengeAnswer = "1007; EXEC xp_cmdshell 'whoami'--",

        TerminologyNote = "Named directly after the SQL Server extended stored procedure it calls — " +
                           "\"xp_cmdshell\" runs a string as a Windows command and is SQL Server's own, official " +
                           "(if dangerous) bridge from T-SQL to the operating system shell.",
        References = new[]
        {
            new ExternalReference { Label = "Hacking Articles — MSSQL for Pentester: Command Execution with xp_cmdshell", Url = "https://www.hackingarticles.in/mssql-for-pentester-command-execution-with-xp_cmdshell/" },
            new ExternalReference { Label = "StraightPathSQL — xp_cmdshell enabled check", Url = "https://straightpathsql.com/check/xp_cmdshell/" }
        }
    };
}
