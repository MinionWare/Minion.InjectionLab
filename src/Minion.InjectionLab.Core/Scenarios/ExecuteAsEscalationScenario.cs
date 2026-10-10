using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>EXECUTE AS escalation: a stored procedure built to run as a highly-privileged account
/// makes any injection reachable through it run with that same privilege — not the caller's.</summary>
public static class ExecuteAsEscalationScenario
{
    private const string Baseline = "Nike Air";

    private static readonly string[] Keywords = { "UNION" };
    private static readonly string[] ExpertKeywords = { "SELECT" };

    private static string Classify(IReadOnlyDictionary<string, string> f)
        => f["search"].Contains("union", StringComparison.OrdinalIgnoreCase) ? "escalation" : "normal";

    public static AttackScenario Create() => new()
    {
        Id = "execute-as-escalation",
        Category = AttackCategory.IdentifiersAndDynamicSql,
        Title = "EXECUTE AS Escalation",
        Premise = "A reporting stored procedure builds dynamic SQL from a search term — and because low-" +
                  "privileged reporting users shouldn't need direct table access, the procedure was created WITH " +
                  "EXECUTE AS OWNER, so it always runs as the database owner, regardless of who calls it.",
        MockAppLabel = "Reporting Portal — Product Search",
        BaselineValues = new Dictionary<string, string> { ["search"] = Baseline },
        Fields = new[] { new FormField { Key = "search", Label = "Search for a product", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Normal search", Icon = "🔍", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "escalation", Label = "Runs as the database owner", Icon = "👑", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f =>
            "CREATE PROCEDURE dbo.SearchProducts\n" +
            "    @SearchTerm NVARCHAR(100)\n" +
            "WITH EXECUTE AS OWNER\n" +
            "AS\n" +
            "BEGIN\n" +
           $"    EXEC('SELECT ProductName, Price FROM dbo.Products WHERE ProductName LIKE ''%{f["search"]}%''');\n" +
            "END;\n\n" +
            "-- The reporting login has EXECUTE on this proc only — no direct SELECT on any table.\n" +
            "-- Everything inside it, including the EXEC(...) above, runs as the database owner instead.",

        BuildVulnerableCSharp = f =>
            "// Caller only needs EXECUTE permission on the procedure — not on any table it touches\n" +
            "using var cmd = new SqlCommand(\"dbo.SearchProducts\", connection) { CommandType = CommandType.StoredProcedure };\n" +
            "cmd.Parameters.AddWithValue(\"@SearchTerm\", search);\n" +
            "using var reader = cmd.ExecuteReader(); // the proc's own EXEC(...) still concatenates @SearchTerm unsafely inside",

        BuildVulnerablePowerShell = f =>
            "$cmd = New-Object System.Data.SqlClient.SqlCommand \"dbo.SearchProducts\", $connection\n" +
            "$cmd.CommandType = [System.Data.CommandType]::StoredProcedure\n" +
            "[void]$cmd.Parameters.AddWithValue('@SearchTerm', $search)\n" +
            "$reader = $cmd.ExecuteReader()",

        // Two real fixes, not equally complete: a keyword blacklist inside the proc (looks like a
        // fix, isn't one) vs. parameterizing the dynamic SQL the proc itself builds.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block search terms containing \"UNION\"",
                Grade = FixGrade.Partial,
                Gap = "At Beginner, checks for the literal uppercase word \"UNION\" inside the procedure — " +
                      "lowercase sails through. Intermediate catches any casing. Expert also blocks \"SELECT\". " +
                      "None of that changes what the injected SQL runs AS: whatever gets past the filter still " +
                      "executes with the database owner's full privileges, not the caller's.",
                BuildSql = (f, d) =>
                {
                    bool blocked = KeywordBlacklist.IsBlocked(f["search"], d, Keywords, ExpertKeywords);
                    var guard = "IF @SearchTerm LIKE '%UNION%' RETURN;\n\n";
                    return blocked
                        ? guard.TrimEnd()
                        : guard +
                          "CREATE PROCEDURE dbo.SearchProducts @SearchTerm NVARCHAR(100) WITH EXECUTE AS OWNER AS\n" +
                          "BEGIN\n" +
                         $"    EXEC('SELECT ProductName, Price FROM dbo.Products WHERE ProductName LIKE ''%{f["search"]}%''');\n" +
                          "END;";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["search"].Contains("UNION", StringComparison.OrdinalIgnoreCase);
                    var guard = "// Inside the procedure itself:\nIF @SearchTerm LIKE '%UNION%' RETURN;\n\n";
                    var vulnerable = "using var cmd = new SqlCommand(\"dbo.SearchProducts\", connection) { CommandType = CommandType.StoredProcedure };\n" +
                                     "cmd.Parameters.AddWithValue(\"@SearchTerm\", search);\n" +
                                     "using var reader = cmd.ExecuteReader();";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["search"].Contains("UNION", StringComparison.OrdinalIgnoreCase);
                    var guard = "# Inside the procedure itself:\n# IF @SearchTerm LIKE '%UNION%' RETURN;\n\n";
                    var vulnerable = "$cmd = New-Object System.Data.SqlClient.SqlCommand \"dbo.SearchProducts\", $connection\n" +
                                      "$cmd.CommandType = [System.Data.CommandType]::StoredProcedure\n" +
                                      "[void]$cmd.Parameters.AddWithValue('@SearchTerm', $search)\n" +
                                      "$reader = $cmd.ExecuteReader()";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = KeywordBlacklist.IsBlocked(f["search"], d, Keywords, ExpertKeywords);
                    if (Classify(f) != "escalation")
                        return new SimulationResult { Severity = Severity.Success, Headline = "Search completed", Detail = "Ordinary search, the filter never engages." };
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Request rejected", Detail = "At this difficulty, the filter happened to catch this specific phrasing." };
                    return new SimulationResult
                    {
                        Severity = Severity.Critical,
                        Headline = "Password hashes returned — fetched by the database owner, not the reporting login",
                        Detail = "The reporting login still has no direct table access at all — but the UNION SELECT " +
                                  "runs INSIDE a procedure that executes as the database owner. The caller's own " +
                                  "(deliberately minimal) permissions never come into it.",
                        AffectedAssets = new[] { "dbo.Users — read via a login that was never granted direct table access" }
                    };
                }
            },
            new FixOption
            {
                Label = "✓ Parameterize the dynamic SQL inside the procedure",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                    "CREATE PROCEDURE dbo.SearchProducts @SearchTerm NVARCHAR(100) WITH EXECUTE AS OWNER AS\n" +
                    "BEGIN\n" +
                    "    EXEC sp_executesql N'SELECT ProductName, Price FROM dbo.Products WHERE ProductName LIKE ''%'' + @Term + ''%''',\n" +
                    "        N'@Term NVARCHAR(100)', @Term = @SearchTerm;\n" +
                    "END;\n\n" +
                   $"@SearchTerm = {f["search"]}",
                BuildCSharp = f =>
                    "// Inside the procedure: the dynamic SQL is now ALSO parameterized\n" +
                    "EXEC sp_executesql N'SELECT ProductName, Price FROM dbo.Products WHERE ProductName LIKE ''%'' + @Term + ''%''', N'@Term NVARCHAR(100)', @Term = @SearchTerm;\n\n" +
                    "using var cmd = new SqlCommand(\"dbo.SearchProducts\", connection) { CommandType = CommandType.StoredProcedure };\n" +
                    "cmd.Parameters.AddWithValue(\"@SearchTerm\", search);",
                BuildPowerShell = f =>
                    "# Inside the procedure: the dynamic SQL is now ALSO parameterized\n" +
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"dbo.SearchProducts\", $connection\n" +
                    "$cmd.CommandType = [System.Data.CommandType]::StoredProcedure\n" +
                    "[void]$cmd.Parameters.AddWithValue('@SearchTerm', $search)",
                Simulate = (f, _) => Classify(f) == "escalation"
                    ? new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "No matching products found",
                        Detail = "The word UNION is just literal text inside the @Term parameter now — there's no " +
                                  "SQL text left for it to inject into, regardless of which account the procedure " +
                                  "runs as."
                    }
                    : new SimulationResult { Severity = Severity.Success, Headline = "Search completed", Detail = "Ordinary search, unaffected by the fix." }
            }
        },

        SimulateVulnerable = f => Classify(f) == "escalation"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Password hashes returned — fetched by the database owner, not the reporting login",
                Detail = "WITH EXECUTE AS OWNER means every statement inside this procedure — including the " +
                          "dynamic SQL it builds from unsanitized input — runs with the database owner's full " +
                          "permissions. The reporting login's own, deliberately narrow permissions are completely " +
                          "irrelevant to what the injected SQL can reach.",
                AffectedAssets = new[] { "dbo.Users — read via a login that was never granted direct table access" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Search completed", Detail = "Ordinary search, nothing unusual happens." },

        HowItWorks =
            "EXECUTE AS lets a module run under a different security context than its caller — commonly used so " +
            "a low-privileged login can run a procedure that needs broader access, without being granted that " +
            "access directly. That's a reasonable design on its own. The problem is specific to injection: if the " +
            "procedure builds dynamic SQL unsafely, whatever gets injected runs with the SAME elevated privileges " +
            "the procedure itself was given — turning an ordinary injection into a full-privilege one, entirely " +
            "because of how the surrounding procedure was secured, not because of anything new in the injection " +
            "itself.",

        WhyTheFixWorks =
            "Parameterizing the dynamic SQL the procedure builds closes the injection regardless of which account " +
            "the procedure executes as — there's no attacker-controlled text left to run as anyone, privileged or " +
            "not.",

        SamplePayloads = new[]
        {
            "nonexistent' UNION SELECT Username, PasswordHash FROM dbo.Users--",
            "nonexistent' union select Username, PasswordHash from dbo.Users--"
        },

        ChallengeGoal = "Get the reporting search to read password hashes, despite the reporting login never being granted direct table access.",
        Hints = new[]
        {
            "The reporting login's own permissions aren't the ones that matter here — whose are?",
            "This procedure builds dynamic SQL the same unsafe way as the plain UNION scenario — the payload is identical."
        },
        ChallengeAnswer = "nonexistent' UNION SELECT Username, PasswordHash FROM dbo.Users--",

        TerminologyNote = "Named for the T-SQL clause that causes it: EXECUTE AS sets which account's " +
                           "permissions a module runs under. \"Ownership chaining\" is the related, broader " +
                           "concept — permission checks being skipped across a chain of same-owner objects — and " +
                           "the two are often discussed together because both can let code run with more " +
                           "privilege than the caller who triggered it actually has.",
        References = new[]
        {
            new ExternalReference { Label = "Microsoft Learn — EXECUTE AS Clause (Transact-SQL)", Url = "https://learn.microsoft.com/sql/t-sql/statements/execute-as-clause-transact-sql" },
            new ExternalReference { Label = "Redgate Simple Talk — Cross-Database Ownership Chaining in SQL Server", Url = "https://www.red-gate.com/simple-talk/databases/sql-server/cross-database-ownership-chaining-in-sql-server-security-risks-behavior-and-privilege-escalation-explained/" }
        }
    };
}
