using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Stacked queries: a semicolon lets an entirely separate statement ride along in the same batch.</summary>
public static class StackedQueriesScenario
{
    private const string Baseline = "1007";

    /// <summary>Same numeric/unquoted shape as NumericInjectionScenario: any non-numeric value is
    /// suspect. "Stacked" (semicolon + a DML/DDL keyword) and "tautology" (e.g. "OR 1=1", no
    /// semicolon needed at all) are both real bypasses here — distinct techniques, same root cause.</summary>
    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var s = f["orderId"].Trim();
        if (s.Length == 0 || int.TryParse(s, out _)) return "normal";

        var lower = s.ToLowerInvariant();
        if (lower.Contains(';') && (lower.Contains("drop") || lower.Contains("insert") || lower.Contains("update") || lower.Contains("delete") || lower.Contains("exec")))
            return "stacked";
        return "tautology";
    }

    public static AttackScenario Create() => new()
    {
        Id = "stacked-queries",
        Category = AttackCategory.ClassicInBand,
        Title = "Stacked Queries",
        Premise = "An internal order-lookup tool builds one T-SQL batch per request. SQL Server (and most " +
                  "drivers, by default) will happily run several semicolon-separated statements in a single batch.",
        MockAppLabel = "Internal Tools — Order Lookup",
        BaselineValues = new Dictionary<string, string> { ["orderId"] = Baseline },
        Fields = new[] { new FormField { Key = "orderId", Label = "Order ID", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Normal lookup", Icon = "📦", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "tautology", Label = "Tautology (no ; needed)", Icon = "🔓", Kind = PathKind.Malicious },
            new DecisionPathDef { Key = "stacked", Label = "Stacked statement", Icon = "💉", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT * FROM dbo.Orders WHERE OrderId = {f["orderId"]};",

        BuildVulnerableCSharp = f =>
            "var sql = $\"SELECT * FROM dbo.Orders WHERE OrderId = {orderId}\";\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "using var reader = cmd.ExecuteReader(); // ExecuteReader happily runs a whole batch, not just one statement",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT * FROM dbo.Orders WHERE OrderId = $orderId\"\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql",

        // Two real fixes, not equally complete: blocking the semicolon (stops stacking, not
        // tautology) vs. a strongly-typed parameter (stops both, since neither parses as an int).
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block input containing \";\"",
                Grade = FixGrade.Partial,
                Gap = "Stops the semicolon-based stacked statement specifically — but this value is still " +
                      "concatenated unquoted elsewhere in the same query. A plain tautology like \"OR 1=1\" needs " +
                      "no semicolon at all, and this filter does nothing to stop it.",
                BuildSql = (f, d) =>
                {
                    bool blocked = f["orderId"].Contains(';');
                    // The filter runs in application code, before any SQL is built — see the C#/PowerShell tabs.
                    return blocked ? "-- Request rejected by the application; no SQL was ever built." : $"SELECT * FROM dbo.Orders WHERE OrderId = {f["orderId"]};";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["orderId"].Contains(';');
                    var guard = "if (orderId.Contains(\";\"))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"SELECT * FROM dbo.Orders WHERE OrderId = {orderId}\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["orderId"].Contains(';');
                    var guard = "if ($orderId.Contains(\";\")) { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"SELECT * FROM dbo.Orders WHERE OrderId = $orderId\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = f["orderId"].Contains(';');
                    var classification = Classify(f);
                    // Note: "stacked" always implies a semicolon is present, so filterCaughtIt is
                    // necessarily true whenever classification == "stacked" — that branch is handled
                    // by the check above. Only "tautology" (no semicolon at all) can slip past.
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Request rejected — contains \";\"", Detail = "Stops this specific stacked-statement attempt." };
                    if (classification == "tautology")
                        return new SimulationResult
                        {
                            Severity = Severity.Critical,
                            Headline = "Every order in the table is returned — the semicolon filter never engages",
                            Detail = "This doesn't use a semicolon at all, so the filter has nothing to catch. The " +
                                      "underlying concatenation is exactly as vulnerable to a plain tautology as it " +
                                      "ever was.",
                            RowCountLabel = "all rows",
                            AffectedAssets = new[] { "dbo.Orders — every row exposed" }
                        };
                    return new SimulationResult { Severity = Severity.Success, Headline = "Order 1007 found", Detail = "Ordinary lookup, the filter never engages." };
                }
            },
            new FixOption
            {
                Label = "✓ Strongly-typed parameter",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                    "EXEC sp_executesql N'SELECT * FROM dbo.Orders WHERE OrderId = @OrderId', N'@OrderId INT', @OrderId;\n\n" +
                    $"@OrderId = {f["orderId"]}  -- must parse as INT, or the call fails before touching SQL text",
                BuildCSharp = f =>
                    "using var cmd = new SqlCommand(\"SELECT * FROM dbo.Orders WHERE OrderId = @OrderId\", connection);\n" +
                    "cmd.Parameters.Add(\"@OrderId\", SqlDbType.Int).Value = orderId; // throws if orderId isn't an int",
                BuildPowerShell = f =>
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"SELECT * FROM dbo.Orders WHERE OrderId = @OrderId\", $connection\n" +
                    "[void]$cmd.Parameters.AddWithValue('@OrderId', [int]$orderId)  # cast throws if not a real int\n" +
                    "$reader = $cmd.ExecuteReader()",
                Simulate = (f, _) => Classify(f) switch
                {
                    "stacked" or "tautology" => new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "Rejected before it ever reaches the database",
                        Detail = "The parameter is declared as SqlDbType.Int. Neither a semicolon nor an \"OR\" " +
                                  "condition parses as a valid integer, so both fail at the type-conversion layer — " +
                                  "the SQL engine never even sees them."
                    },
                    _ => new SimulationResult { Severity = Severity.Success, Headline = "Order 1007 found", Detail = "Ordinary lookup, unaffected by the fix." }
                }
            }
        },

        SimulateVulnerable = f => Classify(f) switch
        {
            "stacked" => new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "A second, unrelated statement just executed in the same batch",
                Detail = "The semicolon ends the SELECT, and whatever comes after it is parsed as a brand new T-SQL " +
                          "statement — not a modified WHERE clause, but an entirely separate command with its own " +
                          "full privileges. This is a different (and often worse) mechanism than a tautology bypass.",
                AffectedAssets = new[] { "A second DDL/DML statement executed with the app's own database permissions" }
            },
            "tautology" => new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Every order in the table is returned",
                Detail = "No semicolon needed — this is the same unquoted-concatenation problem as any numeric " +
                          "injection. Stacking is one technique this query is vulnerable to; a plain tautology is another.",
                RowCountLabel = "all rows",
                AffectedAssets = new[] { "dbo.Orders — every row exposed" }
            },
            _ => new SimulationResult { Severity = Severity.Success, Headline = "Order 1007 found", Detail = "Ordinary lookup." }
        },

        HowItWorks =
            "T-SQL batches can contain multiple statements separated by semicolons. When an app concatenates user " +
            "input directly into a batch, a semicolon in that input doesn't modify the existing query — it ends it, " +
            "and anything after becomes a new, independent statement that runs with the same permissions as the app. " +
            "The same concatenation is also just as vulnerable to a plain tautology, with no semicolon involved at all.",

        WhyTheFixWorks =
            "sp_executesql (or any parameterized command) only ever compiles the fixed SQL text once; the parameter " +
            "value is substituted afterward as data, so a semicolon inside it can't start a new statement — there's no " +
            "longer any SQL text left to parse at that point. A strongly-typed INT parameter closes the tautology path " +
            "too, since neither a semicolon nor an OR condition is a valid integer.",

        SamplePayloads = new[]
        {
            "1007; DROP TABLE Orders--",
            "1007; INSERT INTO Users (UserName, Role) VALUES ('hacker','Administrator')--",
            "1007 OR 1=1"
        },

        ChallengeGoal = "Get a second, entirely different SQL statement to execute alongside the lookup query.",
        Hints = new[]
        {
            "T-SQL batches can hold more than one statement — what character separates them?",
            "Whatever you put after that character runs as its own independent statement, not part of the WHERE clause."
        },
        ChallengeAnswer = "1007; DROP TABLE Orders--",

        TerminologyNote = "\"Stacked\" describes statements piled up one after another in a single batch, " +
                           "separated by semicolons — the same idea some literature calls \"batched\" or " +
                           "\"piggy-backed\" queries, since the extra statement rides along on the back of the " +
                           "original request.",
        References = new[]
        {
            new ExternalReference { Label = "PortSwigger — SQL injection cheat sheet (see \"Batched (or stacked) queries\")", Url = "https://portswigger.net/web-security/sql-injection/cheat-sheet" },
            new ExternalReference { Label = "Halfond, Viegas & Orso — \"A Classification of SQL Injection Attacks and Countermeasures\" (classifies this as \"piggy-backed queries\")", Url = "https://sites.cc.gatech.edu/home/orso/papers/halfond.viegas.orso.ISSSE06.pdf" }
        }
    };
}
