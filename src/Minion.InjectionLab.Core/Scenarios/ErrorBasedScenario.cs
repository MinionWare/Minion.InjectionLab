using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Error-based injection: a page that helpfully shows raw database errors hands an
/// attacker a free data-exfiltration channel built entirely out of type-conversion failures.</summary>
public static class ErrorBasedScenario
{
    private const string Baseline = "1007";

    private static readonly string[] Keywords = { "CONVERT" };
    private static readonly string[] ExpertKeywords = { "CAST" };

    private static bool ContainsAny(string s, params string[] needles)
    {
        var lower = s.ToLowerInvariant();
        return needles.Any(lower.Contains);
    }

    private static string Classify(IReadOnlyDictionary<string, string> f)
        => ContainsAny(f["productId"], "convert(", "cast(") ? "leak" : "normal";

    public static AttackScenario Create() => new()
    {
        Id = "error-based",
        Category = AttackCategory.ClassicInBand,
        Title = "Error-Based Injection",
        Premise = "A \"check product ID\" page shows nothing on an ordinary request — but like a lot of apps in " +
                  "development (and plenty still in production), it helpfully shows the raw SQL Server error " +
                  "message whenever something goes wrong, to make debugging easier.",
        MockAppLabel = "Internal Tools — Product Lookup",
        BaselineValues = new Dictionary<string, string> { ["productId"] = Baseline },
        Fields = new[] { new FormField { Key = "productId", Label = "Product ID", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Normal lookup", Icon = "📦", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "leak", Label = "Data leaked via error message", Icon = "💥", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT * FROM dbo.Products WHERE ProductId = {f["productId"]};",

        BuildVulnerableCSharp = f =>
            "var sql = $\"SELECT * FROM dbo.Products WHERE ProductId = {productId}\";\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "try { using var reader = cmd.ExecuteReader(); }\n" +
            "catch (SqlException ex) { return BadRequest(ex.Message); } // the raw DB error reaches the response",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT * FROM dbo.Products WHERE ProductId = $productId\"\n" +
            "try { Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql }\n" +
            "catch { Write-Output $_.Exception.Message }  # the raw DB error reaches the console/response",

        // Two real fixes, not equally complete: blocking CONVERT (looks like a fix, isn't one —
        // CAST does the identical job) vs. real parameterization.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block input containing \"CONVERT\"",
                Grade = FixGrade.Partial,
                Gap = "At Beginner, checks for the literal uppercase word \"CONVERT\" — lowercase sails through. " +
                      "Intermediate catches any casing. Expert also blocks \"CAST\" — SQL Server's other, " +
                      "functionally identical way to force the exact same type-conversion error. Any future " +
                      "function this filter doesn't know about yet gets the same free pass.",
                BuildSql = (f, d) =>
                {
                    bool blocked = KeywordBlacklist.IsBlocked(f["productId"], d, Keywords, ExpertKeywords);
                    return blocked ? "-- Request rejected by the application; no SQL was ever built." : $"SELECT * FROM dbo.Products WHERE ProductId = {f["productId"]};";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["productId"].Contains("CONVERT", StringComparison.OrdinalIgnoreCase);
                    var guard = "if (productId.Contains(\"CONVERT\", StringComparison.OrdinalIgnoreCase))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"SELECT * FROM dbo.Products WHERE ProductId = {productId}\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["productId"].Contains("CONVERT", StringComparison.OrdinalIgnoreCase);
                    var guard = "if ($productId -match '(?i)convert') { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"SELECT * FROM dbo.Products WHERE ProductId = $productId\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = KeywordBlacklist.IsBlocked(f["productId"], d, Keywords, ExpertKeywords);
                    if (Classify(f) != "leak")
                        return new SimulationResult { Severity = Severity.Success, Headline = "Product 1007 found", Detail = "Ordinary lookup, the filter never engages." };
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Request rejected", Detail = "At this difficulty, the filter happened to catch this specific function name." };
                    return new SimulationResult
                    {
                        Severity = Severity.Critical,
                        Headline = "Error message: \"Conversion failed when converting the nvarchar value " +
                                   "'Microsoft SQL Server 2022...' to data type int.\"",
                        Detail = "This used CAST instead of CONVERT — functionally identical, and never on this " +
                                  "filter's list. The database tried (and failed) to convert the requested text to " +
                                  "an integer, and the error message it raised contains that exact text — whatever " +
                                  "it was asked to convert.",
                        AffectedAssets = new[] { "Arbitrary readable data — anything expressible as a single value leaks through the error channel" }
                    };
                }
            },
            new FixOption
            {
                Label = "✓ Parameterized query",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                    "EXEC sp_executesql N'SELECT * FROM dbo.Products WHERE ProductId = @ProductId', N'@ProductId INT', @ProductId;\n\n" +
                    $"@ProductId = {f["productId"]}  -- must parse as INT, or the call fails before touching SQL text",
                BuildCSharp = f =>
                    "using var cmd = new SqlCommand(\"SELECT * FROM dbo.Products WHERE ProductId = @ProductId\", connection);\n" +
                    "cmd.Parameters.Add(\"@ProductId\", SqlDbType.Int).Value = productId;",
                BuildPowerShell = f =>
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"SELECT * FROM dbo.Products WHERE ProductId = @ProductId\", $connection\n" +
                    "[void]$cmd.Parameters.AddWithValue('@ProductId', [int]$productId)",
                Simulate = (f, _) => Classify(f) == "leak"
                    ? new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "Rejected before it ever reaches the database",
                        Detail = "The parameter is declared as SqlDbType.Int. Neither CONVERT(...) nor CAST(...) parses " +
                                  "as a valid integer, so the call fails at the type-conversion layer on the .NET side " +
                                  "— the SQL engine never even sees the attempted function call."
                    }
                    : new SimulationResult { Severity = Severity.Success, Headline = "Product 1007 found", Detail = "Ordinary lookup, unaffected by the fix." }
            }
        },

        SimulateVulnerable = f => Classify(f) == "leak"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Error message: \"Conversion failed when converting the nvarchar value " +
                           "'Microsoft SQL Server 2022...' to data type int.\"",
                Detail = "The database attempted the requested conversion, failed, and — because this page shows raw " +
                          "errors — included the exact text it was trying to convert right there in the error " +
                          "message. Swap @@version for a subquery pulling a username or password hash, and the same " +
                          "trick reads arbitrary data out of the database one error message at a time.",
                AffectedAssets = new[] { "Arbitrary readable data — anything expressible as a single value leaks through the error channel" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Product 1007 found", Detail = "Ordinary lookup, nothing unusual happens." },

        HowItWorks =
            "SQL Server raises a descriptive error when a value can't be converted to the requested data type — " +
            "and that error message includes the actual value it failed to convert. Forcing a conversion of " +
            "something the attacker doesn't already know (a password hash, a secret, the database version) turns " +
            "every failed conversion into a free read: the answer comes back inside the error text itself, as " +
            "long as the application is careless enough to show raw database errors to the user.",

        WhyTheFixWorks =
            "A strongly-typed parameter is checked for validity before it ever reaches SQL Server as text — " +
            "neither CONVERT(...) nor CAST(...) parses as a plain integer, so the attempt fails at the .NET " +
            "type-conversion layer, long before any SQL Server error (useful or otherwise) could ever be raised.",

        SamplePayloads = new[]
        {
            "1007 AND 1=CONVERT(int, @@version)--",
            "1007 AND 1=CAST(@@version AS int)--",
            "1007 AND 1=CAST((SELECT TOP 1 PasswordHash FROM Users) AS int)--"
        },

        ChallengeGoal = "Get the SQL Server version string to appear inside a visible error message.",
        Hints = new[]
        {
            "This page shows raw database errors — what happens if you deliberately cause one?",
            "Forcing a text value into a numeric type it can't become produces an error that quotes the value it tried to convert."
        },
        ChallengeAnswer = "1007 AND 1=CONVERT(int, @@version)--",

        TerminologyNote = "Named for the channel the data leaks through: not the normal response, not a visible " +
                           "true/false difference, but the database's own error message — which SQL Server " +
                           "populates with the actual value a failed conversion was attempting to produce.",
        References = new[]
        {
            new ExternalReference { Label = "Advania — MSSQL Practical Injection Cheat Sheet", Url = "https://www.advania.co.uk/blog/security/mssql-practical-injection-cheat-sheet/" },
            new ExternalReference { Label = "Exploit-DB — Methods of Quick Exploitation of Blind SQL Injection (the original error-based write-up)", Url = "https://www.exploit-db.com/exploits/13604" }
        }
    };
}
