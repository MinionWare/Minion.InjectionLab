using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Full-text search injection: CONTAINS' search condition is still ordinary T-SQL text
/// until it's bound as a parameter — the fact that it also has its own query syntax doesn't
/// change the fact that unparameterized input reaches the engine as code.</summary>
public static class FullTextContainsInjectionScenario
{
    private const string Baseline = "SQL Server";

    private static readonly string[] Keywords = { "UNION" };
    private static readonly string[] ExpertKeywords = { "SELECT" };

    private static string Classify(IReadOnlyDictionary<string, string> f)
        => f["terms"].Contains("union", StringComparison.OrdinalIgnoreCase) ? "bypass" : "normal";

    public static AttackScenario Create() => new()
    {
        Id = "fulltext-contains-injection",
        Category = AttackCategory.ClassicInBand,
        Title = "Full-Text Search Injection",
        Premise = "An article search box uses SQL Server's full-text CONTAINS predicate so visitors can search " +
                  "with natural phrases, boolean operators, and proximity terms. The search box's text is " +
                  "concatenated straight into the CONTAINS clause.",
        MockAppLabel = "Knowledge Base — Article Search",
        BaselineValues = new Dictionary<string, string> { ["terms"] = Baseline },
        Fields = new[] { new FormField { Key = "terms", Label = "Search terms", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Ordinary search", Icon = "🔍", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "bypass", Label = "UNION rides past CONTAINS", Icon = "📰", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT Title, Body FROM dbo.Articles WHERE CONTAINS(Body, '{f["terms"]}');",

        BuildVulnerableCSharp = f =>
            "var sql = $\"SELECT Title, Body FROM dbo.Articles WHERE CONTAINS(Body, '{terms}')\";\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "using var reader = cmd.ExecuteReader();",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT Title, Body FROM dbo.Articles WHERE CONTAINS(Body, '$terms')\"\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql",

        // Two real fixes, not equally complete: a keyword blacklist (looks like a fix, isn't one)
        // vs. real parameterization of the CONTAINS search condition itself.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block input containing \"UNION\"",
                Grade = FixGrade.Partial,
                Gap = "At Beginner, checks for the literal uppercase word — lowercase sails through. " +
                      "Intermediate catches any casing. Expert also blocks \"SELECT\" — but this is the same " +
                      "underlying SQL injection as the plain UNION scenario; any phrasing this filter doesn't " +
                      "happen to list still gets through, same as everywhere else.",
                BuildSql = (f, d) =>
                {
                    bool blocked = KeywordBlacklist.IsBlocked(f["terms"], d, Keywords, ExpertKeywords);
                    return blocked ? "-- Request rejected by the application; no SQL was ever built." : $"SELECT Title, Body FROM dbo.Articles WHERE CONTAINS(Body, '{f["terms"]}');";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["terms"].Contains("UNION", StringComparison.OrdinalIgnoreCase);
                    var guard = "if (terms.Contains(\"UNION\", StringComparison.OrdinalIgnoreCase))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"SELECT Title, Body FROM dbo.Articles WHERE CONTAINS(Body, '{terms}')\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["terms"].Contains("UNION", StringComparison.OrdinalIgnoreCase);
                    var guard = "if ($terms -match '(?i)union') { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"SELECT Title, Body FROM dbo.Articles WHERE CONTAINS(Body, '$terms')\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = KeywordBlacklist.IsBlocked(f["terms"], d, Keywords, ExpertKeywords);
                    if (Classify(f) != "bypass")
                        return new SimulationResult { Severity = Severity.Success, Headline = "Search completed", Detail = "Ordinary search, the filter never engages." };
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Request rejected", Detail = "At this difficulty, the filter happened to catch this specific phrasing." };
                    return new SimulationResult
                    {
                        Severity = Severity.Critical,
                        Headline = "Real usernames and password hashes returned — disguised as search results",
                        Detail = "CONTAINS(...) closes out fine, and the UNION SELECT right after it runs as a " +
                                  "completely ordinary part of the same statement — CONTAINS having its own search " +
                                  "syntax doesn't change the fact that this is still plain SQL injection.",
                        AffectedAssets = new[] { "dbo.Users — Username and PasswordHash columns exposed through article search" }
                    };
                }
            },
            new FixOption
            {
                Label = "✓ Parameterized CONTAINS condition",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                    "EXEC sp_executesql N'SELECT Title, Body FROM dbo.Articles WHERE CONTAINS(Body, @Terms)', " +
                    "N'@Terms NVARCHAR(200)', @Terms;\n\n" +
                   $"@Terms = {f["terms"]}",
                BuildCSharp = f =>
                    "using var cmd = new SqlCommand(\"SELECT Title, Body FROM dbo.Articles WHERE CONTAINS(Body, @Terms)\", connection);\n" +
                    "cmd.Parameters.AddWithValue(\"@Terms\", terms);",
                BuildPowerShell = f =>
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"SELECT Title, Body FROM dbo.Articles WHERE CONTAINS(Body, @Terms)\", $connection\n" +
                    "[void]$cmd.Parameters.AddWithValue('@Terms', $terms)",
                Simulate = (f, _) => Classify(f) == "bypass"
                    ? new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "No matching articles found",
                        Detail = "The word UNION is just literal text inside the @Terms parameter now, handed " +
                                  "straight to the full-text engine as a search phrase — there's no SQL left for it " +
                                  "to be parsed as."
                    }
                    : new SimulationResult { Severity = Severity.Success, Headline = "Search completed", Detail = "Ordinary search, unaffected by the fix." }
            }
        },

        SimulateVulnerable = f => Classify(f) == "bypass"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Real usernames and password hashes returned — disguised as search results",
                Detail = "CONTAINS(Body, '...') is still just a string argument inside an ordinary SQL statement. " +
                          "Closing that string and adding a UNION SELECT works exactly like the plain UNION " +
                          "scenario — the full-text predicate's own rich search syntax has nothing to do with it.",
                AffectedAssets = new[] { "dbo.Users — Username and PasswordHash columns exposed through article search" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Search completed", Detail = "Ordinary search, nothing unusual happens." },

        HowItWorks =
            "CONTAINS' search-condition argument is still ordinary T-SQL text right up until the moment it's " +
            "bound as a parameter — concatenating user input into it is exactly as dangerous as concatenating " +
            "into any other part of a query. The fact that the text inside the quotes is itself a small query " +
            "language (supporting AND/OR/NEAR, wildcards, weighted terms) is a separate, additional detail worth " +
            "knowing, but it doesn't change how the SQL-level injection here works at all.",

        WhyTheFixWorks =
            "Parameterizing the CONTAINS argument removes the string-concatenation step entirely, the same fix " +
            "as everywhere else in this app. (Separately: an app that wants to guarantee a literal phrase search " +
            "rather than full-text boolean logic should also wrap the parameter value in escaped double quotes — " +
            "a smaller, different concern from the SQL injection this fix closes.)",

        SamplePayloads = new[]
        {
            "test') UNION SELECT Username, PasswordHash FROM dbo.Users--"
        },

        ChallengeGoal = "Get the article search to return usernames and password hashes instead of articles.",
        Hints = new[]
        {
            "This is the same UNION technique from the classic UNION scenario — CONTAINS is just a different place for it to live.",
            "Close the CONTAINS call's string and parentheses, then UNION a SELECT from dbo.Users."
        },
        ChallengeAnswer = "test') UNION SELECT Username, PasswordHash FROM dbo.Users--",

        TerminologyNote = "Named for the SQL Server feature it targets — full-text search's CONTAINS/FREETEXT " +
                           "predicates — not a new injection mechanism. Underneath, this is the same UNION-based " +
                           "SQL injection taught earlier in the catalog, just reached through a predicate with its " +
                           "own embedded search language instead of a plain WHERE comparison.",
        References = new[]
        {
            new ExternalReference { Label = "Microsoft Learn — CONTAINS (Transact-SQL)", Url = "https://learn.microsoft.com/sql/relational-databases/search/query-with-full-text-search" },
            new ExternalReference { Label = "OWASP — SQL Injection Prevention Cheat Sheet", Url = "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet" }
        }
    };
}
