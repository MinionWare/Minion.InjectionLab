using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>XQuery injection: the xml data type's .query() method requires a string literal, not a
/// parameter — which pushes developers toward the exact same unsafe string-building as any other
/// dynamic SQL, just one layer deeper, inside an XML method call.</summary>
public static class XQueryInjectionScenario
{
    private const string Baseline = "Title";

    private static readonly string[] Keywords = { "SELECT" };
    private static readonly string[] ExpertKeywords = { "EXEC" };

    private static string Classify(IReadOnlyDictionary<string, string> f)
        => f["element"].Contains(';') ? "stacked" : "normal";

    public static AttackScenario Create() => new()
    {
        Id = "xquery-injection",
        Category = AttackCategory.IdentifiersAndDynamicSql,
        Title = "XQuery Injection",
        Premise = "A document-search feature lets you pick which XML element to pull out of a stored document " +
                  "column, using the xml data type's .query() method. The XQuery expression .query() takes has " +
                  "to be a string literal — SQL Server won't accept a plain variable there — so the developer " +
                  "builds it with string concatenation instead.",
        MockAppLabel = "Document Library — Field Search",
        BaselineValues = new Dictionary<string, string> { ["element"] = Baseline },
        Fields = new[] { new FormField { Key = "element", Label = "Element to search", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Ordinary element name", Icon = "📄", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "stacked", Label = "Second statement rides along", Icon = "🧬", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT Content.query('/Root/{f["element"]}') FROM dbo.Documents;",

        BuildVulnerableCSharp = f =>
            "var sql = $\"SELECT Content.query('/Root/{element}') FROM dbo.Documents\";\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "using var reader = cmd.ExecuteReader();",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT Content.query('/Root/$element') FROM dbo.Documents\"\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql",

        // Two real fixes, not equally complete: a keyword blacklist (looks like a fix, isn't one)
        // vs. sql:variable(), the real way to bind data into a fixed XQuery literal.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block input containing \"SELECT\"",
                Grade = FixGrade.Partial,
                Gap = "At Beginner, checks for the literal uppercase word — lowercase sails through. " +
                      "Intermediate catches any casing. Expert also blocks \"EXEC\" — but a semicolon still lets " +
                      "through any statement type this filter didn't think to list.",
                BuildSql = (f, d) =>
                {
                    bool blocked = KeywordBlacklist.IsBlocked(f["element"], d, Keywords, ExpertKeywords);
                    return blocked ? "-- Request rejected by the application; no SQL was ever built." : $"SELECT Content.query('/Root/{f["element"]}') FROM dbo.Documents;";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["element"].Contains("SELECT", StringComparison.OrdinalIgnoreCase);
                    var guard = "if (element.Contains(\"SELECT\", StringComparison.OrdinalIgnoreCase))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"SELECT Content.query('/Root/{element}') FROM dbo.Documents\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["element"].Contains("SELECT", StringComparison.OrdinalIgnoreCase);
                    var guard = "if ($element -match '(?i)select') { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"SELECT Content.query('/Root/$element') FROM dbo.Documents\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = KeywordBlacklist.IsBlocked(f["element"], d, Keywords, ExpertKeywords);
                    if (Classify(f) != "stacked")
                        return new SimulationResult { Severity = Severity.Success, Headline = "Element returned", Detail = "Ordinary element name, the filter never engages." };
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Request rejected", Detail = "At this difficulty, the filter happened to catch this specific phrasing." };
                    return new SimulationResult
                    {
                        Severity = Severity.Critical,
                        Headline = "Real usernames and password hashes returned alongside the document search",
                        Detail = "The closing parenthesis and quote end the .query() call early, the semicolon ends " +
                                  "that statement, and a completely independent second statement rides along right " +
                                  "after it.",
                        AffectedAssets = new[] { "dbo.Users — Username and PasswordHash columns exposed through a document field search" }
                    };
                }
            },
            new FixOption
            {
                Label = "✓ Bind the value with sql:variable()",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                    "DECLARE @Element NVARCHAR(100) = @ElementParam;  -- @ElementParam bound as an ordinary parameter\n\n" +
                    "SELECT Content.query('/Root/*[local-name()=sql:variable(\"@Element\")]') FROM dbo.Documents;\n\n" +
                   $"@ElementParam = {f["element"]}",
                BuildCSharp = f =>
                    "using var cmd = new SqlCommand(\n" +
                    "    \"DECLARE @e NVARCHAR(100) = @Element; \" +\n" +
                    "    \"SELECT Content.query('/Root/*[local-name()=sql:variable(\\\"@e\\\")]') FROM dbo.Documents\",\n" +
                    "    connection);\n" +
                    "cmd.Parameters.AddWithValue(\"@Element\", element);",
                BuildPowerShell = f =>
                    "$sql = \"DECLARE @e NVARCHAR(100) = @Element; SELECT Content.query('/Root/*[local-name()=sql:variable(`\"@e`\")]') FROM dbo.Documents\"\n" +
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand $sql, $connection\n" +
                    "[void]$cmd.Parameters.AddWithValue('@Element', $element)",
                Simulate = (f, _) => Classify(f) == "stacked"
                    ? new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "No matching element found",
                        Detail = "The XQuery expression itself never changes — it's a fixed literal. Your input only " +
                                  "ever reaches SQL Server as the bound @Element parameter value, which sql:variable() " +
                                  "exposes inside that fixed expression as plain data, never as new XQuery or SQL syntax."
                    }
                    : new SimulationResult { Severity = Severity.Success, Headline = "Element returned", Detail = "Ordinary element name, unaffected by the fix." }
            }
        },

        SimulateVulnerable = f => Classify(f) == "stacked"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Real usernames and password hashes returned alongside the document search",
                Detail = "Because the XQuery path has to be a literal, the developer built the whole SQL statement " +
                          "by concatenating it in — which means every usual SQL injection technique applies here " +
                          "too, it's just reached through an XML method call instead of a bare SELECT.",
                AffectedAssets = new[] { "dbo.Users — Username and PasswordHash columns exposed through a document field search" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Element returned", Detail = "Ordinary element name, nothing unusual happens." },

        HowItWorks =
            "SQL Server requires the XQuery expression passed to the xml data type's .query() and .value() " +
            "methods to be a string literal — you genuinely cannot pass a plain T-SQL variable there. Faced with " +
            "a feature that needs to vary by user input, a lot of code reaches for the same fix as any other " +
            "'can't be parameterized' situation: string concatenation. Once that's dynamic SQL built from raw " +
            "input, every classic SQL injection technique — stacked queries included — works exactly as it would " +
            "anywhere else.",

        WhyTheFixWorks =
            "sql:variable() is SQL Server's real, documented way to expose an ordinary bound T-SQL variable's " +
            "value inside a fixed XQuery expression. The expression text itself never changes — only the value " +
            "does — so there's no string-building left for an attacker to break out of.",

        SamplePayloads = new[]
        {
            "Title') FROM dbo.Documents; SELECT Username, PasswordHash FROM dbo.Users; --"
        },

        ChallengeGoal = "Get the document search to return usernames and password hashes instead of document content.",
        Hints = new[]
        {
            "This is dynamic SQL, built the same unsafe way as any other scenario — the XML method is just where it happens to live.",
            "Close the .query() call and the statement, then start a brand new one with a semicolon."
        },
        ChallengeAnswer = "Title') FROM dbo.Documents; SELECT Username, PasswordHash FROM dbo.Users; --",

        TerminologyNote = "Named for the query language inside the attack, not a new SQL mechanism: XQuery is " +
                           "the language SQL Server's xml data type methods use internally. CWE-652 classifies " +
                           "\"XQuery Injection\" as its own weakness category — but in T-SQL specifically, it's " +
                           "almost always SQL injection first, just reached through an XML method call that " +
                           "forced the developer into dynamic SQL to begin with.",
        References = new[]
        {
            new ExternalReference { Label = "Microsoft Learn — query() Method (xml Data Type)", Url = "https://learn.microsoft.com/sql/t-sql/xml/query-method-xml-data-type" },
            new ExternalReference { Label = "Microsoft Learn — XQuery Extension Functions: sql:variable()", Url = "https://learn.microsoft.com/sql/xquery/xquery-extension-functions-sql-variable" },
            new ExternalReference { Label = "CWE-652 — Improper Neutralization of Data within XQuery Expressions", Url = "https://cvefeed.io/cwe/detail/cwe-652-improper-neutralization-of-data-within-xquery-expressions-xquery-injection" }
        }
    };
}
