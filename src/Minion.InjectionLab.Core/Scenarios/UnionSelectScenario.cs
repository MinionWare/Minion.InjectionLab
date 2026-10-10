using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>UNION-based injection: pulling columns from an unrelated table through a search box.</summary>
public static class UnionSelectScenario
{
    private const string Baseline = "widget";

    private static readonly string[] Keywords = { "UNION" };
    private static readonly string[] ExpertKeywords = { "SELECT" };

    private static string VulnerableSql(IReadOnlyDictionary<string, string> f) =>
        $"SELECT ProductId, Name, Price FROM dbo.Products WHERE Name LIKE '%{f["search"]}%';";

    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var s = f["search"].ToLowerInvariant();
        bool hasUnion = s.Contains("union") && s.Contains("select");
        bool hasOrderBy = s.Contains("order by");
        if (!hasUnion && !hasOrderBy) return "normal";

        // Real SQL Server parsing (ScriptDom), not a guessed-at "ends with --" pattern — the
        // template's own closing "%';" always follows the injection point, so this is the
        // authoritative check for whether the batch would actually run at all.
        if (SqlSyntaxChecker.HasSyntaxError(VulnerableSql(f))) return "malformed";

        // A UNION that names a real table (FROM ...) is the actual breach. NULL-only columns
        // with no FROM are just confirming the column count — reconnaissance, not a leak yet.
        if (hasUnion) return s.Contains("from") ? "injection" : "probe";
        return "probe";
    }

    public static AttackScenario Create() => new()
    {
        Id = "union-select",
        Category = AttackCategory.ClassicInBand,
        Title = "UNION-Based Injection",
        Premise = "A product search box builds a 3-column SELECT. The results table is rendered straight " +
                  "from whatever columns come back — it doesn't check where they came from.",
        MockAppLabel = "Store — Product Search",
        BaselineValues = new Dictionary<string, string> { ["search"] = Baseline },
        Fields = new[] { new FormField { Key = "search", Label = "Search products", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Normal search", Icon = "🔍", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "probe", Label = "Column-count probe", Icon = "🔎", Kind = PathKind.Neutral },
            new DecisionPathDef { Key = "malformed", Label = "Broken syntax", Icon = "⚠", Kind = PathKind.Neutral },
            new DecisionPathDef { Key = "injection", Label = "UNION targeting a real table", Icon = "💉", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = VulnerableSql,

        BuildVulnerableCSharp = f =>
            "var sql = $\"SELECT ProductId, Name, Price FROM dbo.Products WHERE Name LIKE '%{search}%'\";\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "using var reader = cmd.ExecuteReader(); // columns render straight to the page, whatever they are",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT ProductId, Name, Price FROM dbo.Products WHERE Name LIKE '%$search%'\"\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql",

        // Two real fixes people actually ship, not equally complete: a keyword blacklist (looks
        // like a fix, isn't one) vs. real parameterization.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block input containing \"UNION\"",
                Grade = FixGrade.Partial,
                Gap = "At Beginner, checks for the literal uppercase word \"UNION\" — lowercase \"union\" sails " +
                      "through. Intermediate catches any casing. Expert also blocks \"SELECT\". But ORDER BY-based " +
                      "probing needs neither word, so it still sails through at every level — a blacklist can only " +
                      "ever cover phrasings someone thought to list.",
                BuildSql = (f, d) =>
                {
                    bool blocked = KeywordBlacklist.IsBlocked(f["search"], d, Keywords, ExpertKeywords);
                    var guard = "if (LooksLikeInjection(search))\n    reject();\n\n";
                    return blocked ? guard.TrimEnd() : guard + VulnerableSql(f);
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["search"].Contains("UNION");
                    var guard = "if (search.Contains(\"UNION\"))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"SELECT ProductId, Name, Price FROM dbo.Products WHERE Name LIKE '%{search}%'\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["search"].Contains("UNION");
                    var guard = "if ($search.Contains(\"UNION\")) { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"SELECT ProductId, Name, Price FROM dbo.Products WHERE Name LIKE '%$search%'\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = KeywordBlacklist.IsBlocked(f["search"], d, Keywords, ExpertKeywords);
                    var classification = Classify(f);

                    if (filterCaughtIt && classification is "injection" or "probe" or "malformed")
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Request rejected — matched the filter", Detail = "At this difficulty, the filter happened to catch this specific phrasing." };

                    if (classification == "injection")
                        return new SimulationResult
                        {
                            Severity = Severity.Critical,
                            Headline = "Usernames and password hashes appear in the product list — the filter never saw it",
                            Detail = "This payload used a casing or a phrasing the filter at this difficulty doesn't " +
                                      "check for, so it walked straight past it into the exact same vulnerable query.",
                            RowCountLabel = "6 rows — 3 products + 3 leaked user records",
                            AffectedAssets = new[] { "dbo.Users — UserName/PasswordHash exposed via UNION" },
                            LeakedRows = new IReadOnlyDictionary<string, string>[]
                            {
                                new Dictionary<string, string> { ["ProductId"] = "101", ["Name"] = "Widget Pro", ["Price"] = "19.99" },
                                new Dictionary<string, string> { ["ProductId"] = "102", ["Name"] = "Widget Mini", ["Price"] = "9.99" },
                                new Dictionary<string, string> { ["ProductId"] = "—", ["Name"] = "admin", ["Price"] = "8846F...(hash)" },
                                new Dictionary<string, string> { ["ProductId"] = "—", ["Name"] = "svc_billing", ["Price"] = "2C91A...(hash)" }
                            }
                        };
                    if (classification == "probe")
                        return new SimulationResult
                        {
                            Severity = Severity.Warning,
                            Headline = "The query still succeeds — confirms 3 columns, filter never engaged",
                            Detail = "NULL/ORDER BY probing doesn't need a blocked keyword in some phrasings, so reconnaissance still works.",
                            RowCountLabel = "3 rows — 2 products + 1 row of NULLs"
                        };
                    if (classification == "malformed")
                        return new SimulationResult { Severity = Severity.Warning, Headline = "SQL Server throws a syntax error here", Detail = "The filter never engaged, but the payload still isn't valid SQL without a trailing comment." };
                    return new SimulationResult { Severity = Severity.Success, Headline = "2 products found", Detail = "Ordinary search, the filter never engages.", RowCountLabel = "2 rows" };
                }
            },
            new FixOption
            {
                Label = "✓ Parameterized query",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                    "SELECT ProductId, Name, Price FROM dbo.Products WHERE Name LIKE @Pattern;\n\n" +
                    $"@Pattern = N'%{f["search"]}%'  -- bound as one literal value, not re-parsed as SQL",
                BuildCSharp = f =>
                    "using var cmd = new SqlCommand(\"SELECT ProductId, Name, Price FROM dbo.Products WHERE Name LIKE @Pattern\", connection);\n" +
                    "cmd.Parameters.AddWithValue(\"@Pattern\", $\"%{search}%\");\n" +
                    "using var reader = cmd.ExecuteReader();",
                BuildPowerShell = f =>
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"SELECT ProductId, Name, Price FROM dbo.Products WHERE Name LIKE @Pattern\", $connection\n" +
                    "[void]$cmd.Parameters.AddWithValue('@Pattern', \"%$search%\")\n" +
                    "$reader = $cmd.ExecuteReader()",
                Simulate = (f, _) => Classify(f) switch
                {
                    "injection" => new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "No products match — the payload is just a literal search term",
                        Detail = "The whole value, including the word UNION, is bound as one parameter. There's no SQL text " +
                                  "left to re-parse, so a second SELECT can never be appended."
                    },
                    "probe" => new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "No products match — nothing to probe",
                        Detail = "There's no SQL text left to count columns in: the whole value, NULLs and all, is just a " +
                                  "literal string being searched for in the Name column."
                    },
                    "malformed" => new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "No products match",
                        Detail = "Parameterized or not, this particular attempt was never going to parse as SQL anyway — it " +
                                  "fails the same clean way any non-matching search does."
                    },
                    _ => new SimulationResult { Severity = Severity.Success, Headline = "2 products found", Detail = "Ordinary search results, unaffected by the fix.", RowCountLabel = "2 rows" }
                }
            }
        },

        SimulateVulnerable = f => Classify(f) switch
        {
            "injection" => new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Usernames and password hashes appear in the product list",
                Detail = "A UNION SELECT only needs to match the column count and compatible types of the original " +
                          "query — here, 3 text/number-ish columns. Point those 3 columns at dbo.Users instead of " +
                          "dbo.Products and the results table renders stolen credentials as if they were products.",
                RowCountLabel = "6 rows — 3 products + 3 leaked user records",
                AffectedAssets = new[] { "dbo.Users — UserName/PasswordHash exposed via UNION" },
                LeakedRows = new IReadOnlyDictionary<string, string>[]
                {
                    new Dictionary<string, string> { ["ProductId"] = "101", ["Name"] = "Widget Pro", ["Price"] = "19.99" },
                    new Dictionary<string, string> { ["ProductId"] = "102", ["Name"] = "Widget Mini", ["Price"] = "9.99" },
                    new Dictionary<string, string> { ["ProductId"] = "—", ["Name"] = "admin", ["Price"] = "8846F...(hash)" },
                    new Dictionary<string, string> { ["ProductId"] = "—", ["Name"] = "svc_billing", ["Price"] = "2C91A...(hash)" }
                }
            },
            "probe" => new SimulationResult
            {
                Severity = Severity.Warning,
                Headline = "The query succeeds — this confirms the result set has exactly 3 columns",
                Detail = "Nothing sensitive leaks from this alone: NULL placeholders (or checking which ORDER BY " +
                          "position errors out) don't read any real data — they just confirm how many columns the " +
                          "original SELECT returns, and in what order. That's reconnaissance. The next step is " +
                          "substituting real column names from a table worth reading.",
                RowCountLabel = "3 rows — 2 products + 1 row of NULLs"
            },
            "malformed" => new SimulationResult
            {
                Severity = Severity.Warning,
                Headline = "SQL Server throws a syntax error here",
                Detail = "The template's own closing \"%';\" still follows your text, and nothing commented it out. " +
                          "The database sees a garbled string literal and refuses to run the batch — no probe, no " +
                          "breach, just an error. UNION/ORDER BY injection still needs that trailing comment."
            },
            _ => new SimulationResult { Severity = Severity.Success, Headline = "2 products found", Detail = "Ordinary search results.", RowCountLabel = "2 rows" }
        },

        HowItWorks =
            "UNION combines the results of two SELECT statements into one result set, as long as both sides have the " +
            "same number of columns with compatible types. An attacker closes the string, adds UNION SELECT, and picks " +
            "columns from any table they can name — commonly probing column count first with 'ORDER BY n' or " +
            "'UNION SELECT NULL,NULL,NULL' until it stops erroring, then substituting real columns from a juicy table.",

        WhyTheFixWorks =
            "A parameterized LIKE pattern is sent as one opaque value. The database never re-lexes it looking for " +
            "keywords, so 'UNION', 'SELECT', and every other word in the payload are just characters being searched " +
            "for in the Name column — not SQL.",

        SamplePayloads = new[]
        {
            "' ORDER BY 4--",
            "' UNION SELECT NULL,NULL,NULL --",
            "' UNION SELECT UserId, UserName, PasswordHash FROM Users --",
            "' UNION SELECT UserId, UserName, PasswordHash FROM Users",
            "' union select UserId, UserName, PasswordHash FROM Users --"
        },

        ChallengeGoal = "Make the product search return usernames and password hashes instead of products.",
        Hints = new[]
        {
            "UNION requires both sides to have the same number of columns — probe with ORDER BY or NULLs first.",
            "Once you know the column count, point those columns at a table other than Products.",
            "dbo.Users has UserId, UserName, and PasswordHash — three columns, same as this query."
        },
        ChallengeAnswer = "' UNION SELECT UserId, UserName, PasswordHash FROM Users --"
    };
}
