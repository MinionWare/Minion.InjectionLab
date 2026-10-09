using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>UNION-based injection: pulling columns from an unrelated table through a search box.</summary>
public static class UnionSelectScenario
{
    private const string Baseline = "widget";

    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var s = f["search"].ToLowerInvariant();
        if (s.Contains("union") && s.Contains("select")) return "injection";
        return "normal";
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
            new DecisionPathDef { Key = "injection", Label = "UNION injection pattern", Icon = "💉", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f =>
            $"SELECT ProductId, Name, Price FROM dbo.Products WHERE Name LIKE '%{f["search"]}%';",

        BuildFixedSql = f =>
            "SELECT ProductId, Name, Price FROM dbo.Products WHERE Name LIKE @Pattern;\n\n" +
            $"@Pattern = N'%{f["search"]}%'  -- bound as one literal value, not re-parsed as SQL",

        SimulateVulnerable = f => Classify(f) == "injection"
            ? new SimulationResult
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
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "2 products found", Detail = "Ordinary search results.", RowCountLabel = "2 rows" },

        SimulateFixed = f => Classify(f) == "injection"
            ? new SimulationResult
            {
                Severity = Severity.Blocked,
                Headline = "No products match — the payload is just a literal search term",
                Detail = "The whole value, including the word UNION, is bound as one parameter. There's no SQL text " +
                          "left to re-parse, so a second SELECT can never be appended."
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "2 products found", Detail = "Ordinary search results, unaffected by the fix.", RowCountLabel = "2 rows" },

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
            "' UNION SELECT NULL,NULL,NULL --",
            "' UNION SELECT UserId, UserName, PasswordHash FROM Users --",
            "' ORDER BY 4--"
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
