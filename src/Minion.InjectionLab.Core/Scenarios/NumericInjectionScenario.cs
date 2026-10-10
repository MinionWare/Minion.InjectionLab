using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Numeric injection: "it's just a number" doesn't mean it's safe to concatenate unquoted.</summary>
public static class NumericInjectionScenario
{
    private const string Baseline = "42";

    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var s = f["productId"].Trim();
        if (s.Length == 0) return "normal";
        if (int.TryParse(s, out _)) return "normal";
        return "injection";
    }

    public static AttackScenario Create() => new()
    {
        Id = "numeric-injection",
        Category = AttackCategory.ClassicInBand,
        Title = "Numeric Injection (No Quotes Needed)",
        Premise = "A product detail page looks up a numeric ProductId. The developer reasoned: \"it's a number, " +
                  "there's nothing to escape, so there's nothing to inject.\"",
        MockAppLabel = "Store — Product Detail",
        BaselineValues = new Dictionary<string, string> { ["productId"] = Baseline },
        Fields = new[] { new FormField { Key = "productId", Label = "Product ID", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Valid numeric ID", Icon = "🔢", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "injection", Label = "Non-numeric payload", Icon = "💉", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT * FROM dbo.Products WHERE ProductId = {f["productId"]};",

        BuildVulnerableCSharp = f =>
            "// No quotes anywhere — looks \"obviously\" safe to a lot of developers\n" +
            "var sql = $\"SELECT * FROM dbo.Products WHERE ProductId = {productId}\";\n" +
            "using var cmd = new SqlCommand(sql, connection);",

        // Two real fixes people actually ship, not equally complete: a keyword blacklist (looks
        // like a fix, isn't one) vs. a strongly-typed parameter.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block input containing \"OR\"",
                Grade = FixGrade.Partial,
                Gap = "Checks for the literal uppercase word \"OR\" — lowercase \"or\" sails straight through. And " +
                      "this only ever blocks one specific keyword; UNION, semicolons, and anything else non-numeric " +
                      "are all still wide open.",
                BuildSql = f =>
                {
                    bool blocked = f["productId"].Contains("OR");
                    var guard = "if (productId.Contains(\"OR\"))\n    reject();\n\n";
                    return blocked ? guard.TrimEnd() : guard + $"SELECT * FROM dbo.Products WHERE ProductId = {f["productId"]};";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["productId"].Contains("OR");
                    var guard = "if (productId.Contains(\"OR\"))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"SELECT * FROM dbo.Products WHERE ProductId = {productId}\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = f =>
                {
                    bool filterCaughtIt = f["productId"].Contains("OR");
                    if (Classify(f) == "injection" && !filterCaughtIt)
                        return new SimulationResult
                        {
                            Severity = Severity.Critical,
                            Headline = "Every single product in the catalog is returned — the filter never saw it",
                            Detail = "The blacklist only checks for the exact uppercase word \"OR\". Lowercase, or any " +
                                      "payload that doesn't need that specific word, walks straight past it.",
                            RowCountLabel = "all rows",
                            AffectedAssets = new[] { "dbo.Products — the entire catalog exposed" }
                        };
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Request rejected — contains \"OR\"", Detail = "This specific payload happened to use the exact uppercase word the filter checks for." };
                    return new SimulationResult { Severity = Severity.Success, Headline = "Product #42 found", Detail = "Ordinary lookup, the filter never engages." };
                }
            },
            new FixOption
            {
                Label = "✓ Strongly-typed parameter",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = f =>
                    "EXEC sp_executesql N'SELECT * FROM dbo.Products WHERE ProductId = @ProductId', N'@ProductId INT', @ProductId;\n\n" +
                    $"@ProductId = {f["productId"]}  -- must actually parse as INT before this even runs",
                BuildCSharp = f =>
                    "using var cmd = new SqlCommand(\"SELECT * FROM dbo.Products WHERE ProductId = @ProductId\", connection);\n" +
                    "cmd.Parameters.Add(\"@ProductId\", SqlDbType.Int).Value = productId; // throws if productId isn't an int",
                Simulate = f => Classify(f) == "injection"
                    ? new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "Rejected before it ever reaches the database",
                        Detail = "The parameter is declared as SqlDbType.Int. A value that doesn't actually parse as an " +
                                  "integer fails at the provider/type-conversion layer — the SQL engine never even sees it."
                    }
                    : new SimulationResult { Severity = Severity.Success, Headline = "Product #42 found", Detail = "Ordinary lookup, unaffected by the fix." }
            }
        },

        SimulateVulnerable = f => Classify(f) == "injection"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Every single product in the catalog is returned",
                Detail = "No quote character was ever needed — the value is dropped straight into the SQL text " +
                          "unquoted, so 'OR 1=1' works exactly like it would after breaking out of a string literal. " +
                          "\"It's just a number\" was never a safety property; concatenation is the actual problem, " +
                          "regardless of data type.",
                RowCountLabel = "all rows",
                AffectedAssets = new[] { "dbo.Products — the entire catalog exposed, including unlisted/internal items" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Product #42 found", Detail = "Ordinary lookup." },


        HowItWorks =
            "Quote characters only matter because they close a string literal early. When a value is concatenated in " +
            "unquoted — as numeric IDs often are — there's no literal to break out of in the first place: the " +
            "attacker's text IS the SQL, directly. 'OR 1=1' needs no quotes at all here.",

        WhyTheFixWorks =
            "A strongly-typed parameter (SqlDbType.Int) forces the value to actually be a valid integer before the " +
            "command can execute. This is a second, independent layer of defense on top of parameterization itself — " +
            "it rejects the payload outright rather than merely neutralizing it.",

        SamplePayloads = new[]
        {
            "42 OR 1=1",
            "42; DROP TABLE Products--",
            "42 UNION SELECT UserName, PasswordHash, NULL, NULL FROM Users--",
            "42 or 1=1"
        },

        ChallengeGoal = "Get every product to show up on a single-product lookup page — without typing a single quote character.",
        Hints = new[]
        {
            "This value is never wrapped in quotes to begin with — so there's nothing to \"break out\" of.",
            "You don't need a quote to add a condition that's always true."
        },
        ChallengeAnswer = "42 OR 1=1"
    };
}
