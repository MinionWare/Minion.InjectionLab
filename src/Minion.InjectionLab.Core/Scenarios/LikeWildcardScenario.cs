using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>
/// LIKE wildcard abuse: parameterization alone doesn't neutralize % and _ — those are LIKE's own
/// syntax. This is the flagship "more than one fix, not all equally complete" scenario.
/// </summary>
public static class LikeWildcardScenario
{
    private const string Baseline = "widget";

    private static string VulnerableSql(IReadOnlyDictionary<string, string> f) =>
        $"SELECT ProductId, Name FROM dbo.Products WHERE Name LIKE '%{f["search"]}%';";

    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var raw = f["search"];
        var s = raw.ToLowerInvariant();
        bool looksLikeSqlBreakout = s.Contains('\'') && (s.Contains(" or ") || s.Contains("union"));
        if (looksLikeSqlBreakout)
            // Real SQL Server parsing (ScriptDom), not a guessed-at "ends with --" pattern.
            return SqlSyntaxChecker.HasSyntaxError(VulnerableSql(f)) ? "malformed" : "injection";
        if (raw.Contains('%') || raw.Contains('_')) return "wildcard";
        return "normal";
    }

    public static AttackScenario Create() => new()
    {
        Id = "like-wildcard",
        Category = AttackCategory.ClassicInBand,
        Title = "LIKE Wildcard Abuse",
        Premise = "A product search uses LIKE '%term%'. Even once the obvious SQL-injection hole is patched with " +
                  "parameters, % and _ are still special characters — to the LIKE operator itself, not to SQL syntax.",
        MockAppLabel = "Store — Product Search",
        BaselineValues = new Dictionary<string, string> { ["search"] = Baseline },
        Fields = new[] { new FormField { Key = "search", Label = "Search products", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Normal search", Icon = "🔍", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "wildcard", Label = "Wildcard abuse", Icon = "🌀", Kind = PathKind.Neutral },
            new DecisionPathDef { Key = "malformed", Label = "Broken syntax", Icon = "🚫", Kind = PathKind.Neutral },
            new DecisionPathDef { Key = "injection", Label = "SQL injection", Icon = "💉", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = VulnerableSql,

        BuildVulnerableCSharp = f =>
            "var sql = $\"SELECT ProductId, Name FROM dbo.Products WHERE Name LIKE '%{search}%'\";\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "using var reader = cmd.ExecuteReader();",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT ProductId, Name FROM dbo.Products WHERE Name LIKE '%$search%'\"\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql",

        // Two real fixes, not equally complete — this is the point of the scenario.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Parameterized only",
                Grade = FixGrade.Partial,
                Gap = "Doesn't escape LIKE's own wildcard characters — a parameterized search for \"%\" still " +
                      "matches every single row, and \"_\" still matches any one character.",
                BuildSql = (f, _) =>
                    "SELECT ProductId, Name FROM dbo.Products WHERE Name LIKE @Pattern;\n\n" +
                   $"@Pattern = N'%{f["search"]}%'  -- bound as one literal value, not re-parsed as SQL",
                BuildCSharp = f =>
                    "using var cmd = new SqlCommand(\"SELECT ProductId, Name FROM dbo.Products WHERE Name LIKE @Pattern\", connection);\n" +
                    "cmd.Parameters.AddWithValue(\"@Pattern\", $\"%{search}%\"); // % and _ inside search still act as wildcards\n" +
                    "using var reader = cmd.ExecuteReader();",
                BuildPowerShell = f =>
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"SELECT ProductId, Name FROM dbo.Products WHERE Name LIKE @Pattern\", $connection\n" +
                    "[void]$cmd.Parameters.AddWithValue('@Pattern', \"%$search%\")  # % and _ inside $search still act as wildcards\n" +
                    "$reader = $cmd.ExecuteReader()",
                Simulate = (f, _) => Classify(f) switch
                {
                    "injection" or "malformed" => new SimulationResult { Severity = Severity.Blocked, Headline = "No products match", Detail = "Parameterized — the quote-breakout attempt is just a literal search string now." },
                    "wildcard" => new SimulationResult
                    {
                        Severity = Severity.Warning,
                        Headline = "Still matches every product — parameters don't stop this",
                        Detail = "The value is safely bound as data, so there's no SQL injection here. But LIKE still " +
                                  "interprets '%' inside that bound value as its own wildcard — parameterization " +
                                  "protects against SQL syntax, not against LIKE's pattern-matching syntax.",
                        RowCountLabel = "all rows"
                    },
                    _ => new SimulationResult { Severity = Severity.Success, Headline = "2 products found", Detail = "Ordinary search, unaffected by the fix." }
                }
            },
            new FixOption
            {
                Label = "✓ Parameterized + wildcards escaped",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                {
                    var escaped = f["search"].Replace("[", "[[]").Replace("%", "[%]").Replace("_", "[_]");
                    return "SELECT ProductId, Name FROM dbo.Products WHERE Name LIKE @Pattern ESCAPE '\\';\n\n" +
                          $"@Pattern = N'%{escaped}%'  -- your literal %, _, and [ are now just characters to search for";
                },
                BuildCSharp = f =>
                {
                    var escaped = f["search"].Replace("[", "[[]").Replace("%", "[%]").Replace("_", "[_]");
                    return "static string Escape(string s) => s.Replace(\"[\", \"[[]\").Replace(\"%\", \"[%]\").Replace(\"_\", \"[_]\");\n\n" +
                           "using var cmd = new SqlCommand(\"SELECT ProductId, Name FROM dbo.Products WHERE Name LIKE @Pattern ESCAPE '\\\\'\", connection);\n" +
                          $"cmd.Parameters.AddWithValue(\"@Pattern\", $\"%{{Escape(search)}}%\"); // resolves to: %{escaped}%\n" +
                           "using var reader = cmd.ExecuteReader();";
                },
                BuildPowerShell = f =>
                {
                    var escaped = f["search"].Replace("[", "[[]").Replace("%", "[%]").Replace("_", "[_]");
                    return "function Escape-Like($s) { $s -replace '\\[', '[[]' -replace '%', '[%]' -replace '_', '[_]' }\n\n" +
                           "$cmd = New-Object System.Data.SqlClient.SqlCommand \"SELECT ProductId, Name FROM dbo.Products WHERE Name LIKE @Pattern ESCAPE '\\'\", $connection\n" +
                          $"[void]$cmd.Parameters.AddWithValue('@Pattern', \"%$(Escape-Like $search)%\")  # resolves to: %{escaped}%\n" +
                           "$reader = $cmd.ExecuteReader()";
                },
                Simulate = (f, _) => Classify(f) switch
                {
                    "injection" or "malformed" => new SimulationResult { Severity = Severity.Blocked, Headline = "No products match", Detail = "Parameterized — the quote-breakout attempt is just a literal search string now." },
                    "wildcard" => new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "Treated as a literal percent sign — no products match",
                        Detail = "Escaping %, _, and [ before building the LIKE pattern makes them literal characters " +
                                  "to search for, not wildcard syntax. Both fixes are needed — this one adds the " +
                                  "piece parameterization alone was missing."
                    },
                    _ => new SimulationResult { Severity = Severity.Success, Headline = "2 products found", Detail = "Ordinary search, unaffected by the fix." }
                }
            }
        },

        SimulateVulnerable = f => Classify(f) switch
        {
            "injection" => new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Full SQL injection — this query was never parameterized at all",
                Detail = "Alongside the wildcard quirk, this version is still built by concatenation, so an ordinary " +
                          "quote-breakout bypass works exactly like any other search box — as long as the rest of " +
                          "the original query is properly commented out.",
                AffectedAssets = new[] { "Full query bypass — not just a wildcard-matching quirk" }
            },
            "malformed" => new SimulationResult
            {
                Severity = Severity.Warning,
                Headline = "SQL Server throws a syntax error here",
                Detail = "Close, but the template's own closing \"%';\" still follows your text, and it was never " +
                          "commented out. The database sees an unclosed/garbled string literal and refuses to run " +
                          "the batch at all — no bypass, just an error.",
            },
            "wildcard" => new SimulationResult
            {
                Severity = Severity.Warning,
                Headline = "Every single product matched",
                Detail = "'%' is a wildcard to the LIKE operator — it matches any sequence of characters, including " +
                          "zero. This isn't a full SQL injection (the quote marks are intact), but it still lets a " +
                          "search box be used to enumerate far more data than it was scoped for, or hammer the " +
                          "database with a deliberately expensive pattern.",
                RowCountLabel = "all rows"
            },
            _ => new SimulationResult { Severity = Severity.Success, Headline = "2 products found", Detail = "Ordinary search." }
        },

        HowItWorks =
            "LIKE has its own tiny syntax, independent of SQL itself: % matches any run of characters, _ matches " +
            "exactly one, and [ starts a character-class. None of that is neutralized by parameterizing the query — " +
            "parameters stop the value from being re-parsed as SQL, but LIKE still re-parses it as a *pattern*. A " +
            "search box that lets users submit raw % or _ can be made to match far more (or more expensive) data " +
            "than intended, even in an otherwise fully parameterized app. And as always, a SQL-injection attempt " +
            "still needs to neutralize whatever the template puts after the injection point — usually with a " +
            "trailing comment — or it just breaks the query outright instead of bypassing it.",

        WhyTheFixWorks =
            "Two independent fixes are needed here, which is why this scenario has two to compare: parameterize " +
            "the query (stops SQL injection), AND escape the user's literal %, _, and [ characters before building " +
            "the LIKE pattern (stops wildcard abuse). Either one alone leaves a real gap.",

        SamplePayloads = new[]
        {
            "%",
            "_idget",
            "' OR 1=1 --",
            "' OR 1=1"
        },

        ChallengeGoal = "Get the search box to return every single product, without using a quote character or the word OR.",
        Hints = new[]
        {
            "The LIKE operator has its own wildcard characters, completely separate from SQL syntax.",
            "What single character matches absolutely anything in a LIKE pattern?"
        },
        ChallengeAnswer = "%"
    };
}
