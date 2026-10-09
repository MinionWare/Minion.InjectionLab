using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>LIKE wildcard abuse: parameterization alone doesn't neutralize % and _ — those are LIKE's own syntax.</summary>
public static class LikeWildcardScenario
{
    private const string Baseline = "widget";

    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var s = f["search"].ToLowerInvariant();
        if (s.Contains('\'') && (s.Contains(" or ") || s.Contains("--") || s.Contains("union"))) return "injection";
        if (f["search"].Contains('%') || f["search"].Contains('_')) return "wildcard";
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
            new DecisionPathDef { Key = "injection", Label = "SQL injection", Icon = "💉", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT ProductId, Name FROM dbo.Products WHERE Name LIKE '%{f["search"]}%';",

        BuildFixedSql = f =>
        {
            var escaped = f["search"].Replace("[", "[[]").Replace("%", "[%]").Replace("_", "[_]");
            return "-- Parameterized AND with LIKE's own wildcard characters escaped first:\n" +
                   "SELECT ProductId, Name FROM dbo.Products WHERE Name LIKE @Pattern ESCAPE '\\';\n\n" +
                  $"@Pattern = N'%{escaped}%'  -- your literal %, _, and [ are now just characters to search for";
        },

        SimulateVulnerable = f => Classify(f) switch
        {
            "injection" => new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Full SQL injection — this query was never parameterized at all",
                Detail = "Alongside the wildcard quirk, this version is still built by concatenation, so an ordinary " +
                          "quote-breakout bypass works exactly like any other search box.",
                AffectedAssets = new[] { "Full query bypass — not just a wildcard-matching quirk" }
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

        SimulateFixed = f => Classify(f) switch
        {
            "injection" => new SimulationResult { Severity = Severity.Blocked, Headline = "No products match", Detail = "Parameterized — the quote-breakout attempt is just a literal search string now." },
            "wildcard" => new SimulationResult
            {
                Severity = Severity.Blocked,
                Headline = "Treated as a literal percent sign — no products match",
                Detail = "Escaping %, _, and [ before building the LIKE pattern makes them literal characters to " +
                          "search for, not wildcard syntax — this is a separate fix from parameterization, and both " +
                          "are needed."
            },
            _ => new SimulationResult { Severity = Severity.Success, Headline = "2 products found", Detail = "Ordinary search, unaffected by the fix." }
        },

        HowItWorks =
            "LIKE has its own tiny syntax, independent of SQL itself: % matches any run of characters, _ matches " +
            "exactly one, and [ starts a character-class. None of that is neutralized by parameterizing the query — " +
            "parameters stop the value from being re-parsed as SQL, but LIKE still re-parses it as a *pattern*. A " +
            "search box that lets users submit raw % or _ can be made to match far more (or more expensive) data " +
            "than intended, even in an otherwise fully parameterized app.",

        WhyTheFixWorks =
            "Escape the user's literal %, _, and [ characters (commonly by wrapping them in brackets, e.g. '%' → " +
            "'[%]') before building the LIKE pattern, and specify an ESCAPE clause. Combined with parameterization, " +
            "this makes the search behave exactly as the box implies: searching for literal text, nothing more.",

        SamplePayloads = new[]
        {
            "%",
            "_idget",
            "' OR 1=1--"
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
