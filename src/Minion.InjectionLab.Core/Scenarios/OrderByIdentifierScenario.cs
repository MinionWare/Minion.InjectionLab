using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Identifier injection: parameters can't substitute for column names at all — only an allow-list can.</summary>
public static class OrderByIdentifierScenario
{
    private static readonly string[] AllowList = { "Name", "Price", "CreatedDate" };
    private const string Baseline = "Name";

    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var s = f["sortColumn"];
        if (Array.Exists(AllowList, c => string.Equals(c, s, StringComparison.OrdinalIgnoreCase))) return "normal";
        return "injection";
    }

    public static AttackScenario Create() => new()
    {
        Id = "order-by-identifier",
        Category = AttackCategory.IdentifiersAndDynamicSql,
        Title = "Identifier Injection (ORDER BY)",
        Premise = "A product list has a \"sort by\" option. Column names can't be bound as @parameters the normal " +
                  "way — parameters only ever substitute for values, never for identifiers — so a lot of apps fall " +
                  "back to string-building here even when everything else is properly parameterized.",
        MockAppLabel = "Store — Product List",
        BaselineValues = new Dictionary<string, string> { ["sortColumn"] = Baseline },
        Fields = new[] { new FormField { Key = "sortColumn", Label = "Sort by", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Allow-listed column", Icon = "✅", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "injection", Label = "Arbitrary expression", Icon = "💉", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT * FROM dbo.Products ORDER BY {f["sortColumn"]};",

        BuildFixedSql = f =>
        {
            var safe = Array.Exists(AllowList, c => string.Equals(c, f["sortColumn"], StringComparison.OrdinalIgnoreCase))
                ? f["sortColumn"]
                : "Name";
            return "-- @parameter placeholders don't work for identifiers — validate against a fixed allow-list instead:\n" +
                   "DECLARE @SafeColumn sysname =\n" +
                  $"    CASE @SortColumn WHEN 'Name' THEN N'Name' WHEN 'Price' THEN N'Price'\n" +
                   "         WHEN 'CreatedDate' THEN N'CreatedDate' ELSE N'Name' END;\n\n" +
                  $"EXEC('SELECT * FROM dbo.Products ORDER BY ' + QUOTENAME(@SafeColumn));\n" +
                  $"-- your input ('{f["sortColumn"]}') resolves to: {safe}";
        },

        SimulateVulnerable = f => Classify(f) == "injection"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Arbitrary SQL executes from inside what was supposed to be just a column name",
                Detail = "ORDER BY accepts a full expression, not just a bare column — so string-concatenating this " +
                          "value is exactly as dangerous as concatenating into a WHERE clause. The fact that it " +
                          "\"looks like\" a harmless sort option doesn't make it safe.",
                AffectedAssets = new[] { "Arbitrary expression executed from the ORDER BY clause" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Sorted by Name", Detail = "Ordinary sort." },

        SimulateFixed = f => Classify(f) == "injection"
            ? new SimulationResult
            {
                Severity = Severity.Blocked,
                Headline = "Falls back to the default sort (Name)",
                Detail = "Anything not on the allow-list never reaches the SQL text at all — it's rejected (or " +
                          "substituted with a safe default) before the query is even built."
            }
            : new SimulationResult { Severity = Severity.Success, Headline = $"Sorted by {f["sortColumn"]}", Detail = "An allow-listed column, passed straight through." },

        HowItWorks =
            "Identifiers (table and column names) are categorically different from values: @parameter placeholders " +
            "only ever bind as data, never as SQL syntax, so 'ORDER BY @SortColumn' either errors or doesn't do what " +
            "a developer expects. Faced with that, many fall back to plain string concatenation for \"just a column " +
            "name\" — reopening exactly the same hole as any other injection, because ORDER BY accepts arbitrary " +
            "expressions, not only bare identifiers.",

        WhyTheFixWorks =
            "Validate the requested column against a hard-coded allow-list (or look it up from sys.columns) before " +
            "ever building the SQL text, and wrap the validated identifier in QUOTENAME() as defense in depth. " +
            "Nothing the user typed is ever trusted as-is.",

        SamplePayloads = new[]
        {
            "Name; WAITFOR DELAY '0:0:5'--",
            "(SELECT 1); DROP TABLE Products--"
        },

        ChallengeGoal = "Make the product list execute a WAITFOR delay through the \"sort by\" option.",
        Hints = new[]
        {
            "This value can't be parameterized the normal way at all — it's an identifier, not data.",
            "ORDER BY accepts more than just a column name — it accepts a whole expression.",
            "What ends a statement and lets a new one begin?"
        },
        ChallengeAnswer = "Name; WAITFOR DELAY '0:0:5'--"
    };
}
