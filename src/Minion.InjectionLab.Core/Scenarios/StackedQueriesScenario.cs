using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Stacked queries: a semicolon lets an entirely separate statement ride along in the same batch.</summary>
public static class StackedQueriesScenario
{
    private const string Baseline = "1007";

    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var s = f["orderId"].ToLowerInvariant();
        if (s.Contains(';') && (s.Contains("drop") || s.Contains("insert") || s.Contains("update") || s.Contains("delete")))
            return "injection";
        return "normal";
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
            new DecisionPathDef { Key = "injection", Label = "Stacked statement", Icon = "💉", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT * FROM dbo.Orders WHERE OrderId = {f["orderId"]};",

        BuildFixedSql = f =>
            "EXEC sp_executesql N'SELECT * FROM dbo.Orders WHERE OrderId = @OrderId', N'@OrderId INT', @OrderId;\n\n" +
            $"@OrderId = {f["orderId"]}  -- must parse as INT, or the call fails before touching SQL text",

        SimulateVulnerable = f => Classify(f) == "injection"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "A second, unrelated statement just executed in the same batch",
                Detail = "The semicolon ends the SELECT, and whatever comes after it is parsed as a brand new T-SQL " +
                          "statement — not a modified WHERE clause, but an entirely separate command with its own " +
                          "full privileges. This is a different (and often worse) mechanism than a tautology bypass.",
                AffectedAssets = new[] { "A second DDL/DML statement executed with the app's own database permissions" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Order 1007 found", Detail = "Ordinary lookup." },

        SimulateFixed = f => Classify(f) == "injection"
            ? new SimulationResult
            {
                Severity = Severity.Blocked,
                Headline = "The whole string is one parameter value — no second statement ever forms",
                Detail = "sp_executesql compiles the SQL text once, with @OrderId as a typed placeholder. A semicolon " +
                          "inside the bound value is just a character; the batch boundary was fixed before the value " +
                          "was ever substituted in."
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Order 1007 found", Detail = "Ordinary lookup, unaffected by the fix." },

        HowItWorks =
            "T-SQL batches can contain multiple statements separated by semicolons. When an app concatenates user " +
            "input directly into a batch, a semicolon in that input doesn't modify the existing query — it ends it, " +
            "and anything after becomes a new, independent statement that runs with the same permissions as the app.",

        WhyTheFixWorks =
            "sp_executesql (or any parameterized command) only ever compiles the fixed SQL text once; the parameter " +
            "value is substituted afterward as data, so a semicolon inside it can't start a new statement — there's no " +
            "longer any SQL text left to parse at that point.",

        SamplePayloads = new[]
        {
            "1007; DROP TABLE Orders--",
            "1007; INSERT INTO Users (UserName, Role) VALUES ('hacker','Administrator')--"
        },

        ChallengeGoal = "Get a second, entirely different SQL statement to execute alongside the lookup query.",
        Hints = new[]
        {
            "T-SQL batches can hold more than one statement — what character separates them?",
            "Whatever you put after that character runs as its own independent statement, not part of the WHERE clause."
        },
        ChallengeAnswer = "1007; DROP TABLE Orders--"
    };
}
