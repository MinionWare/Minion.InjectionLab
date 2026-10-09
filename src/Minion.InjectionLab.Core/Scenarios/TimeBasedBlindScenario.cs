using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Time-based blind injection: when there's no visible difference at all, a delay becomes the signal.</summary>
public static class TimeBasedBlindScenario
{
    private const string Baseline = "1007";

    private static string Classify(IReadOnlyDictionary<string, string> f)
        => f["orderId"].ToLowerInvariant().Contains("waitfor") ? "injection" : "normal";

    public static AttackScenario Create() => new()
    {
        Id = "time-based-blind",
        Category = AttackCategory.BlindInferential,
        Title = "Time-Based Blind Injection",
        Premise = "This order-status page is even more locked down than the boolean-blind one — it shows the exact " +
                  "same confirmation page no matter what. There's genuinely nothing to see.",
        MockAppLabel = "Support Chat — Order Status (locked down)",
        BaselineValues = new Dictionary<string, string> { ["orderId"] = Baseline },
        Fields = new[] { new FormField { Key = "orderId", Label = "Order ID", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Normal check", Icon = "📦", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "injection", Label = "Timing probe", Icon = "⏱", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT 1 FROM dbo.Orders WHERE OrderId = {f["orderId"]};",

        BuildFixedSql = f =>
            "EXEC sp_executesql N'SELECT 1 FROM dbo.Orders WHERE OrderId = @OrderId', N'@OrderId INT', @OrderId;\n\n" +
            $"@OrderId = {f["orderId"]}",

        SimulateVulnerable = f => Classify(f) == "injection"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "The response would pause for 5 full seconds before returning",
                Detail = "No data, no error, no visible change in the page at all — but the response takes exactly 5 " +
                          "seconds longer. That delay IS the signal. Wrap the delay in a condition " +
                          "(\"IF (condition) WAITFOR DELAY '0:0:5'\") and an attacker can ask the same kind of yes/no " +
                          "questions as boolean-blind injection, just by measuring a stopwatch instead of reading text.",
                AffectedAssets = new[] { "A measurable timing oracle — works even with zero visible output difference" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Confirmed", Detail = "Ordinary, instant response." },

        SimulateFixed = f => new SimulationResult
        {
            Severity = Classify(f) == "injection" ? Severity.Blocked : Severity.Success,
            Headline = Classify(f) == "injection" ? "Confirmed — instantly, no delay" : "Confirmed",
            Detail = Classify(f) == "injection"
                ? "WAITFOR is just text inside the parameter value now — there's no SQL left to parse it as a command, " +
                  "so the response time never changes."
                : "Ordinary, instant response, unaffected by the fix."
        },

        HowItWorks =
            "When an app gives an attacker literally no observable difference between any outcome, they can still " +
            "extract a yes/no answer by making the database itself take measurably longer to respond when a condition " +
            "is true — typically with WAITFOR DELAY. Response time becomes the side channel, and the same " +
            "character-by-character technique as boolean-blind injection applies, just timed with a stopwatch instead " +
            "of read off the page.",

        WhyTheFixWorks =
            "Same mechanism as every other fix here: the value is bound as data, never re-parsed as SQL, so WAITFOR " +
            "never executes as a command regardless of how the input is worded.",

        SamplePayloads = new[]
        {
            "1007; WAITFOR DELAY '0:0:5'--",
            "1007 IF (1=1) WAITFOR DELAY '0:0:5'--"
        },

        ChallengeGoal = "Make the server visibly pause for 5 seconds before responding — with no other observable change.",
        Hints = new[]
        {
            "If there's nothing to read, the signal has to come from something you can measure instead.",
            "SQL Server can be told to simply wait before continuing — what statement does that?"
        },
        ChallengeAnswer = "1007; WAITFOR DELAY '0:0:5'--"
    };
}
