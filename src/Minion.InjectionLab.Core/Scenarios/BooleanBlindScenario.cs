using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Boolean-blind injection: the app never shows data, only a true/false signal — which is enough.</summary>
public static class BooleanBlindScenario
{
    private const string Baseline = "1007";

    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var s = f["orderId"].ToLowerInvariant();
        if (s.Contains("substring") || s.Contains("ascii") || s.Contains("and 1=2") || s.Contains("and 1=1"))
            return "injection";
        return "normal";
    }

    public static AttackScenario Create() => new()
    {
        Id = "boolean-blind",
        Category = AttackCategory.BlindInferential,
        Title = "Boolean-Blind Injection",
        Premise = "A support chat widget's \"check my order\" feature returns only \"Found\" or \"Not found\" — " +
                  "never any data. Surely there's nothing to steal if nothing comes back?",
        MockAppLabel = "Support Chat — Order Status",
        BaselineValues = new Dictionary<string, string> { ["orderId"] = Baseline },
        Fields = new[] { new FormField { Key = "orderId", Label = "Order ID", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Normal check", Icon = "📦", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "injection", Label = "Blind boolean probe", Icon = "🕵", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT COUNT(*) FROM dbo.Orders WHERE OrderId = {f["orderId"]};",

        BuildFixedSql = f =>
            "EXEC sp_executesql N'SELECT COUNT(*) FROM dbo.Orders WHERE OrderId = @OrderId', N'@OrderId INT', @OrderId;\n\n" +
            $"@OrderId = {f["orderId"]}",

        SimulateVulnerable = f =>
        {
            var s = f["orderId"].ToLowerInvariant();
            if (s.Contains("substring") || s.Contains("ascii"))
                return new SimulationResult
                {
                    Severity = Severity.Critical,
                    Headline = "One character of a password hash just leaked — as a yes/no answer",
                    Detail = "The app only ever says \"Found\"/\"Not found\", but that's still one bit of information. " +
                              "By asking \"is the first character of this password hash 'A'?\" over and over — a " +
                              "different guess each time — an attacker reconstructs the entire hash one character at " +
                              "a time without a single row of data ever being displayed. Tools like sqlmap automate " +
                              "exactly this.",
                    AffectedAssets = new[] { "Full data exfiltration via a yes/no oracle — no visible rows needed" }
                };
            if (s.Contains("and 1=2"))
                return new SimulationResult
                {
                    Severity = Severity.Warning,
                    Headline = "\"Not found\" — even though order 1007 really exists",
                    Detail = "Forcing the WHERE clause false proves the input is reaching the SQL engine as code, not " +
                              "just data. That confirmation is the first step — next comes asking real questions about " +
                              "the data instead of just true/false."
                };
            return new SimulationResult { Severity = Severity.Success, Headline = "Found", Detail = "Order 1007 exists." };
        },

        SimulateFixed = f => new SimulationResult
        {
            Severity = Classify(f) == "injection" ? Severity.Blocked : Severity.Success,
            Headline = Classify(f) == "injection" ? "Not found — the payload never parses as a condition" : "Found",
            Detail = Classify(f) == "injection"
                ? "The parameter value is compared as a whole, literal OrderId. There's no way to append a second " +
                  "condition, so there's no true/false oracle to exploit."
                : "Order 1007 exists, unaffected by the fix."
        },

        HowItWorks =
            "Boolean-blind injection doesn't need the database to ever show its data — only to answer one yes/no " +
            "question per request. An attacker builds conditions like \"AND SUBSTRING(PasswordHash,1,1)='A'\", and the " +
            "visible difference between \"Found\" and \"Not found\" becomes a one-bit channel. Enough requests, " +
            "guessing one character at a time, reconstructs anything in the database.",

        WhyTheFixWorks =
            "Parameterizing removes the ability to add a second condition at all — the attacker's text is just the " +
            "OrderId value being compared, never a clause the engine evaluates, so there's no oracle to query.",

        SamplePayloads = new[]
        {
            "1007 AND 1=1--",
            "1007 AND 1=2--",
            "1007 AND SUBSTRING((SELECT TOP 1 PasswordHash FROM Users),1,1)='A'--"
        },

        ChallengeGoal = "Make the order check return \"Not found\" for order 1007, even though it exists.",
        Hints = new[]
        {
            "You don't need to see data to prove the input is being evaluated as SQL — just flip the answer.",
            "Add a condition that's always false, the same way you'd add one that's always true."
        },
        ChallengeAnswer = "1007 AND 1=2--"
    };
}
