using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Boolean-blind injection: the app never shows data, only a true/false signal — which is enough.</summary>
public static class BooleanBlindScenario
{
    private const string Baseline = "1007";

    private static readonly string[] Keywords = { "AND" };
    private static readonly string[] ExpertKeywords = { "OR" };

    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var s = f["orderId"].ToLowerInvariant();
        if (s.Contains("substring") || s.Contains("ascii")) return "exfiltrate";
        if (s.Contains("and 1=2") || s.Contains("or 1=2")) return "flip";
        if (s.Contains("and 1=1") || s.Contains("or 1=1")) return "confirm";
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
            new DecisionPathDef { Key = "confirm", Label = "Confirms injectable", Icon = "🔎", Kind = PathKind.Neutral },
            new DecisionPathDef { Key = "flip", Label = "Flips a true answer false", Icon = "🕵", Kind = PathKind.Malicious },
            new DecisionPathDef { Key = "exfiltrate", Label = "Exfiltrates one bit at a time", Icon = "🧬", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT COUNT(*) FROM dbo.Orders WHERE OrderId = {f["orderId"]};",

        BuildVulnerableCSharp = f =>
            "var sql = $\"SELECT COUNT(*) FROM dbo.Orders WHERE OrderId = {orderId}\";\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "bool found = (int)cmd.ExecuteScalar() > 0;",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT COUNT(*) FROM dbo.Orders WHERE OrderId = $orderId\"\n" +
            "$found = (Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql) -gt 0",

        // Two real fixes, not equally complete: a keyword blacklist (looks like a fix, isn't one)
        // vs. real parameterization.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block input containing \"AND\"",
                Grade = FixGrade.Partial,
                Gap = "At Beginner, checks for the literal uppercase word \"AND\" — lowercase \"and\" sails through. " +
                      "Intermediate catches any casing. Expert also blocks \"OR\". But blind techniques don't need " +
                      "either word specifically — a condition can be phrased with CASE WHEN, IIF, or a dozen other " +
                      "constructs this filter was never told about. Blacklisting is particularly hopeless against " +
                      "blind injection for exactly this reason.",
                BuildSql = (f, d) =>
                {
                    bool blocked = KeywordBlacklist.IsBlocked(f["orderId"], d, Keywords, ExpertKeywords);
                    // The filter runs in application code, before any SQL is built — see the C#/PowerShell tabs.
                    return blocked ? "-- Request rejected by the application; no SQL was ever built." : $"SELECT COUNT(*) FROM dbo.Orders WHERE OrderId = {f["orderId"]};";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["orderId"].Contains("AND");
                    var guard = "if (orderId.Contains(\"AND\"))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"SELECT COUNT(*) FROM dbo.Orders WHERE OrderId = {orderId}\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["orderId"].Contains("AND");
                    var guard = "if ($orderId.Contains(\"AND\")) { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"SELECT COUNT(*) FROM dbo.Orders WHERE OrderId = $orderId\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = KeywordBlacklist.IsBlocked(f["orderId"], d, Keywords, ExpertKeywords);
                    var classification = Classify(f);
                    if (filterCaughtIt && classification != "normal")
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Request rejected — matched the filter", Detail = "At this difficulty, the filter happened to catch this specific phrasing." };
                    return classification switch
                    {
                        "exfiltrate" => new SimulationResult
                        {
                            Severity = Severity.Critical,
                            Headline = "One character of a password hash just leaked — the filter never saw it",
                            Detail = "This phrasing didn't need any word the filter checks for, so the one-bit oracle " +
                                      "works exactly as if there were no filter at all.",
                            AffectedAssets = new[] { "Full data exfiltration via a yes/no oracle — no visible rows needed" }
                        },
                        "flip" => new SimulationResult { Severity = Severity.Warning, Headline = "\"Not found\" — even though order 1007 really exists", Detail = "The filter never engaged; the oracle is confirmed." },
                        "confirm" => new SimulationResult { Severity = Severity.Success, Headline = "Found", Detail = "The filter never engaged for this phrasing either." },
                        _ => new SimulationResult { Severity = Severity.Success, Headline = "Found", Detail = "Ordinary check, the filter never engages." }
                    };
                }
            },
            new FixOption
            {
                Label = "✓ Parameterized query",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                    "EXEC sp_executesql N'SELECT COUNT(*) FROM dbo.Orders WHERE OrderId = @OrderId', N'@OrderId INT', @OrderId;\n\n" +
                    $"@OrderId = {f["orderId"]}",
                BuildCSharp = f =>
                    "using var cmd = new SqlCommand(\"SELECT COUNT(*) FROM dbo.Orders WHERE OrderId = @OrderId\", connection);\n" +
                    "cmd.Parameters.Add(\"@OrderId\", SqlDbType.Int).Value = orderId;\n" +
                    "bool found = (int)cmd.ExecuteScalar() > 0;",
                BuildPowerShell = f =>
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"SELECT COUNT(*) FROM dbo.Orders WHERE OrderId = @OrderId\", $connection\n" +
                    "[void]$cmd.Parameters.AddWithValue('@OrderId', [int]$orderId)\n" +
                    "$found = ($cmd.ExecuteScalar()) -gt 0",
                Simulate = (f, _) => Classify(f) == "normal"
                    ? new SimulationResult { Severity = Severity.Success, Headline = "Found", Detail = "Order 1007 exists, unaffected by the fix." }
                    : new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "Not found — the payload never parses as a condition",
                        Detail = "The parameter value is compared as a whole, literal OrderId. There's no way to append a second " +
                                  "condition, so there's no true/false oracle to exploit."
                    }
            }
        },

        SimulateVulnerable = f => Classify(f) switch
        {
            "exfiltrate" => new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "One character of a password hash just leaked — as a yes/no answer",
                Detail = "The app only ever says \"Found\"/\"Not found\", but that's still one bit of information. " +
                          "By asking \"is the first character of this password hash 'A'?\" over and over — a " +
                          "different guess each time — an attacker reconstructs the entire hash one character at " +
                          "a time without a single row of data ever being displayed. Tools like sqlmap automate " +
                          "exactly this.",
                AffectedAssets = new[] { "Full data exfiltration via a yes/no oracle — no visible rows needed" }
            },
            "flip" => new SimulationResult
            {
                Severity = Severity.Warning,
                Headline = "\"Not found\" — even though order 1007 really exists",
                Detail = "Forcing the WHERE clause false proves the input is reaching the SQL engine as code, not " +
                          "just data. That confirmation is the first step — next comes asking real questions about " +
                          "the data instead of just true/false."
            },
            "confirm" => new SimulationResult { Severity = Severity.Success, Headline = "Found", Detail = "A condition that's always true changes nothing visible yet — but it proves the input reached the SQL engine as code." },
            _ => new SimulationResult { Severity = Severity.Success, Headline = "Found", Detail = "Order 1007 exists." }
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
            "1007 AND SUBSTRING((SELECT TOP 1 PasswordHash FROM Users),1,1)='A'--",
            "1007 or 1=2--"
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
