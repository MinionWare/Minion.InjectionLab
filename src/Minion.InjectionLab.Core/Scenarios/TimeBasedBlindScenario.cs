using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Time-based blind injection: when there's no visible difference at all, a delay becomes the signal.</summary>
public static class TimeBasedBlindScenario
{
    private const string Baseline = "1007";

    private static readonly string[] Keywords = { "WAITFOR" };
    private static readonly string[] ExpertKeywords = { "DELAY" };

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

        BuildVulnerableCSharp = f =>
            "var sql = $\"SELECT 1 FROM dbo.Orders WHERE OrderId = {orderId}\";\n" +
            "var sw = Stopwatch.StartNew();\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "cmd.ExecuteScalar();\n" +
            "var elapsed = sw.Elapsed; // a 5-second jump here is the whole attack",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT 1 FROM dbo.Orders WHERE OrderId = $orderId\"\n" +
            "$sw = [System.Diagnostics.Stopwatch]::StartNew()\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql\n" +
            "$sw.Stop()",

        // Two real fixes, not equally complete: a keyword blacklist (looks like a fix, isn't one)
        // vs. real parameterization.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block input containing \"WAITFOR\"",
                Grade = FixGrade.Partial,
                Gap = "At Beginner, checks for the literal uppercase word \"WAITFOR\" — lowercase \"waitfor\" sails " +
                      "through. Intermediate catches any casing. Expert also blocks \"DELAY\". But a measurable delay " +
                      "doesn't require either word — a deliberately expensive query (a heavy join or recursive CTE " +
                      "gated by a condition) creates the exact same timing side-channel with no blocked keyword at all.",
                BuildSql = (f, d) =>
                {
                    bool blocked = KeywordBlacklist.IsBlocked(f["orderId"], d, Keywords, ExpertKeywords);
                    var guard = "if (LooksLikeInjection(orderId))\n    reject();\n\n";
                    return blocked ? guard.TrimEnd() : guard + $"SELECT 1 FROM dbo.Orders WHERE OrderId = {f["orderId"]};";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["orderId"].Contains("WAITFOR");
                    var guard = "if (orderId.Contains(\"WAITFOR\"))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"SELECT 1 FROM dbo.Orders WHERE OrderId = {orderId}\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);\n" +
                                     "cmd.ExecuteScalar();";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["orderId"].Contains("WAITFOR");
                    var guard = "if ($orderId.Contains(\"WAITFOR\")) { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"SELECT 1 FROM dbo.Orders WHERE OrderId = $orderId\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = KeywordBlacklist.IsBlocked(f["orderId"], d, Keywords, ExpertKeywords);
                    if (Classify(f) != "injection")
                        return new SimulationResult { Severity = Severity.Success, Headline = "Confirmed", Detail = "Ordinary, instant response, the filter never engages." };
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Confirmed — instantly, no delay", Detail = "At this difficulty, the filter happened to catch this specific phrasing." };
                    return new SimulationResult
                    {
                        Severity = Severity.Critical,
                        Headline = "The response would still pause for 5 full seconds — the filter never saw it",
                        Detail = "This phrasing used a casing the filter at this difficulty doesn't check for, so the " +
                                  "timing oracle works exactly as if there were no filter at all.",
                        AffectedAssets = new[] { "A measurable timing oracle — works even with zero visible output difference" }
                    };
                }
            },
            new FixOption
            {
                Label = "✓ Parameterized query",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                    "EXEC sp_executesql N'SELECT 1 FROM dbo.Orders WHERE OrderId = @OrderId', N'@OrderId INT', @OrderId;\n\n" +
                    $"@OrderId = {f["orderId"]}",
                BuildCSharp = f =>
                    "using var cmd = new SqlCommand(\"SELECT 1 FROM dbo.Orders WHERE OrderId = @OrderId\", connection);\n" +
                    "cmd.Parameters.Add(\"@OrderId\", SqlDbType.Int).Value = orderId;\n" +
                    "cmd.ExecuteScalar();",
                BuildPowerShell = f =>
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"SELECT 1 FROM dbo.Orders WHERE OrderId = @OrderId\", $connection\n" +
                    "[void]$cmd.Parameters.AddWithValue('@OrderId', [int]$orderId)\n" +
                    "$cmd.ExecuteScalar()",
                Simulate = (f, _) => new SimulationResult
                {
                    Severity = Classify(f) == "injection" ? Severity.Blocked : Severity.Success,
                    Headline = Classify(f) == "injection" ? "Confirmed — instantly, no delay" : "Confirmed",
                    Detail = Classify(f) == "injection"
                        ? "WAITFOR is just text inside the parameter value now — there's no SQL left to parse it as a command, " +
                          "so the response time never changes."
                        : "Ordinary, instant response, unaffected by the fix."
                }
            }
        },

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
            "1007 IF (1=1) WAITFOR DELAY '0:0:5'--",
            "1007; waitfor delay '0:0:5'--"
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
