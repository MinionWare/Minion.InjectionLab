using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Error-based blind injection: the content never changes, but whether the page errors
/// out at all is its own true/false channel — a generic "Something went wrong" is still a signal.</summary>
public static class ErrorBasedBlindScenario
{
    private const string Baseline = "1007";

    private static readonly string[] Keywords = { "1/0" };
    private static readonly string[] ExpertKeywords = { "CONVERT" };

    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var s = f["orderId"].ToLowerInvariant().Replace(" ", "");
        if (!s.Contains("casewhen")) return "normal";
        if (s.Contains("(1=1)then1/0")) return "error";
        if (s.Contains("(1=2)then1/0")) return "no-error";
        return "normal";
    }

    public static AttackScenario Create() => new()
    {
        Id = "error-based-blind",
        Category = AttackCategory.BlindInferential,
        Title = "Error-Based Blind Injection",
        Premise = "An order-status page shows the exact same confirmation text no matter what — no data, no " +
                  "true/false difference, nothing. But like most apps, an unhandled database exception still " +
                  "surfaces as a generic \"Something went wrong\" error page instead of a silent failure.",
        MockAppLabel = "Support Chat — Order Status",
        BaselineValues = new Dictionary<string, string> { ["orderId"] = Baseline },
        Fields = new[] { new FormField { Key = "orderId", Label = "Order ID", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Normal check", Icon = "📦", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "no-error", Label = "Condition false — no error", Icon = "✅", Kind = PathKind.Neutral },
            new DecisionPathDef { Key = "error", Label = "Condition true — forced error", Icon = "💥", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT 1 FROM dbo.Orders WHERE OrderId = {f["orderId"]};",

        BuildVulnerableCSharp = f =>
            "var sql = $\"SELECT 1 FROM dbo.Orders WHERE OrderId = {orderId}\";\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "try { cmd.ExecuteScalar(); return Ok(\"Confirmed\"); }\n" +
            "catch (SqlException) { return StatusCode(500, \"Something went wrong\"); } // presence of THIS response is the oracle",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT 1 FROM dbo.Orders WHERE OrderId = $orderId\"\n" +
            "try { Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql; Write-Output \"Confirmed\" }\n" +
            "catch { Write-Output \"Something went wrong\" }",

        // Two real fixes, not equally complete: blocking the literal "1/0" (looks like a fix,
        // isn't one — CONVERT/CAST force the identical kind of error) vs. real parameterization.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block input containing \"1/0\"",
                Grade = FixGrade.Partial,
                Gap = "At Beginner, checks for the literal text \"1/0\" — spacing it out (\"1 / 0\") already sails " +
                      "through. Intermediate and Expert don't help much here either: Expert also blocks " +
                      "\"CONVERT\", but any other expression that can fail only sometimes (a CAST, a divide by a " +
                      "computed zero, a deliberately bad subquery) recreates the identical oracle.",
                BuildSql = (f, d) =>
                {
                    bool blocked = KeywordBlacklist.IsBlocked(f["orderId"], d, Keywords, ExpertKeywords);
                    return blocked ? "-- Request rejected by the application; no SQL was ever built." : $"SELECT 1 FROM dbo.Orders WHERE OrderId = {f["orderId"]};";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["orderId"].Contains("1/0");
                    var guard = "if (orderId.Contains(\"1/0\"))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"SELECT 1 FROM dbo.Orders WHERE OrderId = {orderId}\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);\n" +
                                     "cmd.ExecuteScalar();";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["orderId"].Contains("1/0");
                    var guard = "if ($orderId.Contains('1/0')) { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"SELECT 1 FROM dbo.Orders WHERE OrderId = $orderId\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = KeywordBlacklist.IsBlocked(f["orderId"], d, Keywords, ExpertKeywords);
                    var classification = Classify(f);
                    if (classification == "normal")
                        return new SimulationResult { Severity = Severity.Success, Headline = "Confirmed", Detail = "Ordinary check, the filter never engages." };
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Confirmed — the filter caught this phrasing", Detail = "At this difficulty, the request never reached SQL Server." };
                    return classification == "error"
                        ? new SimulationResult
                        {
                            Severity = Severity.Critical,
                            Headline = "\"Something went wrong\" — and the filter never saw it coming",
                            Detail = "The condition evaluated true, the CASE expression's divide-by-zero branch fired, " +
                                      "and the generic error page appeared. That single bit — error or no error — is " +
                                      "exactly as exploitable as boolean-blind's Found/Not found, one character at a " +
                                      "time.",
                            AffectedAssets = new[] { "A one-bit error/no-error oracle — works even with zero visible output difference" }
                        }
                        : new SimulationResult { Severity = Severity.Success, Headline = "Confirmed", Detail = "The condition evaluated false, so the divide-by-zero branch never fired — no error, no filter engagement." };
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
                    Severity = Classify(f) != "normal" ? Severity.Blocked : Severity.Success,
                    Headline = "Confirmed",
                    Detail = Classify(f) != "normal"
                        ? "The CASE expression is just text inside the parameter value now — there's no SQL left to " +
                          "evaluate it as a condition, so it never fires, true or false."
                        : "Ordinary, unaffected by the fix."
                }
            }
        },

        SimulateVulnerable = f => Classify(f) switch
        {
            "error" => new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "\"Something went wrong\" — a generic error page, and nothing else",
                Detail = "No data, no visible text difference — but the embedded condition evaluated true, the " +
                          "CASE expression's divide-by-zero branch fired, and the application's generic error " +
                          "handler kicked in. That's still a yes/no answer: ask the same kind of character-by-" +
                          "character questions as boolean-blind injection, just reading error-vs-no-error instead " +
                          "of Found-vs-Not-found.",
                AffectedAssets = new[] { "A one-bit error/no-error oracle — works even with zero visible output difference" }
            },
            "no-error" => new SimulationResult { Severity = Severity.Success, Headline = "Confirmed", Detail = "The embedded condition evaluated false, so the divide-by-zero branch never fired — a normal response either way." },
            _ => new SimulationResult { Severity = Severity.Success, Headline = "Confirmed", Detail = "Ordinary, boring lookup. Nothing to report yet." }
        },

        HowItWorks =
            "A CASE expression can be built so one branch divides by zero and the other doesn't — SQL Server " +
            "only evaluates the branch the condition selects, so a divide-by-zero error fires if and only if the " +
            "embedded condition is true. Even an app that shows absolutely nothing useful in its normal response " +
            "usually still surfaces an unhandled database exception as some kind of generic error page — and " +
            "\"did an error happen\" is exactly as good a yes/no oracle as any visible text difference.",

        WhyTheFixWorks =
            "Same mechanism as every other fix here: once the value is bound as data, the CASE expression never " +
            "gets parsed as a condition at all, so neither branch of it — error-causing or not — ever executes.",

        SamplePayloads = new[]
        {
            "1007 AND 1=(SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)--",
            "1007 AND 1=(SELECT CASE WHEN (1=2) THEN 1/0 ELSE 1 END)--",
            "1007 AND 1=(SELECT CASE WHEN (1 = 1) THEN 1 / 0 ELSE 1 END)--"
        },

        ChallengeGoal = "Make the order check throw a visible \"Something went wrong\" error, using a condition that's true — with no other observable change.",
        Hints = new[]
        {
            "If there's nothing to read and no delay to measure, what OTHER application behavior might still differ based on a condition?",
            "A CASE expression only evaluates the branch it selects — what happens if only one branch is valid SQL?"
        },
        ChallengeAnswer = "1007 AND 1=(SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)--",

        TerminologyNote = "Still \"blind\" — no data or content difference is ever visible — but the oracle here " +
                           "is \"error-based\": the signal is whether the request errors out at all, forced via a " +
                           "conditional divide-by-zero, rather than a visible true/false difference (boolean-blind) " +
                           "or a measurable delay (time-based blind).",
        References = new[]
        {
            new ExternalReference { Label = "PortSwigger Web Security Academy — Blind SQL injection (conditional errors)", Url = "https://portswigger.net/web-security/sql-injection/blind" },
            new ExternalReference { Label = "OWASP — Blind SQL Injection", Url = "https://owasp.org/www-community/attacks/Blind_SQL_Injection" }
        }
    };
}
