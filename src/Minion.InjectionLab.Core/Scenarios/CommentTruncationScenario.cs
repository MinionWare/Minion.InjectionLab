using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Comment truncation: you don't need a clever always-true condition — just a valid
/// username and a comment marker that erases everything the app expected to check afterward.</summary>
public static class CommentTruncationScenario
{
    private const string BaselineUsername = "alice";
    private const string BaselinePassword = "hunter2";

    private static readonly string[] Keywords = { "--" };
    private static readonly string[] ExpertKeywords = { "/*" };

    private static bool ContainsAny(string s, params string[] needles) => needles.Any(s.Contains);

    private static string Classify(IReadOnlyDictionary<string, string> f)
        => ContainsAny(f["username"], "--", "/*") ? "truncation" : "normal";

    public static AttackScenario Create() => new()
    {
        Id = "comment-truncation",
        Category = AttackCategory.ClassicInBand,
        Title = "Comment Truncation",
        Premise = "A login form checks a username and password against the Users table — the same shape as the " +
                  "tautology scenario, but this time the attacker already knows a valid username and doesn't need " +
                  "any clever always-true condition at all.",
        MockAppLabel = "Customer Portal — Sign In",
        BaselineValues = new Dictionary<string, string> { ["username"] = BaselineUsername, ["password"] = BaselinePassword },
        Fields = new[]
        {
            new FormField { Key = "username", Label = "Username", DefaultValue = BaselineUsername },
            new FormField { Key = "password", Label = "Password", DefaultValue = BaselinePassword }
        },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Normal login", Icon = "🙂", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "truncation", Label = "Password check erased", Icon = "✂", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT * FROM dbo.Users WHERE Username = '{f["username"]}' AND Password = '{f["password"]}';",

        BuildVulnerableCSharp = f =>
            "var sql = $\"SELECT * FROM dbo.Users WHERE Username = '{username}' AND Password = '{password}'\";\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "using var reader = cmd.ExecuteReader();",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT * FROM dbo.Users WHERE Username = '$username' AND Password = '$password'\"\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql",

        // Two real fixes, not equally complete: blocking "--" (looks like a fix, isn't one —
        // SQL Server accepts a second comment style) vs. real parameterization.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block input containing \"--\"",
                Grade = FixGrade.Partial,
                Gap = "At Beginner, checks for the literal two-dash comment marker — any other way to start a " +
                      "comment sails through. Intermediate makes the check case-irrelevant (dashes don't have a " +
                      "case, so this barely changes anything). Expert also blocks \"/*\" — but by then the lesson " +
                      "is already made: a blacklist of comment styles is still a blacklist.",
                BuildSql = (f, d) =>
                {
                    bool blocked = KeywordBlacklist.IsBlocked(f["username"], d, Keywords, ExpertKeywords);
                    return blocked ? "-- Request rejected by the application; no SQL was ever built." : $"SELECT * FROM dbo.Users WHERE Username = '{f["username"]}' AND Password = '{f["password"]}';";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["username"].Contains("--");
                    var guard = "if (username.Contains(\"--\"))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"SELECT * FROM dbo.Users WHERE Username = '{username}' AND Password = '{password}'\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["username"].Contains("--");
                    var guard = "if ($username.Contains('--')) { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"SELECT * FROM dbo.Users WHERE Username = '$username' AND Password = '$password'\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = KeywordBlacklist.IsBlocked(f["username"], d, Keywords, ExpertKeywords);
                    if (Classify(f) != "truncation")
                        return new SimulationResult { Severity = Severity.Success, Headline = "Login failed", Detail = "Ordinary attempt, the filter never engages." };
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Login failed", Detail = "At this difficulty, the filter happened to catch this comment style." };
                    return new SimulationResult
                    {
                        Severity = Severity.Critical,
                        Headline = "Logged in as alice — the password was never checked at all",
                        Detail = "Everything after the comment marker, including the entire \"AND Password = '...'\" " +
                                  "clause, is erased from the query before SQL Server even parses it. The password " +
                                  "field's value is completely irrelevant — any text at all would have worked.",
                        AffectedAssets = new[] { "Authentication bypassed for any known username" }
                    };
                }
            },
            new FixOption
            {
                Label = "✓ Parameterized query",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                    "EXEC sp_executesql N'SELECT * FROM dbo.Users WHERE Username = @Username AND Password = @Password', " +
                    "N'@Username NVARCHAR(50), @Password NVARCHAR(50)', @Username, @Password;\n\n" +
                    $"@Username = {f["username"]}\n@Password = {f["password"]}",
                BuildCSharp = f =>
                    "using var cmd = new SqlCommand(\"SELECT * FROM dbo.Users WHERE Username = @Username AND Password = @Password\", connection);\n" +
                    "cmd.Parameters.AddWithValue(\"@Username\", username);\n" +
                    "cmd.Parameters.AddWithValue(\"@Password\", password);\n" +
                    "using var reader = cmd.ExecuteReader();",
                BuildPowerShell = f =>
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"SELECT * FROM dbo.Users WHERE Username = @Username AND Password = @Password\", $connection\n" +
                    "[void]$cmd.Parameters.AddWithValue('@Username', $username)\n" +
                    "[void]$cmd.Parameters.AddWithValue('@Password', $password)\n" +
                    "$reader = $cmd.ExecuteReader()",
                Simulate = (f, _) => Classify(f) == "truncation"
                    ? new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "Login failed",
                        Detail = "The comment marker is just two literal dash characters inside the Username parameter " +
                                  "value now — there's no SQL text left for it to comment out, so the password clause " +
                                  "still runs exactly as written."
                    }
                    : new SimulationResult { Severity = Severity.Success, Headline = "Login succeeded", Detail = "Ordinary login, unaffected by the fix." }
            }
        },

        SimulateVulnerable = f => Classify(f) == "truncation"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Logged in as alice — the password was never checked at all",
                Detail = "The comment marker ends the SQL statement's meaningful text right there. Everything the " +
                          "developer wrote after it — the entire password check — becomes a comment, inert text SQL " +
                          "Server never evaluates. No always-true trick needed: just one real username, and the rest " +
                          "of the query simply isn't there anymore.",
                AffectedAssets = new[] { "Authentication bypassed for any known username" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Login failed", Detail = "Ordinary attempt, nothing unusual happens." },

        HowItWorks =
            "SQL Server treats -- (to the end of the line) and /* ... */ as comments, exactly like most " +
            "programming languages. When user input is concatenated directly into a query, a comment marker " +
            "doesn't just add a condition — it erases everything the developer wrote after it, as far as the SQL " +
            "engine is concerned. A tautology (\"OR 1=1\") makes a check pass anyway; truncation skips the check " +
            "entirely.",

        WhyTheFixWorks =
            "Once the username is bound as a parameter value rather than concatenated as SQL text, the two dash " +
            "characters are just two ordinary characters being compared — there's no SQL text surrounding them " +
            "left to comment out, so the password clause stays fully intact and still has to match.",

        SamplePayloads = new[]
        {
            "alice'--",
            "alice'/*",
            "alice' -- trailing note"
        },

        ChallengeGoal = "Log in as alice without ever providing her real password.",
        Hints = new[]
        {
            "You don't need an always-true condition this time — you already know a real username.",
            "What ends a SQL statement's meaningful text early, the same way // or # might in other languages?"
        },
        ChallengeAnswer = "alice'--",

        TerminologyNote = "Named for the mechanism, not a logic trick: a SQL comment marker truncates — cuts off " +
                           "— everything the developer wrote after it, as far as the engine is concerned. It's " +
                           "often confused with tautology-based bypasses because both commonly target logins, but " +
                           "the two work completely differently: one makes a check pass, the other erases the " +
                           "check.",
        References = new[]
        {
            new ExternalReference { Label = "PortSwigger Web Security Academy — SQL injection", Url = "https://portswigger.net/web-security/sql-injection" },
            new ExternalReference { Label = "OWASP — SQL Injection Prevention Cheat Sheet", Url = "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet" }
        }
    };
}
