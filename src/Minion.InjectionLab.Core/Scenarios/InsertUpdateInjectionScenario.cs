using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Write-statement injection: every technique so far reads data it shouldn't — this one
/// changes data the attacker shouldn't be able to touch, in their own row, with their own request.</summary>
public static class InsertUpdateInjectionScenario
{
    private const string Baseline = "Loves hiking and SQL Server internals.";

    private static readonly string[] Keywords = { "ROLE" };
    private static readonly string[] ExpertKeywords = { "ISADMIN" };

    private static string Classify(IReadOnlyDictionary<string, string> f)
        => f["bio"].Contains("',") ? "escalation" : "normal";

    public static AttackScenario Create() => new()
    {
        Id = "insert-update-injection",
        Category = AttackCategory.ClassicInBand,
        Title = "INSERT/UPDATE Injection",
        Premise = "A profile page lets you update your own bio. The feature builds an UPDATE statement by " +
                  "concatenating the bio field straight in — the exact same bug as every SELECT-based scenario " +
                  "here, just in a statement that changes data instead of reading it.",
        MockAppLabel = "Profile Settings — Edit Bio",
        BaselineValues = new Dictionary<string, string> { ["bio"] = Baseline },
        Fields = new[] { new FormField { Key = "bio", Label = "Bio", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Ordinary bio update", Icon = "📝", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "escalation", Label = "Extra column assignment added", Icon = "👑", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"UPDATE dbo.Users SET Bio = '{f["bio"]}' WHERE UserId = 42;",

        BuildVulnerableCSharp = f =>
            "var sql = $\"UPDATE dbo.Users SET Bio = '{bio}' WHERE UserId = 42\";\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "cmd.ExecuteNonQuery();",

        BuildVulnerablePowerShell = f =>
            "$sql = \"UPDATE dbo.Users SET Bio = '$bio' WHERE UserId = 42\"\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql",

        // Two real fixes, not equally complete: blocking the word "Role" (looks like a fix,
        // isn't one — any other sensitive column works identically) vs. real parameterization.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block input containing \"Role\"",
                Grade = FixGrade.Partial,
                Gap = "At Beginner, checks for the literal uppercase word \"Role\" — lowercase sails through. " +
                      "Intermediate catches any casing. Expert also blocks \"IsAdmin\". But the WHERE clause stays " +
                      "intact no matter which column gets added, and this app almost certainly has other " +
                      "sensitive columns nobody thought to list — PasswordHash, IsLocked, whatever comes next.",
                BuildSql = (f, d) =>
                {
                    bool blocked = KeywordBlacklist.IsBlocked(f["bio"], d, Keywords, ExpertKeywords);
                    return blocked ? "-- Request rejected by the application; no SQL was ever built." : $"UPDATE dbo.Users SET Bio = '{f["bio"]}' WHERE UserId = 42;";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["bio"].Contains("Role");
                    var guard = "if (bio.Contains(\"Role\"))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"UPDATE dbo.Users SET Bio = '{bio}' WHERE UserId = 42\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);\n" +
                                     "cmd.ExecuteNonQuery();";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["bio"].Contains("Role");
                    var guard = "if ($bio.Contains('Role')) { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"UPDATE dbo.Users SET Bio = '$bio' WHERE UserId = 42\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = KeywordBlacklist.IsBlocked(f["bio"], d, Keywords, ExpertKeywords);
                    if (Classify(f) != "escalation")
                        return new SimulationResult { Severity = Severity.Success, Headline = "Bio updated", Detail = "Ordinary update, the filter never engages." };
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Request rejected", Detail = "At this difficulty, the filter happened to catch this specific column name." };
                    return new SimulationResult
                    {
                        Severity = Severity.Critical,
                        Headline = "Your own account was just promoted — and your bio update still worked too",
                        Detail = "The closing quote ends the Bio value early, and the extra assignment rides along in " +
                                  "the exact same UPDATE statement. The WHERE clause never changed, so this only " +
                                  "touches the attacker's own row — which is exactly the point: they just " +
                                  "self-promoted using a feature that was only ever supposed to change a bio.",
                        AffectedAssets = new[] { "The requesting user's own account escalated to a privileged role" }
                    };
                }
            },
            new FixOption
            {
                Label = "✓ Parameterized query",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                    "EXEC sp_executesql N'UPDATE dbo.Users SET Bio = @Bio WHERE UserId = 42', N'@Bio NVARCHAR(400)', @Bio;\n\n" +
                    $"@Bio = {f["bio"]}",
                BuildCSharp = f =>
                    "using var cmd = new SqlCommand(\"UPDATE dbo.Users SET Bio = @Bio WHERE UserId = 42\", connection);\n" +
                    "cmd.Parameters.AddWithValue(\"@Bio\", bio);\n" +
                    "cmd.ExecuteNonQuery();",
                BuildPowerShell = f =>
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"UPDATE dbo.Users SET Bio = @Bio WHERE UserId = 42\", $connection\n" +
                    "[void]$cmd.Parameters.AddWithValue('@Bio', $bio)\n" +
                    "$cmd.ExecuteNonQuery()",
                Simulate = (f, _) => Classify(f) == "escalation"
                    ? new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "Bio updated to the full, literal text you typed",
                        Detail = "The quote-comma sequence is just characters inside the Bio parameter value now — " +
                                  "there's no SQL text left for it to break out into, so only the Bio column changes, " +
                                  "exactly as the feature was meant to work."
                    }
                    : new SimulationResult { Severity = Severity.Success, Headline = "Bio updated", Detail = "Ordinary update, unaffected by the fix." }
            }
        },

        SimulateVulnerable = f => Classify(f) == "escalation"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Your own account was just promoted — and your bio update still worked too",
                Detail = "Closing the Bio string early and adding a second column assignment extends the exact same " +
                          "UPDATE statement — it's not a new statement, just a wider one. The WHERE clause is " +
                          "untouched, so this reliably targets only the attacker's own row with a single request.",
                AffectedAssets = new[] { "The requesting user's own account escalated to a privileged role" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Bio updated", Detail = "Ordinary update, nothing unusual happens." },

        HowItWorks =
            "Everything that makes SELECT-based injection dangerous applies identically to INSERT, UPDATE, and " +
            "DELETE statements built the same unsafe way — closing a quoted value early lets the attacker add " +
            "whatever comes next as real SQL, including entirely new column assignments in the same statement. " +
            "Because the WHERE clause is usually untouched, this often flies under the radar as \"just my own " +
            "profile update,\" while quietly also granting the attacker a privilege they were never supposed to " +
            "have.",

        WhyTheFixWorks =
            "Parameterizing the Bio value means it can only ever be compared or assigned as a single piece of " +
            "data — a quote and a comma inside it are just two characters, not a way to add a second column " +
            "assignment to the statement.",

        SamplePayloads = new[]
        {
            "Just here for the snacks', Role = 'Administrator",
            "Nothing much', IsAdmin = 1"
        },

        ChallengeGoal = "Get your own bio update to also grant your account a privileged role.",
        Hints = new[]
        {
            "This isn't a SELECT — think about what else lives in the same statement as the Bio column.",
            "Closing the Bio value's quote early lets you add a second, completely different column assignment."
        },
        ChallengeAnswer = "Just here for the snacks', Role = 'Administrator",

        TerminologyNote = "Named for where the injection lands: a write statement (INSERT, UPDATE, or DELETE) " +
                           "rather than a SELECT. The mechanism is identical to any other string-concatenation " +
                           "bug — what changes is the consequence, since a write statement can alter data (and " +
                           "privileges) directly instead of only reading it.",
        References = new[]
        {
            new ExternalReference { Label = "OWASP — SQL Injection Prevention Cheat Sheet", Url = "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet" },
            new ExternalReference { Label = "PortSwigger Web Security Academy — SQL injection", Url = "https://portswigger.net/web-security/sql-injection" }
        }
    };
}
