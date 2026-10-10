using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Second-order injection: the payload is stored safely, then fires later in a completely different query.</summary>
public static class SecondOrderScenario
{
    /// <summary>Just Step 2 — the query that actually concatenates the stored value — for syntax checking.</summary>
    private static string Step2Sql(IReadOnlyDictionary<string, string> f) =>
        $"SELECT * FROM dbo.AuditLog WHERE Description = 'User {f["displayName"]} logged in';";

    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var s = f["displayName"].ToLowerInvariant();
        if (!s.Contains('\'')) return "normal";

        // Real SQL Server parsing (ScriptDom) of Step 2, rather than guessing from "does it end
        // with --" whether the stored value would neutralize the rest of that later query.
        return SqlSyntaxChecker.HasSyntaxError(Step2Sql(f)) ? "malformed" : "injection";
    }

    public static AttackScenario Create() => new()
    {
        Id = "second-order",
        Category = AttackCategory.DeliveryObfuscation,
        Title = "Second-Order Injection",
        Premise = "Step 1: a profile page lets you set your display name — fully parameterized, genuinely safe. " +
                  "Step 2, much later: an unrelated admin \"Recent Activity\" report concatenates that *already " +
                  "stored* name into a brand new query, trusting it because \"it's already in our own database.\"",
        MockAppLabel = "Profile Settings → (later) Admin Activity Report",
        Fields = new[] { new FormField { Key = "displayName", Label = "Display name", DefaultValue = "" } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Ordinary name", Icon = "🙂", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "malformed", Label = "Broken syntax", Icon = "⚠", Kind = PathKind.Neutral },
            new DecisionPathDef { Key = "injection", Label = "Payload stored for later", Icon = "⏳", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f =>
            "-- STEP 1 (now) — saving the display name: already parameterized, genuinely safe\n" +
            "UPDATE dbo.Users SET DisplayName = @DisplayName WHERE UserId = @UserId;\n\n" +
            "-- STEP 2 (later, a different feature entirely) — an admin report concatenates\n" +
            "-- the *stored* display name into a new query, trusting it as \"our own data\":\n" +
           $"SELECT * FROM dbo.AuditLog WHERE Description = 'User {f["displayName"]} logged in';",

        // Two real fixes people actually ship, not equally complete: a keyword blacklist on Step 2
        // (looks like a fix, isn't one) vs. actually parameterizing Step 2.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block names containing \"DROP\"/\"UNION\"",
                Grade = FixGrade.Partial,
                Gap = "Checks for the literal uppercase words \"DROP\"/\"UNION\" when the report runs — lowercase " +
                      "sails straight through, and this does nothing for any technique that doesn't need those " +
                      "specific words (e.g. reading data some other way).",
                BuildSql = f =>
                {
                    var s = f["displayName"];
                    bool blocked = s.Contains("DROP") || s.Contains("UNION");
                    var guard = "if (storedName.Contains(\"DROP\") || storedName.Contains(\"UNION\"))\n    skip();\n\n";
                    return blocked ? guard.TrimEnd() : guard + Step2Sql(f);
                },
                Simulate = f =>
                {
                    var s = f["displayName"];
                    bool filterCaughtIt = s.Contains("DROP") || s.Contains("UNION");
                    if (Classify(f) == "injection" && !filterCaughtIt)
                        return new SimulationResult
                        {
                            Severity = Severity.Critical,
                            Headline = "The payload still executes when the report runs — the filter never saw it",
                            Detail = "The blacklist only checks for exact uppercase words. Different casing — or a " +
                                      "payload phrased without needing those words at all — walks straight past it.",
                            AffectedAssets = new[] { "dbo.AuditLog — statement executes whenever an admin views recent activity" }
                        };
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Report skips this entry — contains a blocked word", Detail = "This specific payload happened to use an exact uppercase word the filter checks for." };
                    return new SimulationResult { Severity = Severity.Success, Headline = "Display name saved", Detail = "Stored safely, the filter never engages later either." };
                }
            },
            new FixOption
            {
                Label = "✓ Parameterize Step 2 too",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = f =>
                    "-- STEP 1 — unchanged, already safe:\n" +
                    "UPDATE dbo.Users SET DisplayName = @DisplayName WHERE UserId = @UserId;\n\n" +
                    "-- STEP 2 — now ALSO parameterized (this was the actual missing fix):\n" +
                    "SELECT * FROM dbo.AuditLog WHERE Description = @Description;\n" +
                   $"@Description = N'User {f["displayName"]} logged in'",
                Simulate = f => Classify(f) switch
                {
                    "injection" or "malformed" => new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "The activity report treats the stored name as a literal value too",
                        Detail = "Step 1 was never the problem. Fixing Step 2 — the query that actually concatenates — closes " +
                                  "the hole regardless of what gets stored in Step 1."
                    },
                    _ => new SimulationResult { Severity = Severity.Success, Headline = "Display name saved", Detail = "Stored safely, unaffected by the fix." }
                }
            }
        },

        SimulateVulnerable = f => Classify(f) switch
        {
            "injection" => new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "The payload sat safely in the database until an unrelated feature trusted it",
                Detail = "The entry point (the profile form) and the injection point (the admin report) are different " +
                          "features, often owned by different people. The profile form really is safe — the bug is " +
                          "entirely in the second feature treating already-stored data as implicitly trustworthy.",
                AffectedAssets = new[] { "dbo.AuditLog — statement executes whenever an admin views recent activity" }
            },
            "malformed" => new SimulationResult
            {
                Severity = Severity.Warning,
                Headline = "The activity report throws a syntax error when an admin views it",
                Detail = "The report's own template still has \" logged in'\" right after your stored name, and " +
                          "nothing commented it out. It saved fine in Step 1 — the error only shows up later, in " +
                          "Step 2, which makes this class of bug annoying to track down."
            },
            _ => new SimulationResult { Severity = Severity.Success, Headline = "Display name saved", Detail = "Stored safely, nothing unusual happens later either." }
        },


        HowItWorks =
            "Second-order injection splits the attack across two steps: the data is stored safely (often through a " +
            "properly parameterized form, which is why code review of \"the risky input\" finds nothing), and the " +
            "actual injection fires later, somewhere else, the moment a different query treats that stored value as " +
            "trusted and concatenates it. 'It's already in our database' is not a trust boundary.",

        WhyTheFixWorks =
            "Every query needs its own protection. Parameterizing Step 1 does nothing for Step 2 — they're separate " +
            "code, often in separate features — so Step 2 has to be fixed independently, the same as any other query.",

        SamplePayloads = new[]
        {
            "Robert'); DROP TABLE AuditLog;--",
            "x' UNION SELECT UserName, PasswordHash, NULL FROM Users--",
            "Robert'); drop table AuditLog;--"
        },

        ChallengeGoal = "Get a value stored as your display name to execute as SQL later, in a feature that never directly touched your input.",
        Hints = new[]
        {
            "The profile form itself is already safe — don't look for the bug there.",
            "Think about what happens to this value the next time some other feature reads it back out of the database."
        },
        ChallengeAnswer = "Robert'); DROP TABLE AuditLog;--"
    };
}
