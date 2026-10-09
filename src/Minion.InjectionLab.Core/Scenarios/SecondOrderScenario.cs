using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Second-order injection: the payload is stored safely, then fires later in a completely different query.</summary>
public static class SecondOrderScenario
{
    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var s = f["displayName"].ToLowerInvariant();
        if (s.Contains('\'') && (s.Contains("drop") || s.Contains("union") || s.Contains(';'))) return "injection";
        return "normal";
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
            new DecisionPathDef { Key = "injection", Label = "Payload stored for later", Icon = "⏳", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f =>
            "-- STEP 1 (now) — saving the display name: already parameterized, genuinely safe\n" +
            "UPDATE dbo.Users SET DisplayName = @DisplayName WHERE UserId = @UserId;\n\n" +
            "-- STEP 2 (later, a different feature entirely) — an admin report concatenates\n" +
            "-- the *stored* display name into a new query, trusting it as \"our own data\":\n" +
           $"SELECT * FROM dbo.AuditLog WHERE Description = 'User {f["displayName"]} logged in';",

        BuildFixedSql = f =>
            "-- STEP 1 — unchanged, already safe:\n" +
            "UPDATE dbo.Users SET DisplayName = @DisplayName WHERE UserId = @UserId;\n\n" +
            "-- STEP 2 — now ALSO parameterized (this was the actual missing fix):\n" +
            "SELECT * FROM dbo.AuditLog WHERE Description = @Description;\n" +
           $"@Description = N'User {f["displayName"]} logged in'",

        SimulateVulnerable = f => Classify(f) == "injection"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "The payload sat safely in the database until an unrelated feature trusted it",
                Detail = "The entry point (the profile form) and the injection point (the admin report) are different " +
                          "features, often owned by different people. The profile form really is safe — the bug is " +
                          "entirely in the second feature treating already-stored data as implicitly trustworthy.",
                AffectedAssets = new[] { "dbo.AuditLog — statement executes whenever an admin views recent activity" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Display name saved", Detail = "Stored safely, nothing unusual happens later either." },

        SimulateFixed = f => Classify(f) == "injection"
            ? new SimulationResult
            {
                Severity = Severity.Blocked,
                Headline = "The activity report treats the stored name as a literal value too",
                Detail = "Step 1 was never the problem. Fixing Step 2 — the query that actually concatenates — closes " +
                          "the hole regardless of what gets stored in Step 1."
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Display name saved", Detail = "Stored safely, unaffected by the fix." },

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
            "x' UNION SELECT UserName, PasswordHash, NULL FROM Users--"
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
