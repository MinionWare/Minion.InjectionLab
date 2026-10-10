using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Truncation attack: the app pre-truncates input to avoid a database error, and that
/// defensive truncation — plus a trailing-space quirk in string comparison — is the whole bug.</summary>
public static class TruncationAttackScenario
{
    private const int ColumnLength = 20;
    private const string Baseline = "newbie2026";

    /// <summary>What actually gets stored: the registration page pre-truncates to the column
    /// length (to dodge SQL Server's own "String or binary data would be truncated" error) before
    /// anything else happens — this mirrors the real bug, which lives in the app, not the engine.</summary>
    private static string Truncate(string s) => s.Length > ColumnLength ? s[..ColumnLength] : s;

    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var stored = Truncate(f["username"]);
        // SQL Server's = comparison ignores trailing spaces — "admin" and "admin               " compare equal.
        return stored.TrimEnd() == "admin" && stored != "admin" ? "collision" : "normal";
    }

    public static AttackScenario Create() => new()
    {
        Id = "truncation-attack",
        Category = AttackCategory.DeliveryObfuscation,
        Title = "Truncation Attack",
        Premise = $"A registration page checks a new username against the Users table before inserting it — " +
                  $"the Username column is VARCHAR({ColumnLength}). Inserting anything longer would raise SQL " +
                  "Server's own \"String or binary data would be truncated\" error, so the app defensively " +
                  $"pre-truncates every username to {ColumnLength} characters in code before it ever reaches a query.",
        MockAppLabel = "Create Account",
        BaselineValues = new Dictionary<string, string> { ["username"] = Baseline },
        Fields = new[] { new FormField { Key = "username", Label = "Choose a username", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Unique username", Icon = "🙂", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "collision", Label = "Truncates to an existing account", Icon = "👥", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f =>
        {
            var stored = Truncate(f["username"]);
            return $"-- Application code truncated '{f["username"]}' to {ColumnLength} chars before this ever ran: '{stored}'\n" +
                   $"IF NOT EXISTS (SELECT 1 FROM dbo.Users WHERE Username = '{stored}')\n" +
                   $"    INSERT INTO dbo.Users (Username) VALUES ('{stored}');";
        },

        BuildVulnerableCSharp = f =>
           $"var stored = username.Length > {ColumnLength} ? username.Substring(0, {ColumnLength}) : username; // avoids a truncation error\n" +
            "using var check = new SqlCommand($\"SELECT 1 FROM dbo.Users WHERE Username = '{stored}'\", connection);\n" +
            "if (check.ExecuteScalar() == null)\n" +
            "{\n" +
            "    using var insert = new SqlCommand($\"INSERT INTO dbo.Users (Username) VALUES ('{stored}')\", connection);\n" +
            "    insert.ExecuteNonQuery();\n" +
            "}",

        BuildVulnerablePowerShell = f =>
           $"$stored = if ($username.Length -gt {ColumnLength}) {{ $username.Substring(0, {ColumnLength}) }} else {{ $username }}\n" +
            "$exists = Invoke-Sqlcmd -ServerInstance $server -Database $db -Query \"SELECT 1 FROM dbo.Users WHERE Username = '$stored'\"\n" +
            "if (-not $exists) {\n" +
            "    Invoke-Sqlcmd -ServerInstance $server -Database $db -Query \"INSERT INTO dbo.Users (Username) VALUES ('$stored')\"\n" +
            "}",

        // Two real fixes, not equally complete: trimming trailing whitespace before the length
        // check (looks like a fix, isn't one — padding with ANY filler character still collides)
        // vs. rejecting oversized input outright instead of silently truncating it.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Trim trailing spaces before truncating",
                Grade = FixGrade.Partial,
                Gap = "Stops padding with literal space characters specifically — but SQL Server's trailing-space " +
                      "rule is the only part of this bug that cares about spaces. Padding with any other filler " +
                      "that happens to get truncated away (or simply choosing a 21st character the real account " +
                      "never has) can still produce the exact same stored value as an existing username, " +
                      "independent of this one specific fix.",
                BuildSql = (f, _) =>
                {
                    var trimmedInput = f["username"].TrimEnd();
                    var stored = Truncate(trimmedInput);
                    return $"-- Trailing spaces trimmed first, then truncated to {ColumnLength} chars: '{stored}'\n" +
                           $"IF NOT EXISTS (SELECT 1 FROM dbo.Users WHERE Username = '{stored}')\n" +
                           $"    INSERT INTO dbo.Users (Username) VALUES ('{stored}');";
                },
                BuildCSharp = f =>
                   $"var trimmed = username.TrimEnd();\n" +
                   $"var stored = trimmed.Length > {ColumnLength} ? trimmed.Substring(0, {ColumnLength}) : trimmed;\n" +
                    "using var check = new SqlCommand($\"SELECT 1 FROM dbo.Users WHERE Username = '{stored}'\", connection);\n" +
                    "// ... same INSERT as before, using the trimmed-then-truncated value",
                BuildPowerShell = f =>
                   $"$trimmed = $username.TrimEnd()\n" +
                   $"$stored = if ($trimmed.Length -gt {ColumnLength}) {{ $trimmed.Substring(0, {ColumnLength}) }} else {{ $trimmed }}\n" +
                    "# ... same check/INSERT as before, using the trimmed-then-truncated value",
                Simulate = (f, _) =>
                {
                    var trimmedInput = f["username"].TrimEnd();
                    var collidesAfterTrim = Truncate(trimmedInput).TrimEnd() == "admin" && Truncate(trimmedInput) != "admin";
                    var collidesWithoutTrim = Classify(f) == "collision";
                    if (!collidesWithoutTrim)
                        return new SimulationResult { Severity = Severity.Success, Headline = "Account created", Detail = "A genuinely unique username, the fix never engages." };
                    if (!collidesAfterTrim)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Account created under the trimmed name", Detail = "Trailing spaces were trimmed before truncation, so this specific space-padding attempt no longer collides." };
                    return new SimulationResult
                    {
                        Severity = Severity.Critical,
                        Headline = "\"Username already exists\" never fired — a second admin account now exists",
                        Detail = "This attempt didn't rely on trailing spaces at all — truncation alone already produced " +
                                  "a value that matches the real admin account once the extra characters are cut off, " +
                                  "so trimming spaces first changes nothing about it.",
                        AffectedAssets = new[] { "A colliding account created under an existing username" }
                    };
                }
            },
            new FixOption
            {
                Label = "✓ Reject oversized input instead of truncating it",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                {
                    bool tooLong = f["username"].Length > ColumnLength;
                    return tooLong
                        ? $"-- Rejected before any SQL was built: '{f["username"]}' is {f["username"].Length} characters, over the {ColumnLength}-character limit."
                        : $"IF NOT EXISTS (SELECT 1 FROM dbo.Users WHERE Username = '{f["username"]}')\n    INSERT INTO dbo.Users (Username) VALUES ('{f["username"]}');";
                },
                BuildCSharp = f =>
                   $"if (username.Length > {ColumnLength})\n    throw new ValidationException($\"Username must be {ColumnLength} characters or fewer.\");\n\n" +
                    "using var check = new SqlCommand(\"SELECT 1 FROM dbo.Users WHERE Username = @Username\", connection);\n" +
                    "check.Parameters.AddWithValue(\"@Username\", username);\n" +
                    "// ... parameterized INSERT with the full, untruncated value",
                BuildPowerShell = f =>
                   $"if ($username.Length -gt {ColumnLength}) {{ throw \"Username must be {ColumnLength} characters or fewer.\" }}\n\n" +
                    "# ... parameterized check/INSERT with the full, untruncated value",
                Simulate = (f, _) => f["username"].Length > ColumnLength
                    ? new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "Rejected: username too long",
                        Detail = "Oversized input is refused outright instead of being silently cut down to something " +
                                  "that might collide with an existing account — there's no truncated value for the " +
                                  "trailing-space rule to ever act on."
                    }
                    : new SimulationResult { Severity = Severity.Success, Headline = "Account created", Detail = "An ordinary, already-short username, unaffected by the fix." }
            }
        },

        SimulateVulnerable = f => Classify(f) == "collision"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "\"Username already exists\" never fired — a second admin account now exists",
                Detail = $"The uniqueness check ran against the full, untruncated input — which genuinely doesn't " +
                          $"match 'admin' — so it passed. Only the INSERT truncates the value down to {ColumnLength} " +
                          "characters, and SQL Server's own trailing-space comparison rule means the truncated, " +
                          "space-padded result still reads as the same username as the real account to anything " +
                          "that later does `WHERE Username = 'admin'`.",
                AffectedAssets = new[] { "A colliding account created under an existing username" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Account created", Detail = "A genuinely unique username, nothing unusual happens." },

        HowItWorks =
            $"SQL Server itself refuses to silently truncate an oversized VARCHAR insert — it raises \"String or " +
            "binary data would be truncated\" instead. To avoid ever hitting that error, this app pre-truncates " +
            $"usernames to {ColumnLength} characters in its own code before checking uniqueness or inserting. If " +
            "the uniqueness check runs against the full input but the truncated value is what actually gets " +
            "stored, an attacker can register a username that's genuinely unique in full — but truncates down to " +
            "something that collides with a real account. SQL Server's string comparison ignores trailing spaces, " +
            "so padding the truncated result out to an existing username with spaces makes the two compare equal.",

        WhyTheFixWorks =
            "Refusing oversized input outright — rather than quietly cutting it down to fit — means there's never " +
            "a truncated, mismatched value for anything downstream to collide with. The uniqueness check and the " +
            "stored value are always the exact same string the user actually typed.",

        SamplePayloads = new[]
        {
            "admin               1",
            "admin                9"
        },

        ChallengeGoal = "Register a username that's genuinely unique in full, but collides with the existing \"admin\" account once it's stored.",
        Hints = new[]
        {
            $"The Username column only holds {ColumnLength} characters — what happens to anything longer?",
            "SQL Server's string comparisons ignore trailing spaces — pad your real username out with spaces before adding something extra at the end."
        },
        ChallengeAnswer = "admin               1",

        TerminologyNote = "Named for the mechanism, not the database: this is sometimes called a \"truncation\" " +
                           "or \"trimming\" attack in web-security literature, most commonly documented against " +
                           "databases (like MySQL in non-strict mode) that silently cut oversized input down to " +
                           "fit. SQL Server doesn't do that itself — it errors instead — but the identical bug " +
                           "reappears the moment application code truncates defensively to dodge that error.",
        References = new[]
        {
            new ExternalReference { Label = "InfoSec Institute — SQL Truncation Attack", Url = "https://resources.infosecinstitute.com/sql-truncation-attack" },
            new ExternalReference { Label = "LIMSwiki — Web Application Security Guide: Truncation attacks, trimming attacks", Url = "https://limswiki.org/index.php/LII:Web_Application_Security_Guide/Truncation_attacks,_trimming_attacks" },
            new ExternalReference { Label = "SQLServerCentral — ANSI_PADDING, Trailing Whitespace, and Variable Character Columns", Url = "https://www.sqlservercentral.com/articles/ansi-padding-trailing-whitespace-and-variable-character-columns" }
        }
    };
}
