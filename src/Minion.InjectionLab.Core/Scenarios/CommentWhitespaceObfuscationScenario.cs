using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Comment/whitespace obfuscation: a filter matching a literal phrase never notices that
/// SQL Server treats an inline comment exactly like the space it replaced.</summary>
public static class CommentWhitespaceObfuscationScenario
{
    private const string Baseline = "laptop";

    private static string Classify(IReadOnlyDictionary<string, string> f)
        => f["search"].ToLowerInvariant().Contains("union") ? "bypass" : "normal";

    /// <summary>Beginner: exact-case match on the literal phrase. Intermediate/Expert: case-
    /// insensitive. At no difficulty does this check understand that a comment is whitespace too —
    /// that's a structural gap in the filter's design, not a casing gap.</summary>
    private static bool PhraseFilterBlocks(string input, DifficultyLevel difficulty)
    {
        var comparison = difficulty == DifficultyLevel.Beginner ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
        return input.Contains("UNION SELECT", comparison);
    }

    public static AttackScenario Create() => new()
    {
        Id = "comment-whitespace-obfuscation",
        Category = AttackCategory.DeliveryObfuscation,
        Title = "Comment/Whitespace Obfuscation",
        Premise = "The same product search box as the UNION scenario — except this time a filter specifically " +
                  "rejects any request containing the literal phrase \"UNION SELECT\" (with a space), on the " +
                  "theory that blocking the exact attack phrase stops the attack.",
        MockAppLabel = "Store — Product List",
        BaselineValues = new Dictionary<string, string> { ["search"] = Baseline },
        Fields = new[] { new FormField { Key = "search", Label = "Search for a product", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Normal search", Icon = "🔍", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "bypass", Label = "Comment stands in for the space", Icon = "🧩", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT ProductName, Price FROM dbo.Products WHERE ProductName LIKE '%{f["search"]}%';",

        BuildVulnerableCSharp = f =>
            "var sql = $\"SELECT ProductName, Price FROM dbo.Products WHERE ProductName LIKE '%{search}%'\";\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "using var reader = cmd.ExecuteReader();",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT ProductName, Price FROM dbo.Products WHERE ProductName LIKE '%$search%'\"\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql",

        // Two real fixes, not equally complete: a literal-phrase filter (looks like a fix, isn't
        // one — a comment IS whitespace to the parser) vs. real parameterization.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block the literal phrase \"UNION SELECT\"",
                Grade = FixGrade.Partial,
                Gap = "Catches the exact phrase, with a space, in whatever case this difficulty checks for — but " +
                      "SQL Server treats an inline comment (/**/) as whitespace too. \"UNION/**/SELECT\" parses " +
                      "and runs identically to \"UNION SELECT\" with a real space, and it never contains the " +
                      "phrase this filter is looking for — at any difficulty, since the gap is structural, not a " +
                      "casing issue.",
                BuildSql = (f, d) =>
                {
                    bool blocked = PhraseFilterBlocks(f["search"], d);
                    return blocked ? "-- Request rejected by the application; no SQL was ever built." : $"SELECT ProductName, Price FROM dbo.Products WHERE ProductName LIKE '%{f["search"]}%';";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["search"].Contains("UNION SELECT", StringComparison.OrdinalIgnoreCase);
                    var guard = "if (search.Contains(\"UNION SELECT\", StringComparison.OrdinalIgnoreCase))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"SELECT ProductName, Price FROM dbo.Products WHERE ProductName LIKE '%{search}%'\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["search"].Contains("UNION SELECT", StringComparison.OrdinalIgnoreCase);
                    var guard = "if ($search -match '(?i)union select') { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"SELECT ProductName, Price FROM dbo.Products WHERE ProductName LIKE '%$search%'\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = PhraseFilterBlocks(f["search"], d);
                    if (Classify(f) != "bypass")
                        return new SimulationResult { Severity = Severity.Success, Headline = "Search completed", Detail = "An ordinary search, the filter never engages." };
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Request rejected — contains the blocked phrase", Detail = "This specific attempt spelled the phrase out with an ordinary space, exactly what the filter checks for." };
                    return new SimulationResult
                    {
                        Severity = Severity.Critical,
                        Headline = "Real usernames and password hashes returned — disguised as product results",
                        Detail = "SQL Server parses the comment exactly like the space it replaced, so the query runs " +
                                  "identically to a real UNION SELECT — and the filter, which only ever checks for " +
                                  "the literal phrase with a real space, never sees anything to object to.",
                        AffectedAssets = new[] { "dbo.Users — Username and PasswordHash columns exposed through the product list" }
                    };
                }
            },
            new FixOption
            {
                Label = "✓ Parameterized query",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                    "EXEC sp_executesql N'SELECT ProductName, Price FROM dbo.Products WHERE ProductName LIKE ''%'' + @Search + ''%''', " +
                    "N'@Search NVARCHAR(100)', @Search;\n\n" +
                    $"@Search = {f["search"]}",
                BuildCSharp = f =>
                    "using var cmd = new SqlCommand(\"SELECT ProductName, Price FROM dbo.Products WHERE ProductName LIKE '%' + @Search + '%'\", connection);\n" +
                    "cmd.Parameters.AddWithValue(\"@Search\", search);\n" +
                    "using var reader = cmd.ExecuteReader();",
                BuildPowerShell = f =>
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"SELECT ProductName, Price FROM dbo.Products WHERE ProductName LIKE '%' + @Search + '%'\", $connection\n" +
                    "[void]$cmd.Parameters.AddWithValue('@Search', $search)\n" +
                    "$reader = $cmd.ExecuteReader()",
                Simulate = (f, _) => Classify(f) == "bypass"
                    ? new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "No matching products found",
                        Detail = "The comment, the word UNION, all of it, is just literal text inside the @Search " +
                                  "parameter value now — there's no SQL text left for the parser to treat as " +
                                  "whitespace or a keyword, so it's compared as data, not parsed as code."
                    }
                    : new SimulationResult { Severity = Severity.Success, Headline = "Search completed", Detail = "Ordinary search, unaffected by the fix." }
            }
        },

        SimulateVulnerable = f => Classify(f) == "bypass"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Real usernames and password hashes returned — disguised as product results",
                Detail = "No filter in place at all, so this works exactly like the plain UNION scenario — the " +
                          "comment-as-whitespace trick only matters once there's a phrase filter trying (and " +
                          "failing) to stop it.",
                AffectedAssets = new[] { "dbo.Users — Username and PasswordHash columns exposed through the product list" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Search completed", Detail = "An ordinary search, nothing unusual happens." },

        HowItWorks =
            "SQL Server's parser treats an inline comment (/* ... */) exactly like whitespace — it's there to " +
            "separate tokens, nothing more. A filter built around matching a literal phrase like \"UNION SELECT\" " +
            "assumes the attacker will type it out with an ordinary space, the same way a human would read it. " +
            "Swap that space for a comment and the resulting SQL is byte-for-byte equivalent once parsed, but the " +
            "raw request text never contains the phrase the filter is looking for.",

        WhyTheFixWorks =
            "Parameterizing removes the filter's entire job: the search text is never parsed as SQL syntax at " +
            "all, so it doesn't matter whether a space, a comment, or anything else sits between the words — none " +
            "of it is ever interpreted as a keyword boundary, because none of it is SQL text to begin with.",

        SamplePayloads = new[]
        {
            "nonexistent'/**/UNION/**/SELECT/**/Username,/**/PasswordHash/**/FROM/**/dbo.Users--",
            "nonexistent' UNION SELECT Username, PasswordHash FROM dbo.Users--"
        },

        ChallengeGoal = "Get the product search to leak usernames and password hashes, despite the \"UNION SELECT\" phrase filter.",
        Hints = new[]
        {
            "The filter is only looking for one specific, literal phrase — what else does SQL Server treat as a space?",
            "Try replacing every space in your UNION payload with /**/"
        },
        ChallengeAnswer = "nonexistent'/**/UNION/**/SELECT/**/Username,/**/PasswordHash/**/FROM/**/dbo.Users--",

        TerminologyNote = "Named for the evasion method, not a new attack: the underlying technique is still " +
                           "UNION-based injection. \"Obfuscation\" here specifically means substituting an inline " +
                           "SQL comment for a space — valid, parser-neutral whitespace that a literal-phrase " +
                           "filter was never built to recognize.",
        References = new[]
        {
            new ExternalReference { Label = "websec.ca — MSSQL Fuzzing and Obfuscation knowledge base", Url = "https://websec.ca/sql-injection-knowledge-base/mssql/fuzzing-obfuscation" },
            new ExternalReference { Label = "PortSwigger — Obfuscating attacks using encodings", Url = "https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings" },
            new ExternalReference { Label = "OWASP — SQL Injection Bypassing WAF", Url = "https://wiki.owasp.org/index.php/SQL_Injection_Bypassing_WAF" }
        }
    };
}
