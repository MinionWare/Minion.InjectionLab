using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>JSON path injection: unlike the xml data type's .query()/.value(), JSON_VALUE's path
/// argument CAN be bound as an ordinary parameter since SQL Server 2017 — so code that still
/// concatenates it has no structural excuse, just a missed fix.</summary>
public static class JsonPathInjectionScenario
{
    private const string Baseline = "Email";

    private static readonly string[] Keywords = { "UNION" };
    private static readonly string[] ExpertKeywords = { "SELECT" };

    private static string Classify(IReadOnlyDictionary<string, string> f)
        => f["property"].Contains("union", StringComparison.OrdinalIgnoreCase) ? "bypass" : "normal";

    public static AttackScenario Create() => new()
    {
        Id = "json-path-injection",
        Category = AttackCategory.ClassicInBand,
        Title = "JSON Path Injection",
        Premise = "A customer-profile search lets an admin filter by any property stored in a JSON \"Profile\" " +
                  "column, using JSON_VALUE to pull that property out. The property name comes from a dropdown " +
                  "today — but the query is built by concatenating it into the JSON path string, the same as if " +
                  "it were raw user input.",
        MockAppLabel = "Admin Tools — Profile Search",
        BaselineValues = new Dictionary<string, string> { ["property"] = Baseline },
        Fields = new[] { new FormField { Key = "property", Label = "Profile property", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Ordinary property name", Icon = "🗂", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "bypass", Label = "UNION rides out through the JSON path", Icon = "🧩", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f =>
            $"SELECT Username, Email FROM dbo.Users WHERE JSON_VALUE(Profile, '$.{f["property"]}') = 'test@example.com';",

        BuildVulnerableCSharp = f =>
            "var sql = $\"SELECT Username, Email FROM dbo.Users WHERE JSON_VALUE(Profile, '$.{property}') = 'test@example.com'\";\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "using var reader = cmd.ExecuteReader();",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT Username, Email FROM dbo.Users WHERE JSON_VALUE(Profile, '`$.$property') = 'test@example.com'\"\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql",

        // Two real fixes, not equally complete: a keyword blacklist (looks like a fix, isn't one)
        // vs. binding the JSON path itself as a real parameter — fully supported since SQL Server 2017.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block input containing \"UNION\"",
                Grade = FixGrade.Partial,
                Gap = "At Beginner, checks for the literal uppercase word — lowercase sails through. " +
                      "Intermediate catches any casing. Expert also blocks \"SELECT\" — but this is still the " +
                      "same underlying SQL injection as the plain UNION scenario, just reached through a JSON " +
                      "path string instead of a WHERE clause.",
                BuildSql = (f, d) =>
                {
                    bool blocked = KeywordBlacklist.IsBlocked(f["property"], d, Keywords, ExpertKeywords);
                    return blocked ? "-- Request rejected by the application; no SQL was ever built." : $"SELECT Username, Email FROM dbo.Users WHERE JSON_VALUE(Profile, '$.{f["property"]}') = 'test@example.com';";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["property"].Contains("UNION", StringComparison.OrdinalIgnoreCase);
                    var guard = "if (property.Contains(\"UNION\", StringComparison.OrdinalIgnoreCase))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"SELECT Username, Email FROM dbo.Users WHERE JSON_VALUE(Profile, '$.{property}') = 'test@example.com'\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["property"].Contains("UNION", StringComparison.OrdinalIgnoreCase);
                    var guard = "if ($property -match '(?i)union') { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"SELECT Username, Email FROM dbo.Users WHERE JSON_VALUE(Profile, '`$.$property') = 'test@example.com'\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = KeywordBlacklist.IsBlocked(f["property"], d, Keywords, ExpertKeywords);
                    if (Classify(f) != "bypass")
                        return new SimulationResult { Severity = Severity.Success, Headline = "Profile search completed", Detail = "Ordinary property name, the filter never engages." };
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Request rejected", Detail = "At this difficulty, the filter happened to catch this specific phrasing." };
                    return new SimulationResult
                    {
                        Severity = Severity.Critical,
                        Headline = "Real usernames and password hashes returned — disguised as a profile search",
                        Detail = "Closing the JSON path's quote and the JSON_VALUE call early leaves a completely " +
                                  "ordinary UNION SELECT behind it, reaching dbo.Users directly.",
                        AffectedAssets = new[] { "dbo.Users — Username and PasswordHash columns exposed through a profile property search" }
                    };
                }
            },
            new FixOption
            {
                Label = "✓ Bind the JSON path as a parameter",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                    "EXEC sp_executesql N'SELECT Username, Email FROM dbo.Users WHERE JSON_VALUE(Profile, @Path) = @Email', " +
                    "N'@Path NVARCHAR(100), @Email NVARCHAR(100)', @Path, @Email;\n\n" +
                   $"@Path = $.{f["property"]}\n@Email = test@example.com",
                BuildCSharp = f =>
                    "using var cmd = new SqlCommand(\"SELECT Username, Email FROM dbo.Users WHERE JSON_VALUE(Profile, @Path) = @Email\", connection);\n" +
                    "cmd.Parameters.AddWithValue(\"@Path\", $\"$.{property}\"); // SQL Server 2017+: JSON_VALUE's path CAN be a parameter\n" +
                    "cmd.Parameters.AddWithValue(\"@Email\", \"test@example.com\");",
                BuildPowerShell = f =>
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"SELECT Username, Email FROM dbo.Users WHERE JSON_VALUE(Profile, @Path) = @Email\", $connection\n" +
                    "[void]$cmd.Parameters.AddWithValue('@Path', \"`$.$property\")\n" +
                    "[void]$cmd.Parameters.AddWithValue('@Email', 'test@example.com')",
                Simulate = (f, _) => Classify(f) == "bypass"
                    ? new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "No profile property found (or no match)",
                        Detail = "Since SQL Server 2017, JSON_VALUE's path argument can be an ordinary bound " +
                                  "parameter — your input is treated as a literal (if invalid) JSON path string, " +
                                  "never re-parsed as SQL. There's no workaround required here, unlike the xml " +
                                  "data type's .query()/.value() methods — this one was simply never parameterized."
                    }
                    : new SimulationResult { Severity = Severity.Success, Headline = "Profile search completed", Detail = "Ordinary property name, unaffected by the fix." }
            }
        },

        SimulateVulnerable = f => Classify(f) == "bypass"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Real usernames and password hashes returned — disguised as a profile search",
                Detail = "The property name is concatenated straight into the JSON path string inside " +
                          "JSON_VALUE(...). Closing that string and the function call early turns the rest of " +
                          "the statement into an ordinary UNION SELECT, reaching dbo.Users directly.",
                AffectedAssets = new[] { "dbo.Users — Username and PasswordHash columns exposed through a profile property search" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Profile search completed", Detail = "Ordinary property name, nothing unusual happens." },

        HowItWorks =
            "JSON_VALUE pulls a single value out of a JSON column using a small path language ($.PropertyName, " +
            "$.Nested.Property, and so on). Concatenating a property name into that path string is exactly as " +
            "dangerous as concatenating into any other part of a query — closing the path's quote and the " +
            "function call early hands the rest of the statement over as ordinary SQL text.",

        WhyTheFixWorks =
            "Unlike the xml data type's XQuery methods, JSON_VALUE's path argument has been a fully bindable " +
            "parameter since SQL Server 2017 — there's no structural reason this one ever needed string " +
            "concatenation at all. Binding it directly closes the hole with no workaround required.",

        SamplePayloads = new[]
        {
            "Email') = 'x' UNION SELECT Username, PasswordHash FROM dbo.Users--"
        },

        ChallengeGoal = "Get the profile search to return usernames and password hashes instead of profile data.",
        Hints = new[]
        {
            "The property name ends up inside a JSON path string, inside a function call, inside a WHERE clause — that's three things to close before you can add your own SQL.",
            "Close the path's quote, close JSON_VALUE's parentheses, give the comparison a dummy value, then UNION SELECT."
        },
        ChallengeAnswer = "Email') = 'x' UNION SELECT Username, PasswordHash FROM dbo.Users--",

        TerminologyNote = "Named for the JSON path mini-language JSON_VALUE (and JSON_QUERY, OPENJSON) uses to " +
                           "locate a value inside a JSON document — not a new SQL mechanism. A real, documented " +
                           "2024 vulnerability in the Corteza low-code platform's SQL Server backend was exactly " +
                           "this bug: a JSON path/key built via string concatenation with incorrect escaping.",
        References = new[]
        {
            new ExternalReference { Label = "Microsoft Learn — JSON_VALUE (Transact-SQL)", Url = "https://learn.microsoft.com/sql/t-sql/functions/json-value-transact-sql" },
            new ExternalReference { Label = "fluidattacks — SQL Injection in MSSQL JSON-path meta filter (Corteza)", Url = "https://fluidattacks.com/advisories/motley" }
        }
    };
}
