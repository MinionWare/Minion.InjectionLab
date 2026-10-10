using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Identifier injection: parameters can't substitute for column names at all — only an allow-list can.</summary>
public static class OrderByIdentifierScenario
{
    private static readonly string[] AllowList = { "Name", "Price", "CreatedDate" };
    private const string Baseline = "Name";

    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var s = f["sortColumn"];
        if (Array.Exists(AllowList, c => string.Equals(c, s, StringComparison.OrdinalIgnoreCase))) return "normal";
        return "injection";
    }

    public static AttackScenario Create() => new()
    {
        Id = "order-by-identifier",
        Category = AttackCategory.IdentifiersAndDynamicSql,
        Title = "Identifier Injection (ORDER BY)",
        Premise = "A product list has a \"sort by\" option. Column names can't be bound as @parameters the normal " +
                  "way — parameters only ever substitute for values, never for identifiers — so a lot of apps fall " +
                  "back to string-building here even when everything else is properly parameterized.",
        MockAppLabel = "Store — Product List",
        BaselineValues = new Dictionary<string, string> { ["sortColumn"] = Baseline },
        Fields = new[] { new FormField { Key = "sortColumn", Label = "Sort by", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Allow-listed column", Icon = "✅", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "injection", Label = "Arbitrary expression", Icon = "💉", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"SELECT * FROM dbo.Products ORDER BY {f["sortColumn"]};",

        BuildVulnerableCSharp = f =>
            "var sql = $\"SELECT * FROM dbo.Products ORDER BY {sortColumn}\"; // no @parameter exists for an identifier\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "using var reader = cmd.ExecuteReader();",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT * FROM dbo.Products ORDER BY $sortColumn\"  # no @parameter exists for an identifier\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql",

        // Two real fixes people actually ship, not equally complete: an allow-list check that uses
        // Contains instead of an exact match (a very common real logic bug) vs. an exact-match
        // allow-list combined with QUOTENAME.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Allow-list check using Contains",
                Grade = FixGrade.Partial,
                Gap = "Checks whether the input *contains* an allow-listed name, not that it *is* one — and then " +
                      "concatenates the raw input anyway instead of a hard-coded safe value. \"Name; WAITFOR DELAY " +
                      "...\" contains \"Name\" as a substring, so it passes the check and still gets concatenated.",
                BuildSql = (f, _) =>
                {
                    var s = f["sortColumn"];
                    bool passesCheck = Array.Exists(AllowList, c => s.Contains(c, StringComparison.OrdinalIgnoreCase));
                    // The allow-list check runs in application code, before any SQL is built — see the C#/PowerShell tabs.
                    return passesCheck ? $"SELECT * FROM dbo.Products ORDER BY {s};" : "-- Request rejected by the application; no SQL was ever built.";
                },
                BuildCSharp = f =>
                {
                    var s = f["sortColumn"];
                    bool passesCheck = Array.Exists(AllowList, c => s.Contains(c, StringComparison.OrdinalIgnoreCase));
                    var guard = "if (!AllowList.Any(c => sortColumn.Contains(c)))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"SELECT * FROM dbo.Products ORDER BY {sortColumn}\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);";
                    return passesCheck ? guard + vulnerable : guard.TrimEnd();
                },
                BuildPowerShell = f =>
                {
                    var s = f["sortColumn"];
                    bool passesCheck = Array.Exists(AllowList, c => s.Contains(c, StringComparison.OrdinalIgnoreCase));
                    var guard = "if (-not ($AllowList | Where-Object { $sortColumn.Contains($_) })) { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"SELECT * FROM dbo.Products ORDER BY $sortColumn\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return passesCheck ? guard + vulnerable : guard.TrimEnd();
                },
                Simulate = (f, _) =>
                {
                    var s = f["sortColumn"];
                    bool passesCheck = Array.Exists(AllowList, c => s.Contains(c, StringComparison.OrdinalIgnoreCase));
                    if (Classify(f) == "injection" && passesCheck)
                        return new SimulationResult
                        {
                            Severity = Severity.Critical,
                            Headline = "Arbitrary SQL still executes — the check passed on a technicality",
                            Detail = "The value contains an allow-listed column name as a substring, so the Contains() " +
                                      "check approves it — and then the raw value, WAITFOR and all, gets concatenated " +
                                      "anyway instead of the safe literal the check was supposed to guarantee.",
                            AffectedAssets = new[] { "Arbitrary expression executed from the ORDER BY clause" }
                        };
                    if (Classify(f) == "injection")
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Rejected — doesn't contain any allow-listed name", Detail = "This specific payload doesn't happen to contain any of the allow-listed words as a substring." };
                    return new SimulationResult { Severity = Severity.Success, Headline = $"Sorted by {s}", Detail = "An allow-listed column, passed straight through." };
                }
            },
            new FixOption
            {
                Label = "✓ Exact-match allow-list + QUOTENAME",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                {
                    var safe = Array.Exists(AllowList, c => string.Equals(c, f["sortColumn"], StringComparison.OrdinalIgnoreCase))
                        ? f["sortColumn"]
                        : "Name";
                    return "-- @parameter placeholders don't work for identifiers — validate against a fixed allow-list instead:\n" +
                           "DECLARE @SafeColumn sysname =\n" +
                          $"    CASE @SortColumn WHEN 'Name' THEN N'Name' WHEN 'Price' THEN N'Price'\n" +
                           "         WHEN 'CreatedDate' THEN N'CreatedDate' ELSE N'Name' END;\n\n" +
                          $"EXEC('SELECT * FROM dbo.Products ORDER BY ' + QUOTENAME(@SafeColumn));\n" +
                          $"-- your input ('{f["sortColumn"]}') resolves to: {safe}";
                },
                BuildCSharp = f =>
                {
                    var safe = Array.Exists(AllowList, c => string.Equals(c, f["sortColumn"], StringComparison.OrdinalIgnoreCase)) ? f["sortColumn"] : "Name";
                    return "// @parameter doesn't work for identifiers — validate against a fixed allow-list, exact match\n" +
                           "var allowList = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { \"Name\", \"Price\", \"CreatedDate\" };\n" +
                          $"var safeColumn = allowList.Contains(sortColumn) ? sortColumn : \"Name\"; // resolves to: {safe}\n" +
                           "var sql = $\"SELECT * FROM dbo.Products ORDER BY [{safeColumn}]\";\n" +
                           "using var cmd = new SqlCommand(sql, connection);";
                },
                BuildPowerShell = f =>
                {
                    var safe = Array.Exists(AllowList, c => string.Equals(c, f["sortColumn"], StringComparison.OrdinalIgnoreCase)) ? f["sortColumn"] : "Name";
                    return "# @parameter doesn't work for identifiers — validate against a fixed allow-list, exact match\n" +
                           "$allowList = 'Name', 'Price', 'CreatedDate'\n" +
                          $"$safeColumn = if ($allowList -contains $sortColumn) {{ $sortColumn }} else {{ 'Name' }}  # resolves to: {safe}\n" +
                           "$sql = \"SELECT * FROM dbo.Products ORDER BY [$safeColumn]\"\n" +
                           "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                },
                Simulate = (f, _) => Classify(f) == "injection"
                    ? new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "Falls back to the default sort (Name)",
                        Detail = "Anything not an exact allow-listed name never reaches the SQL text at all — it's " +
                                  "substituted with a safe, hard-coded default before the query is even built."
                    }
                    : new SimulationResult { Severity = Severity.Success, Headline = $"Sorted by {f["sortColumn"]}", Detail = "An allow-listed column, passed straight through." }
            }
        },

        SimulateVulnerable = f => Classify(f) == "injection"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Arbitrary SQL executes from inside what was supposed to be just a column name",
                Detail = "ORDER BY accepts a full expression, not just a bare column — so string-concatenating this " +
                          "value is exactly as dangerous as concatenating into a WHERE clause. The fact that it " +
                          "\"looks like\" a harmless sort option doesn't make it safe.",
                AffectedAssets = new[] { "Arbitrary expression executed from the ORDER BY clause" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Sorted by Name", Detail = "Ordinary sort." },


        HowItWorks =
            "Identifiers (table and column names) are categorically different from values: @parameter placeholders " +
            "only ever bind as data, never as SQL syntax, so 'ORDER BY @SortColumn' either errors or doesn't do what " +
            "a developer expects. Faced with that, many fall back to plain string concatenation for \"just a column " +
            "name\" — reopening exactly the same hole as any other injection, because ORDER BY accepts arbitrary " +
            "expressions, not only bare identifiers.",

        WhyTheFixWorks =
            "Validate the requested column against a hard-coded allow-list (or look it up from sys.columns) before " +
            "ever building the SQL text, and wrap the validated identifier in QUOTENAME() as defense in depth. " +
            "Nothing the user typed is ever trusted as-is.",

        SamplePayloads = new[]
        {
            "Name; WAITFOR DELAY '0:0:5'--",
            "(SELECT 1); DROP TABLE Products--"
        },

        ChallengeGoal = "Make the product list execute a WAITFOR delay through the \"sort by\" option.",
        Hints = new[]
        {
            "This value can't be parameterized the normal way at all — it's an identifier, not data.",
            "ORDER BY accepts more than just a column name — it accepts a whole expression.",
            "What ends a statement and lets a new one begin?"
        },
        ChallengeAnswer = "Name; WAITFOR DELAY '0:0:5'--",

        TerminologyNote = "Named for what's being injected: an identifier (a column or table name) rather " +
                           "than a value. That distinction matters because @parameter placeholders only ever " +
                           "bind as data — there's no parameterized way to say \"this identifier\" at all, which " +
                           "is why allow-listing is the only real fix here.",
        References = new[]
        {
            new ExternalReference { Label = "Microsoft Learn — QUOTENAME (Transact-SQL)", Url = "https://learn.microsoft.com/sql/t-sql/functions/quotename-transact-sql" },
            new ExternalReference { Label = "OWASP — SQL Injection Prevention Cheat Sheet", Url = "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet" }
        }
    };
}
