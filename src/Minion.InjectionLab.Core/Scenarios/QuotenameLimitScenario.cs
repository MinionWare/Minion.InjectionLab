using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>QUOTENAME's 128-character limit: the "textbook correct" identifier fix silently falls
/// over past a length nobody thought to check for — because QUOTENAME was never the whole fix.</summary>
public static class QuotenameLimitScenario
{
    private const string Baseline = "Price";
    private static readonly string[] AllowList = { "Name", "Price", "CreatedDate" };

    private static string Classify(IReadOnlyDictionary<string, string> f)
        => f["sortColumn"].Length > 128 ? "overlong" : "normal";

    public static AttackScenario Create() => new()
    {
        Id = "quotename-limit",
        Category = AttackCategory.IdentifiersAndDynamicSql,
        Title = "QUOTENAME's 128-Character Limit",
        Premise = "The same \"sort by\" product list as the identifier-injection scenario — except this developer " +
                  "already learned that lesson and wraps the column name in QUOTENAME() before building the " +
                  "query. QUOTENAME alone sounds like the textbook-correct fix for an identifier. It isn't quite " +
                  "the whole fix.",
        MockAppLabel = "Store — Product List",
        BaselineValues = new Dictionary<string, string> { ["sortColumn"] = Baseline },
        Fields = new[] { new FormField { Key = "sortColumn", Label = "Sort by", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Ordinary column name", Icon = "✅", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "overlong", Label = "Over 128 characters", Icon = "📏", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f =>
        {
            var col = f["sortColumn"];
            var quoted = col.Length > 128 ? "NULL" : $"[{col}]";
            return "-- QUOTENAME(@SortColumn) returns NULL for any input over 128 characters (the sysname limit):\n" +
                  $"EXEC('SELECT * FROM dbo.Products ORDER BY ' + QUOTENAME(@SortColumn));\n" +
                  $"-- QUOTENAME('{(col.Length > 50 ? col[..50] + "…(" + col.Length + " chars total)" : col)}') = {quoted}" +
                   (col.Length > 128 ? "\n-- string concatenation with NULL makes the ENTIRE command text NULL — EXEC(NULL) runs nothing, silently" : "");
        },

        BuildVulnerableCSharp = f =>
            "// QUOTENAME is applied, but nothing validates the column name itself\n" +
            "var sql = $\"EXEC('SELECT * FROM dbo.Products ORDER BY ' + QUOTENAME(@SortColumn))\";\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "cmd.Parameters.AddWithValue(\"@SortColumn\", sortColumn);\n" +
            "using var reader = cmd.ExecuteReader(); // over 128 chars: QUOTENAME returns NULL, the whole batch silently does nothing",

        BuildVulnerablePowerShell = f =>
            "# QUOTENAME is applied, but nothing validates the column name itself\n" +
            "$cmd = New-Object System.Data.SqlClient.SqlCommand \"EXEC('SELECT * FROM dbo.Products ORDER BY ' + QUOTENAME(@SortColumn))\", $connection\n" +
            "[void]$cmd.Parameters.AddWithValue('@SortColumn', $sortColumn)\n" +
            "$reader = $cmd.ExecuteReader()",

        // Two real fixes, not equally complete: QUOTENAME alone (looks like THE fix, is only HALF
        // of it) vs. QUOTENAME combined with the allow-list it should never have been without.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ QUOTENAME alone, no allow-list",
                Grade = FixGrade.Partial,
                Gap = "QUOTENAME does correctly stop every classic identifier-injection payload — but it was " +
                      "never designed to validate that the identifier is one your schema actually has, only to " +
                      "safely quote whatever string it's given. Feed it anything over 128 characters (sysname's " +
                      "own length limit) and it silently returns NULL instead of erroring — which, concatenated " +
                      "into the rest of the command text, turns the ENTIRE batch into NULL. EXEC(NULL) doesn't " +
                      "throw; it just quietly does nothing, every single time, regardless of difficulty.",
                BuildSql = (f, _) =>
                {
                    var col = f["sortColumn"];
                    if (col.Length > 128)
                        return "-- QUOTENAME(@SortColumn) returned NULL (input over 128 characters).\n" +
                               "-- 'NULL command text' + anything = NULL — EXEC(NULL) silently runs nothing at all.\n" +
                               "EXEC(NULL);";
                    return $"EXEC('SELECT * FROM dbo.Products ORDER BY ' + QUOTENAME(@SortColumn));\n\n@SortColumn = {col}";
                },
                BuildCSharp = f =>
                    "var sql = \"EXEC('SELECT * FROM dbo.Products ORDER BY ' + QUOTENAME(@SortColumn))\";\n" +
                    "using var cmd = new SqlCommand(sql, connection);\n" +
                    "cmd.Parameters.AddWithValue(\"@SortColumn\", sortColumn); // no length or allow-list check at all\n" +
                    "using var reader = cmd.ExecuteReader();",
                BuildPowerShell = f =>
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"EXEC('SELECT * FROM dbo.Products ORDER BY ' + QUOTENAME(@SortColumn))\", $connection\n" +
                    "[void]$cmd.Parameters.AddWithValue('@SortColumn', $sortColumn)  # no length or allow-list check at all\n" +
                    "$reader = $cmd.ExecuteReader()",
                Simulate = (f, _) => Classify(f) == "overlong"
                    ? new SimulationResult
                    {
                        Severity = Severity.Warning,
                        Headline = "The product list silently shows nothing — no error, no sort, no explanation",
                        Detail = "QUOTENAME returned NULL, which made the entire dynamic command NULL. EXEC(NULL) is " +
                                  "valid T-SQL that does precisely nothing — not a crash, not an injection, but a " +
                                  "confusing, hard-to-diagnose silent failure that QUOTENAME alone was never built " +
                                  "to prevent.",
                        AffectedAssets = new[] { "Feature silently breaks for any input over 128 characters" }
                    }
                    : new SimulationResult { Severity = Severity.Success, Headline = $"Sorted by {f["sortColumn"]}", Detail = "An ordinary column name, well under the 128-character limit." }
            },
            new FixOption
            {
                Label = "✓ QUOTENAME + exact-match allow-list",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                {
                    var safe = Array.Exists(AllowList, c => string.Equals(c, f["sortColumn"], StringComparison.OrdinalIgnoreCase))
                        ? f["sortColumn"] : "Name";
                    return "-- Allow-list checked FIRST (exact match against known columns) — QUOTENAME is defense in\n" +
                           "-- depth on top of that, never the only check:\n" +
                           "DECLARE @SafeColumn sysname =\n" +
                           "    CASE @SortColumn WHEN 'Name' THEN N'Name' WHEN 'Price' THEN N'Price'\n" +
                           "         WHEN 'CreatedDate' THEN N'CreatedDate' ELSE N'Name' END;\n\n" +
                           "EXEC('SELECT * FROM dbo.Products ORDER BY ' + QUOTENAME(@SafeColumn));\n" +
                          $"-- your input resolves to: {safe}";
                },
                BuildCSharp = f =>
                {
                    var safe = Array.Exists(AllowList, c => string.Equals(c, f["sortColumn"], StringComparison.OrdinalIgnoreCase)) ? f["sortColumn"] : "Name";
                    return "// Allow-list checked first (exact match), QUOTENAME applied on top as defense in depth\n" +
                           "var allowList = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { \"Name\", \"Price\", \"CreatedDate\" };\n" +
                          $"var safeColumn = allowList.Contains(sortColumn) ? sortColumn : \"Name\"; // resolves to: {safe}\n" +
                           "var sql = $\"SELECT * FROM dbo.Products ORDER BY [{safeColumn}]\";\n" +
                           "using var cmd = new SqlCommand(sql, connection);";
                },
                BuildPowerShell = f =>
                {
                    var safe = Array.Exists(AllowList, c => string.Equals(c, f["sortColumn"], StringComparison.OrdinalIgnoreCase)) ? f["sortColumn"] : "Name";
                    return "# Allow-list checked first (exact match), QUOTENAME applied on top as defense in depth\n" +
                           "$allowList = 'Name', 'Price', 'CreatedDate'\n" +
                          $"$safeColumn = if ($allowList -contains $sortColumn) {{ $sortColumn }} else {{ 'Name' }}  # resolves to: {safe}\n" +
                           "$sql = \"SELECT * FROM dbo.Products ORDER BY [$safeColumn]\"\n" +
                           "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                },
                Simulate = (f, _) => Classify(f) == "overlong"
                    ? new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "Falls back to the default sort (Name)",
                        Detail = "The allow-list check runs first and rejects anything that isn't an exact, known " +
                                  "column name — length is irrelevant, because a 200-character string was never " +
                                  "going to match \"Name\", \"Price\", or \"CreatedDate\" in the first place. " +
                                  "QUOTENAME never even gets a chance to return NULL."
                    }
                    : new SimulationResult { Severity = Severity.Success, Headline = $"Sorted by {f["sortColumn"]}", Detail = "An allow-listed column, passed straight through." }
            }
        },

        SimulateVulnerable = f => Classify(f) == "overlong"
            ? new SimulationResult
            {
                Severity = Severity.Warning,
                Headline = "The product list silently shows nothing — no error, no sort, no explanation",
                Detail = "QUOTENAME(@SortColumn) returns NULL for anything over 128 characters — sysname's own " +
                          "length limit — and NULL concatenated into the rest of the dynamic SQL string makes the " +
                          "entire command text NULL. EXEC(NULL) is valid, silent, and does nothing at all.",
                AffectedAssets = new[] { "Feature silently breaks for any input over 128 characters" }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = $"Sorted by {f["sortColumn"]}", Detail = "An ordinary column name, nothing unusual happens." },

        HowItWorks =
            "QUOTENAME() is a real, correct defense against classic identifier injection — it wraps whatever " +
            "string it's given in brackets, safely, so the result can never be parsed as anything but a single " +
            "identifier. But it was built to quote a value, not to validate that the value is actually one of " +
            "your real column names. Its own documented behavior is to return NULL for input longer than 128 " +
            "characters (the sysname data type's limit) — and NULL silently poisons the rest of any string it's " +
            "concatenated into.",

        WhyTheFixWorks =
            "An exact-match allow-list checked before QUOTENAME ever runs means only a handful of known-good " +
            "values are ever passed to it at all — nothing arbitrary, let alone 128+ characters of it, ever " +
            "reaches QUOTENAME in the first place. QUOTENAME then becomes genuine defense in depth, instead of " +
            "the only thing standing in an attacker's way.",

        SamplePayloads = new[]
        {
            new string('A', 129),
            new string('x', 200)
        },

        ChallengeGoal = "Make the product list silently fail to sort at all, using nothing but an overly long column name.",
        Hints = new[]
        {
            "QUOTENAME has documented limits of its own — what's the longest identifier SQL Server allows (the sysname type's limit)?",
            "What does QUOTENAME return for input past that limit, and what happens when you concatenate a string with NULL?"
        },
        ChallengeAnswer = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",

        TerminologyNote = "Not a new attack technique — the identifier can't be \"injected\" here at all, " +
                           "QUOTENAME sees to that. The name refers to a specific, documented edge case in " +
                           "QUOTENAME's own behavior (the 128-character sysname limit) that breaks a fix relying " +
                           "on QUOTENAME as if it were a complete, standalone solution rather than one layer of one.",
        References = new[]
        {
            new ExternalReference { Label = "Microsoft Learn — QUOTENAME (Transact-SQL)", Url = "https://learn.microsoft.com/sql/t-sql/functions/quotename-transact-sql" },
            new ExternalReference { Label = "OWASP — SQL Injection Prevention Cheat Sheet", Url = "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet" }
        }
    };
}
