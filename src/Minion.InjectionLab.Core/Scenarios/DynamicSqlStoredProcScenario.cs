using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>"It's in a stored procedure, so it's safe" — false when the proc itself builds dynamic SQL via EXEC(@sql).</summary>
public static class DynamicSqlStoredProcScenario
{
    private const string Baseline = "Acme Corp";

    private static readonly string[] Keywords = { "UNION" };
    private static readonly string[] ExpertKeywords = { "SELECT", "DROP" };

    /// <summary>What @sql actually contains at runtime once the proc's N'...' literal is built —
    /// this (not the doubled-quote proc source text) is what gets parsed to check validity.</summary>
    private static string RuntimeSql(IReadOnlyDictionary<string, string> f) =>
        $"SELECT * FROM dbo.Customers WHERE CompanyName LIKE '%{f["customerName"]}%'";

    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var s = f["customerName"].ToLowerInvariant();
        if (!s.Contains('\'')) return "normal";

        // Real SQL Server parsing (ScriptDom) of what @sql actually ends up containing, rather
        // than guessing from the proc source text whether it "looks terminated".
        return SqlSyntaxChecker.HasSyntaxError(RuntimeSql(f)) ? "malformed" : "injection";
    }

    public static AttackScenario Create() => new()
    {
        Id = "dynamic-sql-stored-proc",
        Category = AttackCategory.IdentifiersAndDynamicSql,
        Title = "Dynamic SQL Inside a Stored Procedure",
        Premise = "dbo.SearchCustomers is a stored procedure — which a lot of teams assume makes it immune to " +
                  "injection by default. It isn't: inside the proc, it builds a string and runs it with EXEC(@sql).",
        MockAppLabel = "CRM — Customer Search",
        BaselineValues = new Dictionary<string, string> { ["customerName"] = Baseline },
        Fields = new[] { new FormField { Key = "customerName", Label = "Company name", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Normal search", Icon = "🏢", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "malformed", Label = "Broken syntax", Icon = "⚠", Kind = PathKind.Neutral },
            new DecisionPathDef { Key = "injection", Label = "Injection inside the proc", Icon = "💉", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f =>
            "-- Inside dbo.SearchCustomers:\n" +
            "DECLARE @sql NVARCHAR(MAX);\n" +
           $"SET @sql = N'SELECT * FROM dbo.Customers WHERE CompanyName LIKE ''%{f["customerName"]}%''';\n" +
            "EXEC(@sql);  -- the proc boundary provides zero protection here",

        // The app calls the proc the same way regardless of which fix is active — the
        // vulnerability (and the fix) both live entirely inside the proc, shown in the SQL tab.
        BuildVulnerableCSharp = f =>
            "using var cmd = new SqlCommand(\"dbo.SearchCustomers\", connection) { CommandType = CommandType.StoredProcedure };\n" +
            "cmd.Parameters.AddWithValue(\"@Name\", customerName);\n" +
            "using var reader = cmd.ExecuteReader();\n" +
            "// looks completely ordinary from here — the vulnerability is entirely inside the proc",

        BuildVulnerablePowerShell = f =>
            "$cmd = New-Object System.Data.SqlClient.SqlCommand \"dbo.SearchCustomers\", $connection\n" +
            "$cmd.CommandType = [System.Data.CommandType]::StoredProcedure\n" +
            "[void]$cmd.Parameters.AddWithValue('@Name', $customerName)\n" +
            "$reader = $cmd.ExecuteReader()",

        // Two real fixes people actually ship, not equally complete: a keyword blacklist inside
        // the proc (looks like a fix, isn't one) vs. sp_executesql with a real parameter.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block names containing \"UNION\"",
                Grade = FixGrade.Partial,
                Gap = "At Beginner, checks for the literal uppercase word \"UNION\" inside the proc — lowercase " +
                      "\"union\" sails through. Intermediate catches any casing. Expert also blocks \"SELECT\"/" +
                      "\"DROP\". But a semicolon-based stacked query or a truncation attempt needs none of those " +
                      "words, so it still sails through at every level.",
                BuildSql = (f, d) =>
                {
                    bool blocked = KeywordBlacklist.IsBlocked(f["customerName"], d, Keywords, ExpertKeywords);
                    // Unlike the other scenarios, this check genuinely runs as real T-SQL inside the
                    // proc, against the real @Name parameter — so it's shown as such here, not just
                    // in C#/PowerShell. (The exact casing/keyword set still varies by difficulty; this
                    // is a representative example using the Beginner-level check for readability.)
                    var guard = "IF @Name LIKE '%UNION%' RETURN;\n\n";
                    return blocked ? guard.TrimEnd() : guard + RuntimeSql(f);
                },
                BuildCSharp = f =>
                    "using var cmd = new SqlCommand(\"dbo.SearchCustomers\", connection) { CommandType = CommandType.StoredProcedure };\n" +
                    "cmd.Parameters.AddWithValue(\"@Name\", customerName);\n" +
                    "using var reader = cmd.ExecuteReader();\n" +
                    "// identical either way — the filter lives inside the proc, see the SQL tab",
                BuildPowerShell = f =>
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"dbo.SearchCustomers\", $connection\n" +
                    "$cmd.CommandType = [System.Data.CommandType]::StoredProcedure\n" +
                    "[void]$cmd.Parameters.AddWithValue('@Name', $customerName)\n" +
                    "$reader = $cmd.ExecuteReader()",
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = KeywordBlacklist.IsBlocked(f["customerName"], d, Keywords, ExpertKeywords);
                    if (Classify(f) == "injection" && !filterCaughtIt)
                        return new SimulationResult
                        {
                            Severity = Severity.Critical,
                            Headline = "The dynamic SQL still gets rewritten — the filter never saw it",
                            Detail = "This payload used a casing or a phrasing the filter at this difficulty doesn't " +
                                      "check for, so it walked straight past it into the same vulnerable EXEC(@sql).",
                            AffectedAssets = new[] { "dbo.Users — exposed through a 'safe-looking' stored procedure" }
                        };
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Proc returns early — matched the filter", Detail = "At this difficulty, the filter happened to catch this specific phrasing." };
                    return new SimulationResult { Severity = Severity.Success, Headline = "1 customer found", Detail = "Ordinary search, the filter never engages." };
                }
            },
            new FixOption
            {
                Label = "✓ sp_executesql with a parameter",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                    "-- Inside dbo.SearchCustomers:\n" +
                    "DECLARE @sql NVARCHAR(MAX) = N'SELECT * FROM dbo.Customers WHERE CompanyName LIKE @Pattern';\n" +
                   $"DECLARE @Pattern NVARCHAR(102) = N'%' + @Name + N'%';  -- @Name = '{f["customerName"]}'\n" +
                    "EXEC sp_executesql @sql, N'@Pattern NVARCHAR(102)', @Pattern;",
                BuildCSharp = f =>
                    "using var cmd = new SqlCommand(\"dbo.SearchCustomers\", connection) { CommandType = CommandType.StoredProcedure };\n" +
                    "cmd.Parameters.AddWithValue(\"@Name\", customerName);\n" +
                    "using var reader = cmd.ExecuteReader();\n" +
                    "// identical either way — sp_executesql lives inside the proc, see the SQL tab",
                BuildPowerShell = f =>
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand \"dbo.SearchCustomers\", $connection\n" +
                    "$cmd.CommandType = [System.Data.CommandType]::StoredProcedure\n" +
                    "[void]$cmd.Parameters.AddWithValue('@Name', $customerName)\n" +
                    "$reader = $cmd.ExecuteReader()",
                Simulate = (f, _) => Classify(f) switch
                {
                    "injection" or "malformed" => new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "sp_executesql keeps @Pattern as a value — the proc is still dynamic, but safely",
                        Detail = "The query shape can still vary at runtime (that's what makes it 'dynamic SQL'), but the " +
                                  "customer's name is passed as a declared parameter, so it can never break out of the " +
                                  "string it's bound into."
                    },
                    _ => new SimulationResult { Severity = Severity.Success, Headline = "1 customer found", Detail = "Ordinary search, unaffected by the fix." }
                }
            }
        },

        SimulateVulnerable = f => Classify(f) switch
        {
            "injection" => new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "The dynamic SQL inside the stored procedure gets rewritten — same as any ad hoc query",
                Detail = "Being inside a stored procedure means nothing here. The proc builds @sql by concatenation " +
                          "and EXEC()s it raw, which is exactly as exploitable as any other concatenated query. The " +
                          "'it's a proc, it's parameterized by definition' assumption is simply false.",
                AffectedAssets = new[] { "dbo.Users — exposed through a 'safe-looking' stored procedure" }
            },
            "malformed" => new SimulationResult
            {
                Severity = Severity.Warning,
                Headline = "EXEC(@sql) throws a syntax error here",
                Detail = "The proc's own template closes with %''''' right after your text, and nothing commented " +
                          "it out. SQL Server rejects the garbled string before it ever runs — no breach, just an error."
            },
            _ => new SimulationResult { Severity = Severity.Success, Headline = "1 customer found", Detail = "Ordinary search." }
        },

        HowItWorks =
            "A stored procedure is just a named, pre-compiled batch of T-SQL — it has no special immunity to " +
            "injection. If the code inside that proc builds a SQL string via concatenation and runs it with EXEC(), " +
            "it's exploitable in exactly the same way as an ad hoc query built the same way. The vulnerability lives " +
            "in how the SQL text is assembled, not in whether it's wrapped in a CREATE PROCEDURE.",

        WhyTheFixWorks =
            "sp_executesql — used instead of plain EXEC() — compiles the SQL text once with declared parameter " +
            "types, then binds values afterward. That protection works identically whether it's called from inline " +
            "application code or from inside a stored procedure.",

        SamplePayloads = new[]
        {
            "Acme%' UNION SELECT UserName, PasswordHash, NULL, NULL FROM Users--",
            "x'; DROP TABLE Customers--",
            "Acme%' union select UserName, PasswordHash, NULL, NULL FROM Users--"
        },

        ChallengeGoal = "Make the customer search stored procedure return the Users table instead of Customers.",
        Hints = new[]
        {
            "The fact that this runs inside a stored procedure doesn't change the mechanics at all.",
            "This is still a LIKE '%...%' query under the hood — close the string the same way you would anywhere else."
        },
        ChallengeAnswer = "Acme%' UNION SELECT UserName, PasswordHash, NULL, NULL FROM Users--",

        TerminologyNote = "\"Dynamic SQL\" is the general T-SQL term for a statement assembled and compiled at " +
                           "runtime (via EXEC or sp_executesql) rather than written statically into the " +
                           "procedure. Being inside a stored procedure doesn't make dynamic SQL safe by itself — " +
                           "the proc can still build the unsafe string the exact same way application code would.",
        References = new[]
        {
            new ExternalReference { Label = "Microsoft Learn — sp_executesql (Transact-SQL)", Url = "https://learn.microsoft.com/sql/relational-databases/system-stored-procedures/sp-executesql-transact-sql" },
            new ExternalReference { Label = "Microsoft Learn — SQL Injection (official security guidance, covers stored procedures)", Url = "https://learn.microsoft.com/sql/relational-databases/security/sql-injection" }
        }
    };
}
