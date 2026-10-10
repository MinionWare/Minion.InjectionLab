using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>"It's in a stored procedure, so it's safe" — false when the proc itself builds dynamic SQL via EXEC(@sql).</summary>
public static class DynamicSqlStoredProcScenario
{
    private const string Baseline = "Acme Corp";

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

        BuildFixedSql = f =>
            "-- Inside dbo.SearchCustomers:\n" +
            "DECLARE @sql NVARCHAR(MAX) = N'SELECT * FROM dbo.Customers WHERE CompanyName LIKE @Pattern';\n" +
           $"DECLARE @Pattern NVARCHAR(102) = N'%' + @Name + N'%';  -- @Name = '{f["customerName"]}'\n" +
            "EXEC sp_executesql @sql, N'@Pattern NVARCHAR(102)', @Pattern;",

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

        SimulateFixed = f => Classify(f) switch
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
            "x'; DROP TABLE Customers--"
        },

        ChallengeGoal = "Make the customer search stored procedure return the Users table instead of Customers.",
        Hints = new[]
        {
            "The fact that this runs inside a stored procedure doesn't change the mechanics at all.",
            "This is still a LIKE '%...%' query under the hood — close the string the same way you would anywhere else."
        },
        ChallengeAnswer = "Acme%' UNION SELECT UserName, PasswordHash, NULL, NULL FROM Users--"
    };
}
