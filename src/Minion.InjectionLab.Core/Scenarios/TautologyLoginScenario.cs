using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>
/// The canonical "Bobby Tables" login bypass: ' OR 1=1 --
/// </summary>
public static class TautologyLoginScenario
{
    private const string BaselineUser = "alice";
    private const string BaselinePassword = "correct-horse-battery-99";

    /// <summary>The three paths any input takes: a real login, an ordinary failed login, or an attack.
    /// Shared by ClassifyInput (live, pre-submit) and both Simulate functions (post-submit), so the
    /// live diagram and the final narration always agree.</summary>
    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var combined = (f["username"] + " " + f["password"]).ToLowerInvariant();
        bool looksLikeTautology = combined.Contains("or 1=1") || combined.Contains("or '1'='1")
                                   || combined.Contains("or 1 = 1") || (combined.Contains("--") && combined.Contains("or "));
        if (looksLikeTautology) return "injection";

        if (f["username"] == BaselineUser && f["password"] == BaselinePassword) return "correct";

        return "incorrect";
    }

    /// <summary>Representative — not real — single-row result for a successful login.</summary>
    private static IReadOnlyList<IReadOnlyDictionary<string, string>> FakeOwnRow(string username) => new[]
    {
        new Dictionary<string, string> { ["UserId"] = "1042", ["UserName"] = username, ["Role"] = "Customer" }
    };

    /// <summary>Representative — not real — "every row matched" dump for the tautology bypass.</summary>
    private static readonly IReadOnlyList<IReadOnlyDictionary<string, string>> FakeFullUsersDump = new[]
    {
        new Dictionary<string, string> { ["UserId"] = "1001", ["UserName"] = "admin", ["Role"] = "Administrator" },
        new Dictionary<string, string> { ["UserId"] = "1002", ["UserName"] = "svc_billing", ["Role"] = "ServiceAccount" },
        new Dictionary<string, string> { ["UserId"] = "1042", ["UserName"] = "alice", ["Role"] = "Customer" },
        new Dictionary<string, string> { ["UserId"] = "1043", ["UserName"] = "bob", ["Role"] = "Customer" },
        new Dictionary<string, string> { ["UserId"] = "…", ["UserName"] = "… 42 more rows …", ["Role"] = "" }
    };

    public static AttackScenario Create() => new()
    {
        Id = "tautology-login",
        Category = AttackCategory.ClassicInBand,
        Title = "Tautology / Login Bypass",
        Premise = "A login form checks a username and password against the Users table. " +
                  "The query is built by gluing the two text boxes straight into the WHERE clause.",
        MockAppLabel = "Customer Portal — Sign In",
        BaselineValues = new Dictionary<string, string>
        {
            ["username"] = BaselineUser,
            ["password"] = BaselinePassword
        },
        // Defaults start on the "correct login" path on purpose — hit Submit with nothing changed
        // and you see a normal, legitimate success. Only once you start typing a payload does the
        // path diagram (and the outcome) shift.
        Fields = new[]
        {
            new FormField { Key = "username", Label = "Username", DefaultValue = BaselineUser, Placeholder = "username" },
            new FormField { Key = "password", Label = "Password", DefaultValue = BaselinePassword, Placeholder = "password", IsPassword = true }
        },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "correct", Label = "Correct credentials", Icon = "🔑", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "incorrect", Label = "Wrong password", Icon = "🚫", Kind = PathKind.Neutral },
            new DecisionPathDef { Key = "injection", Label = "SQL injection pattern", Icon = "💉", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f =>
            $"SELECT UserId, UserName, Role FROM dbo.Users " +
            $"WHERE UserName = '{f["username"]}' AND PasswordHash = '{f["password"]}';",

        BuildFixedSql = f =>
            "-- Parameters bind as typed values, never as SQL text\n" +
            "SELECT UserId, UserName, Role FROM dbo.Users\n" +
            "WHERE UserName = @UserName AND PasswordHash = @PasswordHash;\n\n" +
            "-- Parameter values sent alongside the batch (not concatenated):\n" +
            $"@UserName    = N'{f["username"]}'\n" +
            $"@PasswordHash = N'{f["password"]}'",

        BuildVulnerableCSharp = f =>
            "var sql = \"SELECT UserId, UserName, Role FROM dbo.Users \" +\n" +
           $"           \"WHERE UserName = '\" + username + \"' AND PasswordHash = '\" + password + \"';\";\n\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "using var reader = cmd.ExecuteReader(); // whatever `username`/`password` contain becomes SQL",

        BuildFixedCSharp = f =>
            "const string sql = \"SELECT UserId, UserName, Role FROM dbo.Users \" +\n" +
            "                    \"WHERE UserName = @UserName AND PasswordHash = @PasswordHash;\";\n\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "cmd.Parameters.Add(\"@UserName\", SqlDbType.NVarChar, 100).Value = username;\n" +
            "cmd.Parameters.Add(\"@PasswordHash\", SqlDbType.NVarChar, 128).Value = password;\n" +
            "using var reader = cmd.ExecuteReader(); // values bind as data, never as SQL text",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT UserId, UserName, Role FROM dbo.Users \" +\n" +
           $"       \"WHERE UserName = '$username' AND PasswordHash = '$password';\"\n\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql",

        BuildFixedPowerShell = f =>
            "$sql = \"SELECT UserId, UserName, Role FROM dbo.Users \" +\n" +
            "       \"WHERE UserName = @UserName AND PasswordHash = @PasswordHash;\"\n\n" +
            "$cmd = New-Object System.Data.SqlClient.SqlCommand $sql, $connection\n" +
            "[void]$cmd.Parameters.AddWithValue('@UserName', $username)\n" +
            "[void]$cmd.Parameters.AddWithValue('@PasswordHash', $password)\n" +
            "$reader = $cmd.ExecuteReader()",

        SimulateVulnerable = f => Classify(f) switch
        {
            "injection" => new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Authentication bypassed — every row in Users matches",
                Detail = "The injected 'OR 1=1' makes the WHERE clause true for every row, and the trailing " +
                          "'--' comments out the rest of the original query (including the password check). " +
                          "The app receives the first row back — typically the first account in the table — and logs that user in " +
                          "without ever knowing a valid password.",
                RowCountLabel = "47 rows — the entire Users table",
                AffectedAssets = new[] { "dbo.Users — all 47 rows exposed to the app" },
                LeakedRows = FakeFullUsersDump
            },
            "correct" => new SimulationResult
            {
                Severity = Severity.Success,
                Headline = $"Login succeeded — welcome, {f["username"]}",
                Detail = "The concatenated query happens to run fine here because the input contains no SQL syntax. " +
                          "That's not the fix working — it's just an ordinary value. The query is exactly as vulnerable " +
                          "as it was a moment ago; nothing here has been exploited yet.",
                RowCountLabel = "1 row",
                LeakedRows = FakeOwnRow(f["username"])
            },
            _ => new SimulationResult
            {
                Severity = Severity.Info,
                Headline = "Invalid username or password",
                Detail = "An ordinary failed login — the WHERE clause evaluated to false, same as it would in a safely " +
                          "written app. The vulnerability only shows itself once the input contains SQL syntax."
            }
        },

        SimulateFixed = f => Classify(f) switch
        {
            "injection" => new SimulationResult
            {
                Severity = Severity.Blocked,
                Headline = "Treated as a literal string — no rows match",
                Detail = "Because the values are sent as parameters, the database never re-parses them as SQL. " +
                          "\"' OR 1=1 --\" is just a username nobody has, so the WHERE clause evaluates to false for every row. " +
                          "The login fails exactly the way it should."
            },
            "correct" => new SimulationResult
            {
                Severity = Severity.Success,
                Headline = $"Login succeeded — welcome, {f["username"]}",
                Detail = "Parameterizing the query doesn't change how legitimate logins behave — it only removes the " +
                          "ability for input to be reinterpreted as SQL. Correct credentials still work exactly as before.",
                RowCountLabel = "1 row",
                LeakedRows = FakeOwnRow(f["username"])
            },
            _ => new SimulationResult
            {
                Severity = Severity.Info,
                Headline = "Invalid username or password",
                Detail = "Same as the vulnerable version — the fix only changes what happens to attack-shaped input, " +
                          "not ordinary failed logins."
            }
        },

        HowItWorks =
            "The app builds the query by concatenating raw text into the SQL string instead of treating it as data. " +
            "A quote character (') closes the string literal early, so anything typed after it is parsed as SQL, not as a password. " +
            "'OR 1=1' adds a condition that is always true, and '--' turns the rest of the line into a comment, discarding whatever " +
            "the original query intended to check next.",

        WhyTheFixWorks =
            "Parameterized queries (sp_executesql, or a parameterized ADO.NET/Dapper/EF command) send the SQL text and the " +
            "parameter values in two separate channels. The database compiles the SQL text once, with @UserName and @PasswordHash " +
            "as placeholders, and only afterward substitutes the values as typed data. A quote character inside the value is just " +
            "a character inside a string — it has no power to change the shape of the query.",

        SamplePayloads = new[]
        {
            "' OR 1=1 --",
            "' OR '1'='1",
            "admin'--",
            "' OR 1=1#"
        },

        ChallengeGoal = "Log in as any user without knowing a real password.",
        Hints = new[]
        {
            "The query is built with string concatenation — what character ends a SQL string literal?",
            "Once you close the string, you can add your own condition to the WHERE clause.",
            "A condition that's always true, followed by a comment marker, discards the rest of the query."
        },
        ChallengeAnswer = "' OR 1=1 --"
    };
}
