using Minion.InjectionLab.Core.Models;
using Minion.InjectionLab.Core.Services;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>
/// The canonical "Bobby Tables" login bypass: ' OR 1=1 --
/// </summary>
public static class TautologyLoginScenario
{
    private const string BaselineUser = "alice";
    private const string BaselinePassword = "correct-horse-battery-99";

    private static readonly string[] Keywords = { "OR" };
    private static readonly string[] ExpertKeywords = { "UNION" };

    private static string VulnerableSql(IReadOnlyDictionary<string, string> f) =>
        $"SELECT UserId, UserName, Role FROM dbo.Users " +
        $"WHERE UserName = '{f["username"]}' AND PasswordHash = '{f["password"]}';";

    // Our fictional baseline values never contain a quote character, so any quote at all signals
    // an attempted string-literal breakout — tautology-style ("' OR 1=1") or truncation-style
    // ("admin'"), it doesn't matter which.
    private static bool LooksLikeBreakoutAttempt(string s) => s.Contains('\'');

    /// <summary>The four paths any input takes: a real login, an ordinary failed login, a properly
    /// terminated attack, or a near-miss that never neutralizes the rest of the query. Shared by
    /// ClassifyInput (live, pre-submit) and both Simulate functions (post-submit), so the live
    /// diagram and the final narration always agree. Whether the query is even syntactically valid
    /// is checked with the real SQL Server parser (ScriptDom) rather than a guessed-at pattern like
    /// "does it end with --" — that was tried first and got it wrong (see docs.md). A quote
    /// breakout that parses cleanly is treated as a full bypass; this doesn't model every subtlety
    /// of operator precedence for payloads that are valid SQL but happen not to fully defeat both
    /// checks — that would mean evaluating the WHERE clause's boolean logic in general, which is
    /// out of scope here.</summary>
    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var username = f["username"];
        var password = f["password"];

        if (LooksLikeBreakoutAttempt(username) || LooksLikeBreakoutAttempt(password))
            return SqlSyntaxChecker.HasSyntaxError(VulnerableSql(f)) ? "malformed" : "injection";

        if (username == BaselineUser && password == BaselinePassword) return "correct";

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
            new DecisionPathDef { Key = "malformed", Label = "Broken syntax", Icon = "⚠", Kind = PathKind.Neutral },
            new DecisionPathDef { Key = "injection", Label = "SQL injection pattern", Icon = "💉", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = VulnerableSql,

        BuildVulnerableCSharp = f =>
            "var sql = \"SELECT UserId, UserName, Role FROM dbo.Users \" +\n" +
           $"           \"WHERE UserName = '\" + username + \"' AND PasswordHash = '\" + password + \"';\";\n\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "using var reader = cmd.ExecuteReader(); // whatever `username`/`password` contain becomes SQL",

        BuildVulnerablePowerShell = f =>
            "$sql = \"SELECT UserId, UserName, Role FROM dbo.Users \" +\n" +
           $"       \"WHERE UserName = '$username' AND PasswordHash = '$password';\"\n\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql",

        // Two real fixes people actually ship, not equally complete: a keyword blacklist (looks
        // like a fix, isn't one) vs. real parameterization. Each shows SQL *and* C#/PowerShell so
        // the code tabs stay consistent regardless of which fix is selected.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Block input containing \"OR\"",
                Grade = FixGrade.Partial,
                Gap = "At Beginner, checks for the literal uppercase word \"OR\" — lowercase \"or\" sails straight " +
                      "through. Intermediate catches any casing. Expert also blocks \"UNION\". But a payload that " +
                      "never needs any blocked word at all (like \"admin'--\") still sails through at every level — " +
                      "a blacklist can only ever cover phrasings someone thought to list.",
                BuildSql = (f, d) =>
                {
                    bool blocked = KeywordBlacklist.IsBlocked(f["username"], d, Keywords, ExpertKeywords) || KeywordBlacklist.IsBlocked(f["password"], d, Keywords, ExpertKeywords);
                    var guard = "if (LooksLikeInjection(username) || LooksLikeInjection(password))\n    reject();\n\n";
                    return blocked ? guard.TrimEnd() : guard + VulnerableSql(f);
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["username"].Contains("OR") || f["password"].Contains("OR");
                    var guard = "if (username.Contains(\"OR\") || password.Contains(\"OR\"))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = \"SELECT UserId, UserName, Role FROM dbo.Users \" +\n" +
                                     "           \"WHERE UserName = '\" + username + \"' AND PasswordHash = '\" + password + \"';\";\n\n" +
                                     "using var cmd = new SqlCommand(sql, connection);\n" +
                                     "using var reader = cmd.ExecuteReader();";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["username"].Contains("OR") || f["password"].Contains("OR");
                    var guard = "if ($username.Contains(\"OR\") -or $password.Contains(\"OR\")) { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"SELECT UserId, UserName, Role FROM dbo.Users \" +\n" +
                                      "       \"WHERE UserName = '$username' AND PasswordHash = '$password';\"\n\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, d) =>
                {
                    bool filterCaughtIt = KeywordBlacklist.IsBlocked(f["username"], d, Keywords, ExpertKeywords) || KeywordBlacklist.IsBlocked(f["password"], d, Keywords, ExpertKeywords);
                    var classification = Classify(f);
                    if (classification == "injection" && !filterCaughtIt)
                        return new SimulationResult
                        {
                            Severity = Severity.Critical,
                            Headline = "Authentication bypassed — the filter never even saw it",
                            Detail = "This payload used a casing or a phrasing the filter at this difficulty doesn't " +
                                      "check for, so it walked straight past into the exact same vulnerable concatenation.",
                            RowCountLabel = "47 rows — the entire Users table",
                            AffectedAssets = new[] { "dbo.Users — all 47 rows exposed to the app" },
                            LeakedRows = FakeFullUsersDump
                        };
                    if (classification == "injection" && filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Request rejected — matched the filter", Detail = "At this difficulty, the filter happened to catch this specific phrasing." };
                    if (classification == "correct")
                        return new SimulationResult { Severity = Severity.Success, Headline = $"Login succeeded — welcome, {f["username"]}", Detail = "Ordinary login, the filter never engages.", RowCountLabel = "1 row", LeakedRows = FakeOwnRow(f["username"]) };
                    return new SimulationResult { Severity = Severity.Info, Headline = "Invalid username or password", Detail = "Ordinary failed login." };
                }
            },
            new FixOption
            {
                Label = "✓ Parameterized query",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                    "-- Parameters bind as typed values, never as SQL text\n" +
                    "SELECT UserId, UserName, Role FROM dbo.Users\n" +
                    "WHERE UserName = @UserName AND PasswordHash = @PasswordHash;\n\n" +
                    "-- Parameter values sent alongside the batch (not concatenated):\n" +
                    $"@UserName    = N'{f["username"]}'\n" +
                    $"@PasswordHash = N'{f["password"]}'",
                BuildCSharp = f =>
                    "const string sql = \"SELECT UserId, UserName, Role FROM dbo.Users \" +\n" +
                    "                    \"WHERE UserName = @UserName AND PasswordHash = @PasswordHash;\";\n\n" +
                    "using var cmd = new SqlCommand(sql, connection);\n" +
                    "cmd.Parameters.Add(\"@UserName\", SqlDbType.NVarChar, 100).Value = username;\n" +
                    "cmd.Parameters.Add(\"@PasswordHash\", SqlDbType.NVarChar, 128).Value = password;\n" +
                    "using var reader = cmd.ExecuteReader(); // values bind as data, never as SQL text",
                BuildPowerShell = f =>
                    "$sql = \"SELECT UserId, UserName, Role FROM dbo.Users \" +\n" +
                    "       \"WHERE UserName = @UserName AND PasswordHash = @PasswordHash;\"\n\n" +
                    "$cmd = New-Object System.Data.SqlClient.SqlCommand $sql, $connection\n" +
                    "[void]$cmd.Parameters.AddWithValue('@UserName', $username)\n" +
                    "[void]$cmd.Parameters.AddWithValue('@PasswordHash', $password)\n" +
                    "$reader = $cmd.ExecuteReader()",
                Simulate = (f, _) => Classify(f) switch
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
                    "malformed" => new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "Invalid username or password",
                        Detail = "Parameterized or not, this particular attempt was never going to work anyway — but now " +
                                  "it fails the same clean way any wrong input does, instead of risking a confusing error."
                    },
                    _ => new SimulationResult
                    {
                        Severity = Severity.Info,
                        Headline = "Invalid username or password",
                        Detail = "Same as the vulnerable version — the fix only changes what happens to attack-shaped input, " +
                                  "not ordinary failed logins."
                    }
                }
            }
        },

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
            "malformed" => new SimulationResult
            {
                Severity = Severity.Warning,
                Headline = "Login fails — and the real app would likely throw a SQL error",
                Detail = "There's a quote character here, so something is breaking out of the string literal — but " +
                          "without a trailing \"--\" to neutralize whatever the template puts after it (the rest of " +
                          "the WHERE clause), this either errors outright or simply fails to defeat both checks. " +
                          "Close, but SQL still has to parse — \"looks right\" isn't the same as \"is right\"."
            },
            _ => new SimulationResult
            {
                Severity = Severity.Info,
                Headline = "Invalid username or password",
                Detail = "An ordinary failed login — the WHERE clause evaluated to false, same as it would in a safely " +
                          "written app. The vulnerability only shows itself once the input contains SQL syntax."
            }
        },

        HowItWorks =
            "The app builds the query by concatenating raw text into the SQL string instead of treating it as data. " +
            "A quote character (') closes the string literal early, so anything typed after it is parsed as SQL, not as a password. " +
            "'OR 1=1' adds a condition that is always true, and '--' turns the rest of the line into a comment, discarding whatever " +
            "the original query intended to check next. That trailing comment isn't optional flavor — without it, whatever the " +
            "template puts after the injection point (here, the rest of the password check) is still live SQL, and the attempt " +
            "either errors out or quietly fails to fully bypass the login.",

        WhyTheFixWorks =
            "Parameterized queries (sp_executesql, or a parameterized ADO.NET/Dapper/EF command) send the SQL text and the " +
            "parameter values in two separate channels. The database compiles the SQL text once, with @UserName and @PasswordHash " +
            "as placeholders, and only afterward substitutes the values as typed data. A quote character inside the value is just " +
            "a character inside a string — it has no power to change the shape of the query.",

        SamplePayloads = new[]
        {
            "' OR 1=1 --",
            "' OR '1'='1' --",
            "admin'--",
            "' OR 1=1",
            "' or 1=1 --"
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
