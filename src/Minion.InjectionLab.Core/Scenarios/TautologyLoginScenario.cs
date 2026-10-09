using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>
/// The canonical "Bobby Tables" login bypass: ' OR 1=1 --
/// </summary>
public static class TautologyLoginScenario
{
    public static AttackScenario Create() => new()
    {
        Id = "tautology-login",
        Category = AttackCategory.ClassicInBand,
        Title = "Tautology / Login Bypass",
        Premise = "A login form checks a username and password against the Users table. " +
                  "The query is built by gluing the two text boxes straight into the WHERE clause.",
        Fields = new[]
        {
            new FormField { Key = "username", Label = "Username", DefaultValue = "admin", Placeholder = "username" },
            new FormField { Key = "password", Label = "Password", DefaultValue = "wrongpassword", Placeholder = "password", IsPassword = true }
        },

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

        SimulateVulnerable = f =>
        {
            var combined = (f["username"] + " " + f["password"]).ToLowerInvariant();
            bool looksLikeTautology = combined.Contains("or 1=1") || combined.Contains("or '1'='1")
                                       || combined.Contains("or 1 = 1") || (combined.Contains("--") && combined.Contains("or "));

            if (looksLikeTautology)
            {
                return new SimulationResult
                {
                    Severity = Severity.Critical,
                    Headline = "Authentication bypassed — every row in Users matches",
                    Detail = "The injected 'OR 1=1' makes the WHERE clause true for every row, and the trailing " +
                              "'--' comments out the rest of the original query (including the password check). " +
                              "The app receives the first row back — typically the first account in the table — and logs that user in " +
                              "without ever knowing a valid password."
                };
            }

            return new SimulationResult
            {
                Severity = Severity.Info,
                Headline = "No match (unless the credentials happen to be correct)",
                Detail = "The concatenated query runs as plain SQL. With ordinary input it behaves like a normal login " +
                          "check — the vulnerability only shows itself once the input contains SQL syntax."
            };
        },

        SimulateFixed = f => new SimulationResult
        {
            Severity = Severity.Blocked,
            Headline = "Treated as a literal string — no rows match",
            Detail = "Because the values are sent as parameters, the database never re-parses them as SQL. " +
                      "\"' OR 1=1 --\" is just a username nobody has, so the WHERE clause evaluates to false for every row. " +
                      "The login fails exactly the way it should."
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
