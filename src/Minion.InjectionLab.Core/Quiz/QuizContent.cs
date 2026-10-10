using System.Text.RegularExpressions;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Quiz;

/// <summary>
/// Three capstone missions, one per difficulty — open-ended "devise your own attack" grading
/// instead of per-scenario Challenge Mode's single canonical answer. Expert is a genuine two-stage
/// recon-then-exploit mission: you don't know the schema going in, you have to find it.
/// </summary>
public static class QuizContent
{
    private static bool Rx(string input, string pattern) => Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase);

    public static IReadOnlyList<QuizMission> All { get; } = new[]
    {
        BeginnerMission(),
        IntermediateMission(),
        ExpertMission()
    };

    // ---------------------------------------------------------------- Beginner

    private static QuizMission BeginnerMission() => new()
    {
        Id = "lazy-login",
        Difficulty = QuizDifficulty.Beginner,
        Title = "The Lazy Login",
        Briefing = "An internal tool's login form checks a username and password the same way every other " +
                   "unprotected login in this app does. Nobody told you which technique to use this time.",
        Goal = "Log in as \"admin\" without ever knowing the real password. Any technique that genuinely works counts.",
        Fields = new[]
        {
            new FormField { Key = "username", Label = "Username", DefaultValue = "admin" },
            new FormField { Key = "password", Label = "Password", DefaultValue = "" }
        },
        BaselineValues = new Dictionary<string, string> { ["username"] = "admin", ["password"] = "" },

        BuildSql = f => $"SELECT * FROM dbo.Users WHERE Username = '{f["username"]}' AND Password = '{f["password"]}';",
        BuildCSharp = f =>
            "var sql = $\"SELECT * FROM dbo.Users WHERE Username = '{username}' AND Password = '{password}'\";\n" +
            "using var cmd = new SqlCommand(sql, connection);",
        BuildPowerShell = f =>
            "$sql = \"SELECT * FROM dbo.Users WHERE Username = '$username' AND Password = '$password'\"",

        Evaluate = (f, _) =>
        {
            var u = f["username"];
            var p = f["password"];
            bool tautology = Rx(u, @"'\s*or\s*'?1'?\s*=\s*'?1") || Rx(p, @"'\s*or\s*'?1'?\s*=\s*'?1");
            bool truncation = Rx(u, @"admin'\s*(--|/\*)");
            bool unionBypass = Rx(u, @"union\s+select");

            if (tautology)
                return new QuizOutcome { Succeeded = true, Headline = "Logged in as admin", Detail = "An always-true condition made the WHERE clause pass regardless of the real password — the tautology technique, applied without being told to use it." };
            if (truncation)
                return new QuizOutcome { Succeeded = true, Headline = "Logged in as admin", Detail = "A comment marker erased the password check entirely — comment truncation, applied without being told to use it." };
            if (unionBypass)
                return new QuizOutcome { Succeeded = true, Headline = "Logged in as admin", Detail = "A UNION'd row with a known password hash would also work here, if the app then compared your submitted password against it — accepted as a valid approach." };
            return new QuizOutcome { Succeeded = false, Headline = "Login failed", Detail = "That didn't bypass the check. Think back to the Classic/In-Band category — two different techniques both solve this." };
        },

        Hints = new[]
        {
            "You've already learned at least two ways to beat a login check without the real password.",
            "One makes the check pass anyway. The other erases the check entirely.",
            "Try: ' OR '1'='1 — or: admin'--"
        }
    };

    // ---------------------------------------------------------------- Intermediate

    private static QuizMission IntermediateMission() => new()
    {
        Id = "customer-list-leak",
        Difficulty = QuizDifficulty.Intermediate,
        Title = "The Customer List Leak",
        Briefing = "An internal CRM's customer search looks up one customer by exact name. You don't have a " +
                   "specific customer in mind — you want every row in the table.",
        Goal = "Make this single-customer lookup return every row in the Customers table.",
        Fields = new[] { new FormField { Key = "name", Label = "Customer name", DefaultValue = "Acme Corp" } },
        BaselineValues = new Dictionary<string, string> { ["name"] = "Acme Corp" },

        BuildSql = f => $"SELECT CustomerName, Email FROM dbo.Customers WHERE CustomerName = '{f["name"]}';",
        BuildCSharp = f =>
            "var sql = $\"SELECT CustomerName, Email FROM dbo.Customers WHERE CustomerName = '{name}'\";\n" +
            "using var cmd = new SqlCommand(sql, connection);",
        BuildPowerShell = f => "$sql = \"SELECT CustomerName, Email FROM dbo.Customers WHERE CustomerName = '$name'\"",

        Evaluate = (f, _) =>
        {
            var s = f["name"];
            bool tautology = Rx(s, @"'\s*or\s*'?1'?\s*=\s*'?1");
            bool union = Rx(s, @"union\s+select");
            if (tautology || union)
                return new QuizOutcome
                {
                    Succeeded = true,
                    Headline = "Every row in dbo.Customers returned",
                    Detail = tautology
                        ? "An always-true condition made the exact-match WHERE clause match every row instead of just one."
                        : "A UNION'd SELECT against the same table returns the same effect here — a valid, if slightly roundabout, way to dump everything."
                };
            return new QuizOutcome { Succeeded = false, Headline = "One customer, or none, returned", Detail = "This still filters down to a single match (or nothing). You need the WHERE clause to stop filtering at all." };
        },

        Hints = new[]
        {
            "This is an exact-match WHERE clause — what condition would make it match literally everything?",
            "Try: Acme Corp' OR '1'='1"
        }
    };

    // ---------------------------------------------------------------- Expert

    private static readonly HashSet<string> KnownTables = new() { "payments", "customers", "auditlog" };
    private static readonly HashSet<string> PaymentsColumns = new() { "paymentid", "cardholdername", "creditcardnumber", "amount" };

    private static QuizMission ExpertMission() => new()
    {
        Id = "steal-the-payment-data",
        Difficulty = QuizDifficulty.Expert,
        Title = "Steal the Payment Data",
        Briefing = "An internal \"search payments\" tool takes a reference number and returns a payment ID and " +
                   "amount. That's all you know. No schema, no table names, no column names — you have to find " +
                   "them yourself before you can steal anything.",
        Goal = "Discover the real schema behind this endpoint, then exfiltrate real credit card numbers through it. " +
               "No hints are given at this difficulty, and the answer can't be revealed.",
        Fields = new[] { new FormField { Key = "reference", Label = "Payment reference", DefaultValue = "PMT-5001" } },
        BaselineValues = new Dictionary<string, string> { ["reference"] = "PMT-5001" },

        BuildSql = f => $"SELECT PaymentId, Amount FROM dbo.Payments WHERE Reference = '{f["reference"]}';",
        BuildCSharp = f =>
            "var sql = $\"SELECT PaymentId, Amount FROM dbo.Payments WHERE Reference = '{reference}'\";\n" +
            "using var cmd = new SqlCommand(sql, connection);",
        BuildPowerShell = f => "$sql = \"SELECT PaymentId, Amount FROM dbo.Payments WHERE Reference = '$reference'\"",

        Evaluate = (f, discovered) =>
        {
            var s = f["reference"].ToLowerInvariant();
            bool isUnion = Rx(s, @"union\s+select");

            // Stage 4: the actual theft — UNION selecting CreditCardNumber (and anything else)
            // straight out of dbo.Payments.
            if (isUnion && s.Contains("creditcardnumber") && s.Contains("dbo.payments"))
                return new QuizOutcome
                {
                    Succeeded = true,
                    Headline = "Real credit card numbers returned, disguised as payment results",
                    Detail = "You found the table, found the column, and pulled it straight out through the " +
                              "search box. This is the complete chain: recon, then exploit."
                };

            // Stage 3: enumerate columns of a specific discovered table.
            var columnsOfMatch = Regex.Match(s, @"information_schema\.columns.*table_name\s*=\s*'(\w+)'");
            if (isUnion && columnsOfMatch.Success)
            {
                var table = columnsOfMatch.Groups[1].Value.ToLowerInvariant();
                if (table == "payments")
                {
                    var facts = PaymentsColumns.Select(c => $"column: dbo.Payments.{c}").ToList();
                    return new QuizOutcome
                    {
                        Succeeded = false,
                        Headline = "Columns discovered: PaymentId, CardHolderName, CreditCardNumber, Amount",
                        Detail = "dbo.Payments has a CreditCardNumber column. You know what to do with that.",
                        NewlyDiscovered = facts
                    };
                }
                return new QuizOutcome { Succeeded = false, Headline = $"No table named '{table}' found", Detail = "That table doesn't exist in this schema — check what you discovered in the table-enumeration step." };
            }

            // Stage 2: enumerate table names.
            if (isUnion && s.Contains("information_schema.tables"))
            {
                var facts = KnownTables.Select(t => $"table: dbo.{char.ToUpperInvariant(t[0])}{t[1..]}").ToList();
                return new QuizOutcome
                {
                    Succeeded = false,
                    Headline = "Tables discovered: Payments, Customers, AuditLog",
                    Detail = "Now find out what columns dbo.Payments actually has.",
                    NewlyDiscovered = facts
                };
            }

            // Stage 1: work out the column count with NULLs.
            if (isUnion && Rx(s, @"select\s+null\s*,\s*null\b"))
                return new QuizOutcome
                {
                    Succeeded = false,
                    Headline = "No error — this query returns exactly 2 columns",
                    Detail = "Good, the column count is confirmed. Now find out what tables actually exist — " +
                              "SQL Server keeps a catalog of its own schema you can query like any other table.",
                    NewlyDiscovered = new[] { "column count: 2" }
                };

            if (isUnion)
                return new QuizOutcome { Succeeded = false, Headline = "Query failed or returned nothing useful", Detail = "A UNION needs the right number of columns, and you're reading from a table or view that may not exist. Start smaller." };

            return new QuizOutcome { Succeeded = false, Headline = "Ordinary lookup", Detail = "This hasn't tried to break out of the query yet. You already know several ways to do that from the catalog." };
        },

        Hints = null
    };
}
