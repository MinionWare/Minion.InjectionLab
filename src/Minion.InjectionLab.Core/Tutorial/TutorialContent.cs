using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Tutorial;

/// <summary>
/// The opening wizard: a from-scratch walkthrough of what SQL injection is, why it matters, and
/// how a handful of core techniques work. Deliberately simpler than the full attack catalog — this
/// teaches the underlying concept once, clearly; each catalog entry then covers one technique's
/// full depth (SQL/C#/PowerShell, graded fixes, challenge mode).
/// </summary>
public static class TutorialContent
{
    private static bool ContainsAny(string s, params string[] needles)
    {
        var lower = s.ToLowerInvariant();
        return needles.Any(lower.Contains);
    }

    public static IReadOnlyList<TutorialStep> Create() => new[]
    {
        new TutorialStep
        {
            Title = "What is a SQL injection, really?",
            Paragraphs = new[]
            {
                "Almost every app that remembers anything — logins, products, orders, messages — keeps that " +
                "information in a database, and talks to it using a language called SQL (Structured Query " +
                "Language). A typical request looks like: \"SELECT * FROM Users WHERE Name = 'Sean'\".",
                "Here's the part that matters: a huge number of apps build that sentence by gluing fixed text " +
                "together with whatever you typed into a form. The database never sees a \"form field\" and a " +
                "\"command\" as two different things — by the time your input arrives, it's just more characters " +
                "sitting inside the same sentence. If those characters happen to look like SQL syntax, the " +
                "database can't tell the difference. It just... runs it.",
                "SQL injection is what happens when someone types something into an ordinary textbox that isn't " +
                "a name or a password at all — it's a fragment of a new command, smuggled in through a field " +
                "that was only ever supposed to hold data. This tutorial builds that idea up from nothing, with " +
                "five tiny hands-on examples. By the end you'll be able to look at any \"glue the input into the " +
                "query\" line of code and see exactly where it breaks."
            }
        },
        new TutorialStep
        {
            Title = "The core flaw: your input becomes part of the command",
            Paragraphs = new[]
            {
                "Below is about as simple as a database lookup gets: find the row whose Name column matches " +
                "whatever you typed, wrapped in single quotes because that's how SQL marks text. Type your name " +
                "and watch the SQL update live.",
                "Now try something odd: type a single quote mark (') somewhere in the middle. Nothing scary — " +
                "just that one character. Watch what it does to the sentence below."
            },
            Demo = new TutorialDemo
            {
                FieldLabel = "Your name",
                DefaultValue = "Sean",
                BuildSql = f => $"SELECT * FROM dbo.Users WHERE Name = '{f}';",
                Simulate = (f, hasSyntaxError) => hasSyntaxError
                    ? new SimulationResult
                      {
                          Severity = Severity.Warning,
                          Headline = "SQL Server throws a syntax error here",
                          Detail = "Look closely at the SQL above: your quote mark closed the string early. " +
                                    "Everything after it is no longer \"the value someone typed\" — as far as the " +
                                    "database is concerned, it's fresh SQL syntax, sitting right there in the " +
                                    "middle of a WHERE clause. You didn't type a command on purpose. But you " +
                                    "proved the database can't tell your data from its own code once the two are " +
                                    "glued together. Every technique in this tutorial is just a more useful way " +
                                    "to exploit that exact same gap."
                      }
                    : new SimulationResult
                      {
                          Severity = Severity.Success,
                          Headline = "An ordinary, well-formed lookup",
                          Detail = "Right now, your name slots in neatly between two quote marks as an ordinary " +
                                    "value. The database has no idea it came from a textbox on a web page — it " +
                                    "only ever sees the finished sentence above, and today that sentence happens " +
                                    "to be well-formed."
                      },
                Hint = "Try typing a single quote mark ( ' ) anywhere in the name."
            }
        },
        new TutorialStep
        {
            Title = "Technique 1: the Always-True Trick",
            Paragraphs = new[]
            {
                "The quote mark alone just breaks things — a syntax error, nothing gained. The first real " +
                "technique puts that broken-open string to use: close it early, then glue on a condition that's " +
                "always true, so the WHERE clause passes no matter what the real value was.",
                "This login checks a username and password the same way. Try logging in as alice without her " +
                "real password — using the hint if you want it."
            },
            Demo = new TutorialDemo
            {
                FieldLabel = "Password (trying to log in as \"alice\")",
                DefaultValue = "hunter2",
                BuildSql = f => $"SELECT * FROM dbo.Users WHERE Username = 'alice' AND Password = '{f}';",
                Simulate = (f, hasSyntaxError) =>
                {
                    if (!hasSyntaxError && ContainsAny(f, "' or '1'='1", "' or 1=1"))
                        return new SimulationResult
                        {
                            Severity = Severity.Critical,
                            Headline = "Signed in as alice — no password needed",
                            Detail = "Your text closed the Password string early with a quote, then OR'd in " +
                                      "'1'='1' — a condition that is always, unconditionally true. The WHERE " +
                                      "clause no longer cares what the real password is: (Username = 'alice' AND " +
                                      "Password = '...') OR (always true) is true regardless, so alice's row " +
                                      "comes back. You just logged in as her without ever knowing her password.",
                            AffectedAssets = new[] { "dbo.Users — authentication bypassed for 'alice'" }
                        };
                    if (hasSyntaxError)
                        return new SimulationResult { Severity = Severity.Warning, Headline = "SQL Server throws a syntax error here", Detail = "A stray quote broke the statement, but nothing after it formed a usable condition — the login fails the same way a typo would." };
                    return new SimulationResult { Severity = Severity.Info, Headline = "Access denied", Detail = "Compared against alice's real password, this (almost certainly) doesn't match — exactly how a login is supposed to behave." };
                },
                Hint = "Try: ' OR '1'='1"
            }
        },
        new TutorialStep
        {
            Title = "Technique 2: UNION — asking for someone else's data",
            Paragraphs = new[]
            {
                "A tautology gets you past a check, but it doesn't hand you new data. UNION does: it glues a " +
                "second, completely unrelated SELECT onto the first one, and the database returns both result " +
                "sets as if they were always one — as long as both sides return the same number of columns.",
                "This is an ordinary product search box. It's built to show a product name and a price. See " +
                "what happens when the second SELECT asks for something else entirely."
            },
            Demo = new TutorialDemo
            {
                FieldLabel = "Search for a product",
                DefaultValue = "laptop",
                BuildSql = f => $"SELECT ProductName, Price FROM dbo.Products WHERE ProductName LIKE '%{f}%';",
                Simulate = (f, hasSyntaxError) =>
                {
                    if (!hasSyntaxError && ContainsAny(f, "union"))
                        return new SimulationResult
                        {
                            Severity = Severity.Critical,
                            Headline = "Usernames and password hashes appear in the product list",
                            Detail = "The page only knows how to print two columns, labeled \"ProductName\" and " +
                                      "\"Price\" — it has no idea what's actually inside them. Your UNION SELECT " +
                                      "pulls real usernames and real password hashes out of a totally different " +
                                      "table and hands them to the page wearing the product name and price " +
                                      "columns as a disguise. The page dutifully prints them, confident it's " +
                                      "showing a product.",
                            RowCountLabel = "2 rows leaked from dbo.Users",
                            AffectedAssets = new[] { "dbo.Users — UserName/PasswordHash exposed via UNION" },
                            LeakedRows = new IReadOnlyDictionary<string, string>[]
                            {
                                new Dictionary<string, string> { ["ProductName"] = "admin", ["Price"] = "8846F...(hash)" },
                                new Dictionary<string, string> { ["ProductName"] = "svc_billing", ["Price"] = "2C91A...(hash)" }
                            }
                        };
                    if (hasSyntaxError)
                        return new SimulationResult { Severity = Severity.Warning, Headline = "SQL Server throws a syntax error here", Detail = "UNION needs a matching column count and a closing comment on the template's own trailing quote — this attempt doesn't parse yet." };
                    return new SimulationResult { Severity = Severity.Success, Headline = "Ordinary search results", Detail = "The catalog gets searched normally — nothing unusual in the result." };
                },
                Hint = "Try: nonexistent' UNION SELECT Username, Password FROM dbo.Users--"
            }
        },
        new TutorialStep
        {
            Title = "Technique 3: Blind injection — when there's nothing to see",
            Paragraphs = new[]
            {
                "UNION only works if the page prints extra columns back to you. A well-locked-down page might " +
                "show nothing but \"Found\" or \"Not found\" — no data, ever, no matter what you ask it. Does " +
                "that make it safe? Not quite: even a plain yes/no is a channel you can exploit, one true/false " +
                "question at a time.",
                "Order 1007 genuinely exists. Try forcing the lookup to claim it doesn't, by adding a condition " +
                "that's always false."
            },
            Demo = new TutorialDemo
            {
                FieldLabel = "Order ID",
                DefaultValue = "1007",
                BuildSql = f => $"SELECT COUNT(*) FROM dbo.Orders WHERE OrderId = {f};",
                Simulate = (f, hasSyntaxError) =>
                {
                    if (!hasSyntaxError && ContainsAny(f, "and 1=2", "or 1=2"))
                        return new SimulationResult
                        {
                            Severity = Severity.Critical,
                            Headline = "\"Not found\" — even though order 1007 is completely real",
                            Detail = "Forcing the condition false proves your input is being evaluated as live " +
                                      "SQL, not just compared as a plain number. That one bit of proof is all an " +
                                      "attacker needs: ask \"is the first letter of the admin password 'A'?\" as " +
                                      "its own true/false condition, read Found/Not found, then try 'B', then " +
                                      "'C' — and reconstruct an entire password one character at a time without " +
                                      "ever seeing a single row of real data."
                        };
                    if (!hasSyntaxError && ContainsAny(f, "and 1=1", "or 1=1"))
                        return new SimulationResult
                        {
                            Severity = Severity.Warning,
                            Headline = "\"Found\" — the input is reaching the SQL engine as code",
                            Detail = "A condition that's always true doesn't change what you can see, but it " +
                                      "already proves the input reached the SQL engine as code. That's step one " +
                                      "of the same trick; forcing it false (try replacing 1=1 with 1=2) is what " +
                                      "makes it undeniable."
                        };
                    if (hasSyntaxError)
                        return new SimulationResult { Severity = Severity.Warning, Headline = "SQL Server throws a syntax error here", Detail = "OrderId is a number, not text — whatever you added here doesn't parse as part of that condition." };
                    return new SimulationResult { Severity = Severity.Success, Headline = "\"Found\"", Detail = "An ordinary, boring lookup. Order 1007 exists, nothing unusual to report yet." };
                },
                Hint = "Try: 1007 AND 1=2"
            }
        },
        new TutorialStep
        {
            Title = "Technique 4: Stacked queries — smuggling in a second statement",
            Paragraphs = new[]
            {
                "Every technique so far reshapes the one statement that was already there. A semicolon does " +
                "something more drastic: it ends that statement completely. Whatever comes after isn't a tweak " +
                "to the WHERE clause anymore — it's a brand new, independent command, and plenty of drivers and " +
                "apps will happily run a whole batch of semicolon-separated statements back to back.",
                "This is an internal order-lookup tool. See what riding a second statement in after the " +
                "semicolon can do."
            },
            Demo = new TutorialDemo
            {
                FieldLabel = "Order ID",
                DefaultValue = "1007",
                BuildSql = f => $"SELECT * FROM dbo.Orders WHERE OrderId = {f};",
                Simulate = (f, hasSyntaxError) =>
                {
                    if (f.Contains(';') && ContainsAny(f, "drop", "delete", "insert", "update", "exec"))
                        return new SimulationResult
                        {
                            Severity = Severity.Critical,
                            Headline = "A second, independent statement just ran",
                            Detail = "That semicolon closed the lookup completely. Everything after it is a " +
                                      "second, fully independent SQL statement — not a modified condition, a " +
                                      "whole new command — and it runs with exactly the same database " +
                                      "permissions the app itself has. No quote-escaping trick stops this one, " +
                                      "because the first statement was never \"broken out of\"; it was simply " +
                                      "finished early, on purpose.",
                            AffectedAssets = new[] { "dbo.Orders — stacked statement executed with app's own permissions" }
                        };
                    if (hasSyntaxError)
                        return new SimulationResult { Severity = Severity.Warning, Headline = "SQL Server throws a syntax error here", Detail = "OrderId is a number, not text — whatever's here doesn't parse as a valid condition." };
                    return new SimulationResult { Severity = Severity.Success, Headline = "Ordinary lookup", Detail = "Order 1007, nothing else attached to it." };
                },
                Hint = "Try: 1007; DROP TABLE Orders--"
            }
        },
        new TutorialStep
        {
            Title = "Why this keeps happening",
            Paragraphs = new[]
            {
                "Every example above comes down to the same root cause: a command and the data inside it were " +
                "written in the same language, then mixed together as plain text before anyone decided which " +
                "parts were safe. That's not a quirk of SQL specifically — the exact same flaw shows up anywhere " +
                "an app builds a command string by hand: operating-system commands, LDAP queries, even some " +
                "NoSQL databases. SQL injection is simply the most common, best-understood example of a much " +
                "bigger family of \"injection\" bugs.",
                "It also keeps happening because it's easy to miss: concatenating a string together often just " +
                "looks like normal code. There's no red flag at the point where the bug is introduced — only at " +
                "the point where someone sends it the wrong input."
            }
        },
        new TutorialStep
        {
            Title = "The fix: treat data as data",
            Paragraphs = new[]
            {
                "Every technique above depends on one thing: your text gets woven into the SQL before the " +
                "database ever sees it, so the database has to re-interpret the whole sentence from scratch — " +
                "quotes, semicolons and all. The fix removes that step entirely.",
                "A parameterized query sends the command text and the value separately: \"SELECT * FROM Users " +
                "WHERE Name = @Name\", plus @Name = \"whatever you typed\" as its own, clearly labeled piece of " +
                "data. The database compiles the command shape first — @Name is just a placeholder — and only " +
                "afterward substitutes your value in as a literal, inert piece of data. A quote mark, a " +
                "semicolon, the word UNION — none of it is ever re-parsed as SQL, because by the time your text " +
                "shows up, the sentence's shape has already been decided.",
                "That's the one idea behind almost every real fix you'll see in this app: not \"detect bad " +
                "words\" (which the Partial fixes in this app show you how to defeat), but \"never let input " +
                "change what the command means\" in the first place."
            }
        },
        new TutorialStep
        {
            Title = "You're ready — go explore",
            Paragraphs = new[]
            {
                "That's the whole concept. Everything else in Minion.InjectionLab is the same idea applied to " +
                "more realistic, more specific situations — pick any attack from the list on the left and " +
                "you'll get the full picture: the real SQL, the C# and PowerShell that would produce it, a " +
                "side-by-side of a weak \"Partial\" fix against the real \"Best\" fix (and exactly what the weak " +
                "one still misses), and a \"Try it yourself\" challenge mode with hints if you get stuck.",
                "The Difficulty selector in the top-left changes how forgiving the weak fixes are — Beginner " +
                "lets obvious attempts slip through easily, Expert makes you work harder to find the gap. " +
                "There's no scoring and nothing here ever touches a real database — it's all just text, built " +
                "live so you can see exactly how it's put together.",
                "Have fun breaking things."
            }
        }
    };
}
