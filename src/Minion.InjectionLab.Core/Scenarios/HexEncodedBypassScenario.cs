using System.Text.RegularExpressions;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>Hex-encoded literal bypass: a filter that only inspects the characters you typed never
/// sees the characters that only exist after SQL Server decodes a hex literal.</summary>
public static class HexEncodedBypassScenario
{
    private const string AllowedCommand = "select @@version";
    private const string Baseline = "0x53454c45435420404056455253494f4e3b"; // SELECT @@VERSION;

    private static string? TryDecodeHex(string s)
    {
        s = s.Trim();
        if (!s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) return null;
        var hex = s[2..];
        if (hex.Length == 0 || hex.Length % 2 != 0 || !Regex.IsMatch(hex, "^[0-9A-Fa-f]+$")) return null;
        try
        {
            var bytes = System.Convert.FromHexString(hex);
            return System.Text.Encoding.ASCII.GetString(bytes);
        }
        catch
        {
            return null;
        }
    }

    private static bool IsAllowed(string? effective) =>
        (effective ?? string.Empty).Trim().TrimEnd(';').Equals(AllowedCommand, StringComparison.OrdinalIgnoreCase);

    /// <summary>normal (the one allowed command, typed or hex-encoded) / quoted (a literal quote,
    /// the classic direct attempt) / bypass (valid hex decoding to anything else) / malformed
    /// (neither hex nor the allowed command, nothing coherent for EXEC to run).</summary>
    private static string Classify(IReadOnlyDictionary<string, string> f)
    {
        var raw = f["command"];
        var decoded = TryDecodeHex(raw);
        var effective = decoded ?? raw;
        if (IsAllowed(effective)) return "normal";
        if (decoded != null) return "bypass";
        if (raw.Contains('\'')) return "quoted";
        return "malformed";
    }

    public static AttackScenario Create() => new()
    {
        Id = "hex-encoded-bypass",
        Category = AttackCategory.DeliveryObfuscation,
        Title = "Hex-Encoded Literal Bypass",
        Premise = "An internal diagnostics tool runs whatever gets typed in via EXEC() — support staff can type " +
                  "the command directly, or as a 0x-prefixed hex literal, a completely ordinary SQL Server feature " +
                  "for representing binary data. EXEC() will run a hex literal exactly as if it were the decoded " +
                  "text — quotes, keywords and all.",
        MockAppLabel = "Internal Tools — Run Diagnostic Command",
        BaselineValues = new Dictionary<string, string> { ["command"] = Baseline },
        Fields = new[] { new FormField { Key = "command", Label = "Command (plain text or 0x-hex)", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Allowed command", Icon = "✅", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "malformed", Label = "Broken syntax", Icon = "⚠", Kind = PathKind.Neutral },
            new DecisionPathDef { Key = "quoted", Label = "Direct quote attempt", Icon = "🔓", Kind = PathKind.Malicious },
            new DecisionPathDef { Key = "bypass", Label = "Hex-encoded bypass", Icon = "🧬", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f => $"EXEC({f["command"]});",

        BuildVulnerableCSharp = f =>
            "var sql = $\"EXEC({command})\";\n" +
            "using var cmd = new SqlCommand(sql, connection);\n" +
            "cmd.ExecuteNonQuery(); // whatever the hex decodes to runs exactly like typed SQL text",

        BuildVulnerablePowerShell = f =>
            "$sql = \"EXEC($command)\"\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql",

        // Two real fixes, not equally complete: blocking the literal quote character (looks like
        // a fix, isn't one against hex) vs. validating the DECODED command against an allow-list.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Reject input containing a quote ( ' )",
                Grade = FixGrade.Partial,
                Gap = "Stops anyone from typing a literal quote character — but a hex-encoded payload contains " +
                      "zero quote characters for the filter to catch. The quote only exists after SQL Server " +
                      "decodes the hex, which happens after this filter already approved the request.",
                BuildSql = (f, _) =>
                {
                    bool blocked = f["command"].Contains('\'');
                    return blocked ? "-- Request rejected by the application; no SQL was ever built." : $"EXEC({f["command"]});";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["command"].Contains('\'');
                    var guard = "if (command.Contains('\\''))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var sql = $\"EXEC({command})\";\n" +
                                     "using var cmd = new SqlCommand(sql, connection);\n" +
                                     "cmd.ExecuteNonQuery();";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["command"].Contains('\'');
                    var guard = "if ($command.Contains(\"'\")) { throw \"rejected\" }\n\n";
                    var vulnerable = "$sql = \"EXEC($command)\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query $sql";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, _) => Classify(f) switch
                {
                    "quoted" => new SimulationResult { Severity = Severity.Blocked, Headline = "Request rejected — contains a quote", Detail = "The literal quote in this attempt is exactly what the filter was built to catch." },
                    "bypass" => new SimulationResult
                    {
                        Severity = Severity.Critical,
                        Headline = "The hex-encoded command still runs — the filter never saw a single quote",
                        Detail = "This payload never contains a quote character at all — only hex digits. The filter " +
                                  "approves it, and SQL Server decodes and executes the real command afterward, " +
                                  "completely unaffected by a check that was already finished by then.",
                        AffectedAssets = new[] { "dbo.Users — PasswordHash column read out through a \"diagnostics\" command" }
                    },
                    "malformed" => new SimulationResult { Severity = Severity.Warning, Headline = "Syntax error", Detail = "Neither a recognized hex literal nor the allowed command — EXEC() has nothing valid to run." },
                    _ => new SimulationResult { Severity = Severity.Success, Headline = "SQL Server version returned", Detail = "The one allowed diagnostic command, the filter never engages." }
                }
            },
            new FixOption
            {
                Label = "✓ Decode first, then allow-list the command",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                {
                    var decoded = TryDecodeHex(f["command"]);
                    var effective = decoded ?? f["command"];
                    bool allowed = IsAllowed(effective);
                    return allowed
                        ? "-- Decoded first (if it was hex), THEN checked against the allow-list:\n" +
                          "EXEC('SELECT @@VERSION;');  -- only this exact command is ever allowed to reach EXEC()"
                        : "-- Decoded first (if it was hex), then rejected: the result isn't the one allow-listed command.\n" +
                          "-- No SQL was built.";
                },
                BuildCSharp = f =>
                    "// Decode first (if hex), THEN compare the real, intended command against an allow-list —\n" +
                    "// never trust the encoding, trust what it actually says.\n" +
                    "var decoded = command.StartsWith(\"0x\") ? DecodeHex(command) : command;\n" +
                    "if (!decoded.Trim().TrimEnd(';').Equals(\"SELECT @@VERSION\", StringComparison.OrdinalIgnoreCase))\n" +
                    "    throw new SecurityException();\n\n" +
                    "using var cmd = new SqlCommand(\"EXEC('SELECT @@VERSION;')\", connection);\n" +
                    "cmd.ExecuteNonQuery();",
                BuildPowerShell = f =>
                    "# Decode first (if hex), THEN compare against an allow-list\n" +
                    "$decoded = if ($command.StartsWith('0x')) { Convert-HexToString $command } else { $command }\n" +
                    "if ($decoded.Trim().TrimEnd(';') -ne 'SELECT @@VERSION') { throw \"rejected\" }\n\n" +
                    "Invoke-Sqlcmd -ServerInstance $server -Database $db -Query \"EXEC('SELECT @@VERSION;')\"",
                Simulate = (f, _) => Classify(f) == "normal"
                    ? new SimulationResult { Severity = Severity.Success, Headline = "SQL Server version returned", Detail = "The one allow-listed command, unaffected by the fix — whether typed plainly or hex-encoded." }
                    : new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "Rejected — doesn't decode to the allow-listed command",
                        Detail = "The encoding never matters here: hex is decoded first, and whatever comes out — quoted " +
                                  "injection attempt or hex payload alike — is compared against the one command this tool " +
                                  "is allowed to run. Anything else is rejected before EXEC() ever sees it."
                    }
            }
        },

        SimulateVulnerable = f => Classify(f) switch
        {
            "normal" => new SimulationResult { Severity = Severity.Success, Headline = "SQL Server version returned", Detail = "Ordinary, intended use of the diagnostics tool." },
            "malformed" => new SimulationResult { Severity = Severity.Warning, Headline = "Syntax error", Detail = "EXEC() needs a string expression, a variable, or a valid hex/binary literal — this is none of those." },
            "quoted" => new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "Arbitrary SQL executes — no filter in place at all",
                Detail = "With no protection whatsoever, typing the attack directly works exactly as plainly as any other unfiltered injection.",
                AffectedAssets = new[] { "dbo.Users — PasswordHash column read out through a \"diagnostics\" command" }
            },
            _ => new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "The hex-encoded command runs — decoded and executed exactly as typed",
                Detail = "EXEC() doesn't care that the real command only exists as hex digits in the request — SQL Server " +
                          "decodes it first, then runs it precisely as if it had been typed out in full, quotes and all.",
                AffectedAssets = new[] { "dbo.Users — PasswordHash column read out through a \"diagnostics\" command" }
            }
        },

        HowItWorks =
            "SQL Server lets you write a binary/varbinary value as 0x followed by hex digits — an entirely " +
            "ordinary feature with nothing malicious about it on its own. EXEC() accepts that value and runs it " +
            "as a command exactly as if you'd typed the decoded text, quotes and keywords included. A filter that " +
            "inspects the raw characters a user typed never sees any of those quotes or keywords, because they " +
            "don't exist yet at the point the filter runs — only after SQL Server's own decode step, which " +
            "happens later and which the filter never gets to see.",

        WhyTheFixWorks =
            "The fix stops asking \"does the raw text look dangerous\" and starts asking \"does the actual, " +
            "decoded command match what this tool is supposed to run, at all\" — an allow-list check performed " +
            "after decoding, not a blacklist check performed before it.",

        SamplePayloads = new[]
        {
            Baseline,
            "0x53454c45435420557365726e616d652c2050617373776f7264486173682046524f4d2064626f2e55736572733b",
            "'; EXEC xp_cmdshell('whoami'); --"
        },

        ChallengeGoal = "Get the diagnostics tool to run a completely different command than the one it's meant for, despite the quote filter.",
        Hints = new[]
        {
            "The filter only looks at the literal characters you type — what if the real command never appears as text at all until SQL Server decodes it?",
            "SQL Server treats a 0x-prefixed value as binary data, and EXEC() will run it exactly as if you'd typed the decoded text."
        },
        ChallengeAnswer = "0x53454c45435420557365726e616d652c2050617373776f7264486173682046524f4d2064626f2e55736572733b",

        TerminologyNote = "Named for the encoding it abuses, not a new SQL mechanism: SQL Server already lets you " +
                           "write binary data as 0x followed by hex digits, and EXEC() will run that value as a " +
                           "command exactly as if you'd typed the decoded text out in full. A filter that only " +
                           "inspects the characters you typed never sees any of them, because they only exist " +
                           "after SQL Server's own decode step.",
        References = new[]
        {
            new ExternalReference { Label = "GoSecure — AWS WAF clients left vulnerable to SQL injection via MSSQL's EXEC() design", Url = "https://gosecure.ai/blog/2023/06/21/aws-waf-clients-left-vulnerable-to-sql-injection-due-to-unorthodox-mssql-design-choice/" },
            new ExternalReference { Label = "PortSwigger — Obfuscating attacks using encodings", Url = "https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings" },
            new ExternalReference { Label = "OWASP — SQL Injection Bypassing WAF", Url = "https://wiki.owasp.org/index.php/SQL_Injection_Bypassing_WAF" }
        }
    };
}
