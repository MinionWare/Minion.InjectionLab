using System.Text.RegularExpressions;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Core.Scenarios;

/// <summary>SQL Agent CmdExec job steps hand their command string straight to the Windows shell —
/// this is OS command injection reached through a SQL Server feature, not SQL injection itself.</summary>
public static class SqlAgentCmdExecScenario
{
    private const string Baseline = "nightly_backup.bak";
    private static readonly Regex SafeFileName = new(@"^[A-Za-z0-9_\-]+\.bak$", RegexOptions.Compiled);

    private static bool ContainsAny(string s, params string[] needles) => needles.Any(s.Contains);

    private static string Classify(IReadOnlyDictionary<string, string> f)
        => ContainsAny(f["filename"], "&", "|", "\"") ? "escalation" : "normal";

    public static AttackScenario Create() => new()
    {
        Id = "sql-agent-cmdexec",
        Category = AttackCategory.SqlServerAgentAndJobs,
        Title = "SQL Agent CmdExec Job Step Escalation",
        Premise = "An internal \"Schedule a backup\" admin page lets a user name the backup file, which gets " +
                  "woven into a SQL Server Agent job step that runs as a CmdExec (operating-system command) step. " +
                  "CmdExec steps hand their command string straight to the Windows shell, running as the SQL " +
                  "Server Agent service account or a configured proxy — very often far more privileged than the " +
                  "web app's own low-privileged SQL login.",
        MockAppLabel = "Internal Tools — Schedule a Backup",
        BaselineValues = new Dictionary<string, string> { ["filename"] = Baseline },
        Fields = new[] { new FormField { Key = "filename", Label = "Backup file name", DefaultValue = Baseline } },

        DecisionPaths = new[]
        {
            new DecisionPathDef { Key = "normal", Label = "Ordinary file name", Icon = "💾", Kind = PathKind.Safe },
            new DecisionPathDef { Key = "escalation", Label = "OS command reaches cmd.exe", Icon = "🧨", Kind = PathKind.Malicious }
        },
        ClassifyInput = Classify,

        BuildVulnerableSql = f =>
            "EXEC msdb.dbo.sp_add_jobstep\n" +
            "    @job_name = N'NightlyBackup',\n" +
            "    @step_name = N'RunBackup',\n" +
            "    @subsystem = N'CmdExec',\n" +
           $"    @command = N'sqlcmd -Q \"BACKUP DATABASE Sales TO DISK=''C:\\Backups\\{f["filename"]}''\"';",

        BuildVulnerableCSharp = f =>
            "var command = $\"sqlcmd -Q \\\"BACKUP DATABASE Sales TO DISK=''C:\\\\Backups\\\\{filename}''\\\"\";\n" +
            "using var cmd = new SqlCommand(\"EXEC msdb.dbo.sp_add_jobstep @job_name, @step_name, @subsystem='CmdExec', @command\", connection);\n" +
            "cmd.Parameters.AddWithValue(\"@command\", command); // the OS command string itself is still hand-built\n" +
            "cmd.ExecuteNonQuery();",

        BuildVulnerablePowerShell = f =>
            "$command = \"sqlcmd -Q `\"BACKUP DATABASE Sales TO DISK=''C:\\Backups\\$filename''`\"\"\n" +
            "$sql = \"EXEC msdb.dbo.sp_add_jobstep @job_name=N'NightlyBackup', @step_name=N'RunBackup', @subsystem=N'CmdExec', @command=N'$command'\"\n" +
            "Invoke-Sqlcmd -ServerInstance $server -Database msdb -Query $sql",

        // Two real fixes, not equally complete: blocking two shell metacharacters (looks like a
        // fix, isn't one — cmd.exe has more than two) vs. avoiding the shell-out entirely.
        Fixes = new[]
        {
            new FixOption
            {
                Label = "⚠ Reject file names containing \"&\" or \"\\\"\"",
                Grade = FixGrade.Partial,
                Gap = "Blocks the two characters this particular attack sample happens to use — but cmd.exe " +
                      "treats several characters specially (|, &, &&, ||, >, <, ^, %), and this filter only " +
                      "checks two of them. A payload built with the pipe character instead still reaches the " +
                      "shell untouched.",
                BuildSql = (f, _) =>
                {
                    bool blocked = f["filename"].Contains('&') || f["filename"].Contains('"');
                    return blocked
                        ? "-- Request rejected by the application; no job step was ever created."
                        : "EXEC msdb.dbo.sp_add_jobstep\n    @job_name = N'NightlyBackup',\n    @step_name = N'RunBackup',\n    @subsystem = N'CmdExec',\n" +
                         $"    @command = N'sqlcmd -Q \"BACKUP DATABASE Sales TO DISK=''C:\\Backups\\{f["filename"]}''\"';";
                },
                BuildCSharp = f =>
                {
                    bool blocked = f["filename"].Contains('&') || f["filename"].Contains('"');
                    var guard = "if (filename.Contains('&') || filename.Contains('\"'))\n    throw new SecurityException();\n\n";
                    var vulnerable = "var command = $\"sqlcmd -Q \\\"BACKUP DATABASE Sales TO DISK=''C:\\\\Backups\\\\{filename}''\\\"\";\n" +
                                     "using var cmd = new SqlCommand(\"EXEC msdb.dbo.sp_add_jobstep ...\", connection);\n" +
                                     "cmd.Parameters.AddWithValue(\"@command\", command);\n" +
                                     "cmd.ExecuteNonQuery();";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                BuildPowerShell = f =>
                {
                    bool blocked = f["filename"].Contains('&') || f["filename"].Contains('"');
                    var guard = "if ($filename.Contains('&') -or $filename.Contains('\"')) { throw \"rejected\" }\n\n";
                    var vulnerable = "$command = \"sqlcmd -Q `\"BACKUP DATABASE Sales TO DISK=''C:\\Backups\\$filename''`\"\"\n" +
                                      "Invoke-Sqlcmd -ServerInstance $server -Database msdb -Query \"EXEC msdb.dbo.sp_add_jobstep ...\"";
                    return blocked ? guard.TrimEnd() : guard + vulnerable;
                },
                Simulate = (f, _) =>
                {
                    bool filterCaughtIt = f["filename"].Contains('&') || f["filename"].Contains('"');
                    if (Classify(f) != "escalation")
                        return new SimulationResult { Severity = Severity.Success, Headline = "Backup job step created", Detail = "Ordinary file name, the filter never engages." };
                    if (filterCaughtIt)
                        return new SimulationResult { Severity = Severity.Blocked, Headline = "Request rejected — contains a blocked character", Detail = "This specific attempt used one of the two characters the filter checks for." };
                    return new SimulationResult
                    {
                        Severity = Severity.Critical,
                        Headline = "A new Windows administrator account was just created",
                        Detail = "This payload uses the pipe character instead of \"&\" — which this filter never checks for — " +
                                  "so cmd.exe still chains the extra commands straight after the backup, running as whatever " +
                                  "account the CmdExec step uses.",
                        AffectedAssets = new[]
                        {
                            "New local administrator account created on the database server's OS",
                            "Full OS-level compromise via the SQL Server Agent service/proxy account"
                        }
                    };
                }
            },
            new FixOption
            {
                Label = "✓ Allow-listed file name + no shell-out at all",
                Grade = FixGrade.Best,
                Gap = null,
                BuildSql = (f, _) =>
                {
                    bool safe = SafeFileName.IsMatch(f["filename"]);
                    var safeName = safe ? f["filename"] : "nightly_backup.bak";
                    return "-- No CmdExec/shell-out at all: a native T-SQL backup, with the file name validated\n" +
                           "-- against a strict allow-list pattern before it ever reaches a string.\n" +
                          $"BACKUP DATABASE Sales TO DISK = N'C:\\Backups\\{safeName}';" +
                          (safe ? "" : $"\n-- your input ('{f["filename"]}') didn't match the allow-list pattern; falling back to the default name");
                },
                BuildCSharp = f =>
                {
                    bool safe = SafeFileName.IsMatch(f["filename"]);
                    return "// No shell-out at all — a native T-SQL BACKUP, with the name allow-listed first\n" +
                           "var safeName = Regex.IsMatch(filename, @\"^[A-Za-z0-9_\\-]+\\.bak$\") ? filename : \"nightly_backup.bak\";\n" +
                           "using var cmd = new SqlCommand(\"BACKUP DATABASE Sales TO DISK = @Path\", connection);\n" +
                          $"cmd.Parameters.AddWithValue(\"@Path\", $\"C:\\\\Backups\\\\{{safeName}}\"); // resolves to: C:\\Backups\\{(safe ? f["filename"] : "nightly_backup.bak")}\n" +
                           "cmd.ExecuteNonQuery();";
                },
                BuildPowerShell = f =>
                {
                    bool safe = SafeFileName.IsMatch(f["filename"]);
                    return "# No shell-out at all — a native T-SQL BACKUP, with the name allow-listed first\n" +
                           "$safeName = if ($filename -match '^[A-Za-z0-9_-]+\\.bak$') { $filename } else { 'nightly_backup.bak' }\n" +
                          $"# resolves to: C:\\Backups\\{(safe ? f["filename"] : "nightly_backup.bak")}\n" +
                           "Invoke-Sqlcmd -ServerInstance $server -Database Sales -Query \"BACKUP DATABASE Sales TO DISK = 'C:\\Backups\\$safeName'\"";
                },
                Simulate = (f, _) => Classify(f) == "escalation"
                    ? new SimulationResult
                    {
                        Severity = Severity.Blocked,
                        Headline = "Falls back to the default backup file name",
                        Detail = "Anything that isn't a plain, allow-listed file name never reaches a command string at all — " +
                                  "and there's no shell involved any more to chain commands through even if it did."
                    }
                    : new SimulationResult { Severity = Severity.Success, Headline = $"Backup written to C:\\Backups\\{f["filename"]}", Detail = "An ordinary file name, passed straight through." }
            }
        },

        SimulateVulnerable = f => Classify(f) == "escalation"
            ? new SimulationResult
            {
                Severity = Severity.Critical,
                Headline = "A new Windows administrator account was just created",
                Detail = "The file name closes the quoted argument early, and cmd.exe's own command-chaining operator " +
                          "runs the rest as independent commands — creating a user and adding it to Administrators — " +
                          "all under whatever account the CmdExec job step runs as. This is why that account matters so " +
                          "much: it's very often more privileged than the web app's own SQL login ever was.",
                AffectedAssets = new[]
                {
                    "New local administrator account created on the database server's OS",
                    "Full OS-level compromise via the SQL Server Agent service/proxy account"
                }
            }
            : new SimulationResult { Severity = Severity.Success, Headline = "Backup job step created", Detail = "An ordinary file name, nothing unusual happens." },

        HowItWorks =
            "A CmdExec job step doesn't ask SQL Server to run anything — it hands a finished string straight to " +
            "the Windows command shell, exactly like any other OS command injection. The SQL Server Agent service " +
            "account (or a configured proxy account) is what actually executes it, and that account is very often " +
            "far more privileged on the operating system than the database login the web app itself uses, which " +
            "is why reaching CmdExec at all is such a significant escalation — even without touching a single " +
            "table.",

        WhyTheFixWorks =
            "The backup never needs a shell at all — T-SQL's own BACKUP DATABASE statement does the job natively, " +
            "with the file name validated against a strict allow-list before it's ever woven into anything. No " +
            "shell, no shell metacharacters to chain, regardless of which one an attacker reaches for.",

        SamplePayloads = new[]
        {
            "nightly_backup.bak\" & net user hacker Pwnd123! /add & net localgroup administrators hacker /add & \"",
            "nightly_backup.bak | net user hacker Pwnd123! /add"
        },

        ChallengeGoal = "Get the backup job's OS command step to create a new Windows administrator account.",
        Hints = new[]
        {
            "CmdExec steps hand the finished string straight to the Windows command shell (cmd.exe) — what characters does it treat specially?",
            "You don't need a semicolon here — cmd.exe chains commands with its own operator."
        },
        ChallengeAnswer = "nightly_backup.bak\" & net user hacker Pwnd123! /add & net localgroup administrators hacker /add & \"",

        TerminologyNote = "Named for the SQL Server Agent subsystem it abuses: a \"CmdExec\" job step hands its " +
                           "command string to the Windows shell, not to the SQL engine — so despite starting from " +
                           "a SQL Server feature, this is plain OS command injection underneath, just reached " +
                           "through a job step instead of a web server shelling out directly.",
        References = new[]
        {
            new ExternalReference { Label = "NetSPI — Hijacking SQL Server Credentials using Agent Jobs for Domain Privilege Escalation", Url = "https://www.netspi.com/blog/technical-blog/network-pentesting/hijacking-sql-server-credentials-with-agent-jobs-for-domain-privilege-escalation/" },
            new ExternalReference { Label = "Microsoft Learn — SQL Server Agent Fixed Database Roles", Url = "https://learn.microsoft.com/ssms/agent/sql-server-agent-fixed-database-roles" }
        }
    };
}
