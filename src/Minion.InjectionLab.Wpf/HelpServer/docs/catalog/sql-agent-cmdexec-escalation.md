---
support_id: injectionlab.catalog.sql-agent-cmdexec-escalation
---
# SQL Agent CmdExec Job Step Escalation

> SQL Server Agent & Jobs · where this stops being about data and starts
> being about the operating system

**The premise:** an internal "Schedule a backup" admin page lets a user
name the backup file, which gets woven into a SQL Server Agent job step
that runs as a `CmdExec` (operating-system command) step. `CmdExec` steps
hand their command string straight to the Windows shell, running as the
SQL Server Agent service account or a configured proxy — very often far
more privileged than the web app's own low-privileged SQL login.

**Why it matters:** this is the scenario that shows SQL injection's ceiling
isn't "read some rows." A single unsanitized filename can end in a brand
new Windows administrator account, entirely outside the database.

## Where the name comes from

Named for the SQL Server Agent subsystem it abuses: a "CmdExec" job step
hands its command string to the Windows shell, not to the SQL engine — so
despite starting from a SQL Server feature, this is plain OS command
injection underneath, just reached through a job step instead of a web
server shelling out directly.

## In the app

- Watch an ordinary backup-filename field reach all the way into a Windows
  shell command.
- Compare a two-character blacklist (`&` and `"`) against the real fix —
  which isn't a better filter, it's "never shell out at all."
- Challenge: get the backup job's OS command step to create a new Windows
  administrator account.

## Learn more

- [NetSPI — Hijacking SQL Server Credentials using Agent Jobs for Domain Privilege Escalation](https://www.netspi.com/blog/technical-blog/network-pentesting/hijacking-sql-server-credentials-with-agent-jobs-for-domain-privilege-escalation/)
- [Microsoft Learn — SQL Server Agent Fixed Database Roles](https://learn.microsoft.com/ssms/agent/sql-server-agent-fixed-database-roles)

Back to the **[Attack Catalog](overview.md)**.
