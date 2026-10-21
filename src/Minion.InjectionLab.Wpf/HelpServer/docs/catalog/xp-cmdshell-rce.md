---
support_id: injectionlab.catalog.xp-cmdshell-rce
---
# xp_cmdshell Remote Code Execution

> Post-Injection Impact · the actual ceiling of what SQL injection can reach

**The premise:** the same order-lookup tool as the stacked-queries
scenario — except this connection runs as a sysadmin-level login, the kind
many legacy apps and internal tools still use because "it was easier to
set up." `xp_cmdshell`, the extended procedure that runs operating-system
commands, is only a stacked statement away.

**Why it matters:** this is the catalog's answer to "okay, but how bad can
SQL injection actually get?" On the wrong connection, the answer is: as
bad as a direct shell on the database server.

## Where the name comes from

Named directly after the SQL Server extended stored procedure it calls —
`xp_cmdshell` runs a string as a Windows command and is SQL Server's own,
official (if dangerous) bridge from T-SQL to the operating system shell.

## In the app

- Watch a stacked `EXEC xp_cmdshell 'whoami'` return `NT AUTHORITY\SYSTEM`
  — no further escalation needed, because the connection is already
  sysadmin.
- Compare a keyword blacklist (a sysadmin connection has other ways to
  reach the same destination) against the real fix: parameterization,
  which stops the stacking entirely.
- Challenge: get an operating-system command to execute through the order
  lookup.

## Learn more

- [Hacking Articles — MSSQL for Pentester: Command Execution with xp_cmdshell](https://www.hackingarticles.in/mssql-for-pentester-command-execution-with-xp_cmdshell/)
- [StraightPathSQL — xp_cmdshell enabled check](https://straightpathsql.com/check/xp_cmdshell/)

Related: [Stacked Queries](stacked-queries.md) is the mechanism this
scenario builds on. Back to the **[Attack Catalog](overview.md)**.
