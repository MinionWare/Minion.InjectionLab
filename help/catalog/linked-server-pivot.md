# Linked-Server Pivoting

> Post-Injection Impact · the injection never has to touch the sensitive
> data directly — it just has to reach a server that already trusts this one

**The premise:** an internal reporting tool queries its own, fairly
low-value database — but that server has a linked server configured to a
much more sensitive Finance instance, mapped to a SQL login with real
access on the remote side.

**Why it matters:** this is the scenario that shows "the compromised
server has nothing valuable on it" isn't the end of the story. Standing
trust relationships between servers are exactly what a pivot is built to
abuse.

## Where the name comes from

Named for the mechanism, not a new injection technique: "pivoting" means
using one compromised foothold to reach a second, different system — here,
across a configured linked-server trust relationship via `OPENQUERY`/
`OPENROWSET`/`EXEC ... AT`, rather than anything new about how the
injection itself works.

## In the app

- Watch a stacked statement call `OPENQUERY` against a linked server and
  pull real data from a completely different SQL Server instance.
- Compare an `OPENQUERY`-blacklist against the real fix: parameterization,
  which stops the stacking entirely regardless of which linked servers
  exist.
- Challenge: read data from the Finance server through the reporting
  tool's own lookup field.

## Learn more

- [NetSPI — How to Hack Database Links in SQL Server](https://www.netspi.com/blog/technical-blog/network-pentesting/how-to-hack-database-links-in-sql-server/)
- [Microsoft Learn — Linked Servers (OPENQUERY, OPENROWSET, EXEC AT)](https://learn.microsoft.com/sql/relational-databases/linked-servers/linked-servers-openquery-openrowset-exec-at)

Related: [Stacked Queries](stacked-queries.md) is the mechanism this
scenario builds on, same as out-of-band exfiltration and xp_cmdshell RCE.
Back to the **[Attack Catalog](overview.md)**.
