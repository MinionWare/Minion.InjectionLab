# EXECUTE AS Escalation

> Where Parameters Don't Help · the permissions that matter aren't the
> caller's

**The premise:** a reporting stored procedure builds dynamic SQL from a
search term — and because low-privileged reporting users shouldn't need
direct table access, the procedure was created `WITH EXECUTE AS OWNER`, so
it always runs as the database owner, regardless of who calls it.

**Why it matters:** this is the scenario that breaks "but the caller has
almost no permissions, so what's the worst that could happen?" The
procedure's *own* permissions are the ones that count once an injection
reaches it.

## Where the name comes from

Named for the T-SQL clause that causes it: `EXECUTE AS` sets which
account's permissions a module runs under. "Ownership chaining" is the
related, broader concept — permission checks being skipped across a chain
of same-owner objects — and the two are often discussed together because
both can let code run with more privilege than the caller who triggered it
actually has.

## In the app

- Watch the same UNION payload from the plain UNION scenario reach data a
  reporting login was never granted direct access to — because the
  procedure it rides through runs as the database owner.
- Compare a `UNION`-blacklist (the privilege problem persists regardless)
  against the real fix: parameterizing the dynamic SQL inside the
  procedure itself.
- Challenge: get the reporting search to read password hashes, despite the
  reporting login never being granted direct table access.

## Learn more

- [Microsoft Learn — EXECUTE AS Clause (Transact-SQL)](https://learn.microsoft.com/sql/t-sql/statements/execute-as-clause-transact-sql)
- [Redgate Simple Talk — Cross-Database Ownership Chaining in SQL Server](https://www.red-gate.com/simple-talk/databases/sql-server/cross-database-ownership-chaining-in-sql-server-security-risks-behavior-and-privilege-escalation-explained/)

Related: [Dynamic SQL in a Stored Procedure](dynamic-sql-stored-procedure.md)
covers the base vulnerability this scenario adds a privilege dimension to.
Back to the **[Attack Catalog](overview.md)**.
