---
support_id: injectionlab.catalog.dynamic-sql-stored-procedure
---
# Dynamic SQL in a Stored Procedure

> Where Parameters Don't Help · "it's in a stored procedure" is not the
> same thing as "it's safe"

**The premise:** a stored procedure builds and runs T-SQL text at runtime
from one of its own parameters — the exact same unsafe pattern as
application-level string concatenation, just one layer deeper.

**Why it matters:** a lot of teams treat "move the logic into a stored
procedure" as a security fix by itself. It isn't. A procedure that builds
dynamic SQL from unvalidated input is exactly as vulnerable as the
application code it replaced.

## Where the name comes from

"Dynamic SQL" is the general T-SQL term for a statement assembled and
compiled at runtime (via `EXEC` or `sp_executesql`) rather than written
statically into the procedure. Being inside a stored procedure doesn't make
dynamic SQL safe by itself — the proc can still build the unsafe string
the exact same way application code would.

## In the app

- Watch a proc's own internal guard clause run as real T-SQL (`IF @Name
  LIKE '%UNION%' RETURN;`) — and see exactly how it gets bypassed.
- Compare that filter against the real fix: `sp_executesql` with a typed
  parameter.
- Challenge: get the procedure to leak real usernames and password hashes.

## Learn more

- [Microsoft Learn — sp_executesql (Transact-SQL)](https://learn.microsoft.com/sql/relational-databases/system-stored-procedures/sp-executesql-transact-sql)
- [Microsoft Learn — SQL Injection (official security guidance, covers stored procedures)](https://learn.microsoft.com/sql/relational-databases/security/sql-injection)

Related: [Identifier Injection (ORDER BY)](order-by-identifier-injection.md)
is the other "parameters don't help" scenario in this catalog. Back to the
**[Attack Catalog](overview.md)**.
