---
support_id: injectionlab.catalog.order-by-identifier-injection
---
# Identifier Injection (ORDER BY)

> Where Parameters Don't Help · the one time "just parameterize it" isn't
> even an option

**The premise:** a product list has a "sort by" option. Column names can't
be bound as `@parameters` the normal way — parameters only ever substitute
for values, never for identifiers — so a lot of apps fall back to string
concatenation here even when everything else is properly parameterized.

**Why it matters:** this is the scenario that breaks the assumption
"parameterized queries are always safe." They are — for *data*. Identifiers
are a different category entirely, and plenty of otherwise-careful code
gets caught out exactly here.

## Where the name comes from

Named for what's being injected: an identifier (a column or table name)
rather than a value. That distinction matters because `@parameter`
placeholders only ever bind as data — there's no parameterized way to say
"this identifier" at all, which is why allow-listing is the only real fix
here.

## In the app

- See why `ORDER BY` accepts a full expression, not just a bare column name
  — which is exactly what makes concatenating it dangerous.
- Compare a common real logic bug (an allow-list check using `Contains`
  instead of an exact match) against the real fix (exact-match allow-list
  + `QUOTENAME`).
- Challenge: make the product list execute a delay through the "sort by"
  option alone.

## Learn more

- [Microsoft Learn — QUOTENAME (Transact-SQL)](https://learn.microsoft.com/sql/t-sql/functions/quotename-transact-sql)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet)

Related: [Dynamic SQL in a Stored Procedure](dynamic-sql-stored-procedure.md)
is the other "parameters don't help" scenario in this catalog. Back to the
**[Attack Catalog](overview.md)**.
