# QUOTENAME's 128-Character Limit

> Where Parameters Don't Help · the textbook-correct fix, with one edge
> case nobody checks for

**The premise:** the same "sort by" product list as the identifier-
injection scenario — except this developer already learned that lesson
and wraps the column name in `QUOTENAME()` before building the query.
`QUOTENAME` alone sounds like the textbook-correct fix for an identifier.
It isn't quite the whole fix.

**Why it matters:** this is the catalog's best example of "the fix is
real, but incomplete" applied to a *good* mitigation instead of a naive
one — `QUOTENAME` genuinely stops classic identifier injection; it just
was never built to validate that the identifier is one your schema
actually has.

## Where the name comes from

Not a new attack technique — the identifier can't be "injected" here at
all, `QUOTENAME` sees to that. The name refers to a specific, documented
edge case in `QUOTENAME`'s own behavior (the 128-character `sysname`
limit) that breaks a fix relying on `QUOTENAME` as if it were a complete,
standalone solution rather than one layer of one.

## In the app

- Feed the sort field more than 128 characters and watch `QUOTENAME`
  silently return NULL — which poisons the entire concatenated command
  into a silent no-op.
- Compare `QUOTENAME` alone (breaks past 128 characters) against the real
  fix: an exact-match allow-list, with `QUOTENAME` as genuine defense in
  depth on top of it.
- Challenge: make the product list silently fail to sort at all, using
  nothing but an overly long column name.

## Learn more

- [Microsoft Learn — QUOTENAME (Transact-SQL)](https://learn.microsoft.com/sql/t-sql/functions/quotename-transact-sql)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet)

Related: [Identifier Injection (ORDER BY)](order-by-identifier-injection.md)
is the scenario this one's "textbook fix" is built to solve. Back to the
**[Attack Catalog](overview.md)**.
