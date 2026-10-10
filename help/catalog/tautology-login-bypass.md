# Tautology / Login Bypass

> Classic / In-Band · the one everybody's heard of, and the one most people
> still get wrong

**The premise:** a login form checks a username and password against the
Users table. The query is built by gluing the two text boxes straight into
the `WHERE` clause.

**Why it matters:** this is usually the very first SQL injection anyone
ever sees — and for good reason. It's the clearest possible demonstration
that a condition you add to a query doesn't have to be *true for the real
data*, just true, period.

## Where the name comes from

"Tautology" is borrowed from formal logic: a statement that's true no
matter what the variables are (like `1=1` or `'1'='1'`). This technique
injects exactly that kind of always-true condition into a `WHERE` clause,
so it passes regardless of the real data — the name describes the logical
trick, not the SQL syntax used to deliver it.

## In the app

- Watch the generated SQL flip from a normal password check to an
  always-true condition as you type.
- Compare the Partial fix (a keyword blacklist on "OR") against the real
  fix (parameterization) — and see exactly which sample payload the
  blacklist can never catch, at any difficulty.
- Challenge: log in as `alice` without ever knowing her real password.

## Learn more

- [Halfond, Viegas & Orso — "A Classification of SQL Injection Attacks and Countermeasures"](https://sites.cc.gatech.edu/home/orso/papers/halfond.viegas.orso.ISSSE06.pdf) — the paper that formalized this category.
- [PortSwigger Web Security Academy — SQL injection](https://portswigger.net/web-security/sql-injection)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet)

Related: [Boolean-Blind Injection](boolean-blind-injection.md) builds on
the same always-true/always-false idea without ever showing you data.
Back to the **[Attack Catalog](overview.md)**.
