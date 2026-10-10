# XQuery Injection

> Where Parameters Don't Help · a structural restriction in SQL Server
> pushes developers into dynamic SQL, every time

**The premise:** a document-search feature lets you pick which XML element
to pull out of a stored document, using the xml data type's `.query()`
method. The XQuery expression `.query()` takes has to be a string literal
— SQL Server won't accept a plain variable there — so the developer builds
it with string concatenation instead.

**Why it matters:** this is the scenario that shows a *platform
limitation*, not a developer mistake, can be the root cause of a real
injection — and the real fix requires knowing about a specific, somewhat
obscure SQL Server feature (`sql:variable()`) most developers have never
heard of.

## Where the name comes from

Named for the query language inside the attack, not a new SQL mechanism:
XQuery is the language SQL Server's xml data type methods use internally.
CWE-652 classifies "XQuery Injection" as its own weakness category — but
in T-SQL specifically, it's almost always SQL injection first, just
reached through an XML method call that forced the developer into dynamic
SQL to begin with.

## In the app

- Watch a stacked statement ride out through a `.query()` call that was
  only ever supposed to search inside one XML column.
- Compare a keyword blacklist against the real fix: `sql:variable()`,
  which binds an ordinary parameter's value into a *fixed* XQuery literal
  — no string-building required.
- Challenge: get the document search to return usernames and password
  hashes instead of document content.

## Learn more

- [Microsoft Learn — query() Method (xml Data Type)](https://learn.microsoft.com/sql/t-sql/xml/query-method-xml-data-type)
- [Microsoft Learn — XQuery Extension Functions: sql:variable()](https://learn.microsoft.com/sql/xquery/xquery-extension-functions-sql-variable)
- [CWE-652 — Improper Neutralization of Data within XQuery Expressions](https://cvefeed.io/cwe/detail/cwe-652-improper-neutralization-of-data-within-xquery-expressions-xquery-injection)

Related: [JSON Path Injection](json-path-injection.md) is the same
"argument resists parameterization" family, but with the opposite ending —
JSON_VALUE's path CAN be bound directly, no workaround needed. Back to the
**[Attack Catalog](overview.md)**.
