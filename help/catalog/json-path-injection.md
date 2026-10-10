# JSON Path Injection

> Classic / In-Band · the fix here has no excuse not to exist

**The premise:** a customer-profile search lets an admin filter by any
property stored in a JSON "Profile" column, using `JSON_VALUE` to pull
that property out. The query is built by concatenating the property name
into the JSON path string, the same as if it were raw user input.

**Why it matters:** unlike several other scenarios in this catalog, there's
no structural reason this one was ever vulnerable — `JSON_VALUE`'s path
argument has been a fully bindable parameter since SQL Server 2017. This
is a missed fix, not a forced workaround.

## Where the name comes from

Named for the JSON path mini-language `JSON_VALUE` (and `JSON_QUERY`,
`OPENJSON`) uses to locate a value inside a JSON document — not a new SQL
mechanism. A real, documented 2024 vulnerability in the Corteza low-code
platform's SQL Server backend was exactly this bug: a JSON path/key built
via string concatenation with incorrect escaping.

## In the app

- Watch a closed `JSON_VALUE(...)` call hand off into an ordinary `UNION
  SELECT`.
- Compare a keyword blacklist against the real fix: binding the JSON path
  itself as a parameter — no workaround needed, unlike the xml data type's
  XQuery methods.
- Challenge: get the profile search to return usernames and password
  hashes instead of profile data.

## Learn more

- [Microsoft Learn — JSON_VALUE (Transact-SQL)](https://learn.microsoft.com/sql/t-sql/functions/json-value-transact-sql)
- [fluidattacks — SQL Injection in MSSQL JSON-path meta filter (Corteza)](https://fluidattacks.com/advisories/motley)

Related: [XQuery Injection](xquery-injection.md) is the same family of bug
with the opposite ending — the xml data type's methods genuinely can't be
parameterized the normal way. Back to the **[Attack Catalog](overview.md)**.
