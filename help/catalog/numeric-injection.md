# Numeric Injection

> Classic / In-Band · no quotes needed, no filter to get past

**The premise:** an order lookup compares a numeric, unquoted ID column
directly against user input, with no surrounding quote marks at all.

**Why it matters:** a huge amount of injection advice starts with "watch
out for quote characters" — which is correctly useless advice here. If the
value was never quoted to begin with, there's nothing to escape out of.

## Where the name comes from

Named for where the injection lands: a numeric (unquoted) column, not a
quoted string. There's no quote mark to escape and no quote-stripping
filter to get past — the value is concatenated bare, so the attack is
often even simpler than a string-context one.

## In the app

- See how the exact same unquoted-concatenation problem shows up whenever
  a numeric field is built as a string.
- Compare the Partial fix against the Best (strongly-typed parameter) fix.
- Challenge: get every order in the table to come back from what looks
  like a single-ID lookup.

## Learn more

- [PortSwigger Web Security Academy — SQL injection](https://portswigger.net/web-security/sql-injection) (see the unquoted/numeric context example)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet)

Related: [Stacked Queries](stacked-queries.md) shares the same unquoted,
concatenated shape. Back to the **[Attack Catalog](overview.md)**.
