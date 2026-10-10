# UNION-Based Injection

> Classic / In-Band · the moment "I can bypass a check" becomes "I can read
> your entire database"

**The premise:** a product search box, built to show a product name and a
price — nothing more.

**Why it matters:** this is the technique that turns SQL injection from "a
clever trick" into "a data breach." Tautologies prove the hole exists;
UNION is how you actually walk out the door with real rows.

## Where the name comes from

Named directly after the SQL `UNION` operator it abuses — `UNION`'s actual
job is combining the results of two unrelated `SELECT` statements into one
result set. The attack just supplies the second `SELECT` itself.

## In the app

- Watch the search box's query grow a second `SELECT` pulling columns from
  a completely different table.
- See why column *count* and *type* both have to line up for this to work
  — and what the generated SQL looks like when they don't.
- Challenge: get the product search to leak real usernames and password
  hashes.

## Learn more

- [PortSwigger Web Security Academy — SQL injection UNION attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet)

Related: [Hex-Encoded Literal Bypass](hex-encoded-bypass.md) shows a
different way to get a payload — including a `UNION`-based one — past a
naive filter. Back to the **[Attack Catalog](overview.md)**.
