# Error-Based Injection

> Classic / In-Band · a page that helpfully shows raw database errors hands
> you a free data-exfiltration channel

**The premise:** a "check product ID" page shows nothing on an ordinary
request — but like a lot of apps still in production, it helpfully shows
the raw SQL Server error message whenever something goes wrong.

**Why it matters:** this is the one that shows exactly why "show detailed
errors to help debugging" is a real, live security decision, not a
convenience with no downside.

## Where the name comes from

Named for the channel the data leaks through: not the normal response, not
a visible true/false difference, but the database's own error message —
which SQL Server populates with the actual value a failed conversion was
attempting to produce.

## In the app

- Force a `CONVERT`/`CAST` type-conversion failure and watch the SQL
  Server version string (or worse) appear right inside the error text.
- Compare a `CONVERT`-blacklist (bypassed by `CAST`, functionally
  identical) against the real fix: parameterization.
- Challenge: get the SQL Server version string to appear inside a visible
  error message.

## Learn more

- [Advania — MSSQL Practical Injection Cheat Sheet](https://www.advania.co.uk/blog/security/mssql-practical-injection-cheat-sheet/)
- [Exploit-DB — Methods of Quick Exploitation of Blind SQL Injection (the original error-based write-up)](https://www.exploit-db.com/exploits/13604)

Related: [Error-Based Blind Injection](error-based-blind-injection.md) uses
the same error-triggering idea when there's no error text to actually read.
Back to the **[Attack Catalog](overview.md)**.
