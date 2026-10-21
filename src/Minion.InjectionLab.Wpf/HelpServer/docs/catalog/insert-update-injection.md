---
support_id: injectionlab.catalog.insert-update-injection
---
# INSERT/UPDATE Injection

> Classic / In-Band · every SELECT-based lesson here applies identically
> to statements that change data

**The premise:** a profile page lets you update your own bio. The feature
builds an UPDATE statement by concatenating the bio field straight in —
the exact same bug as every SELECT-based scenario here, just in a
statement that changes data instead of reading it.

**Why it matters:** this is the one that shows injection isn't only a
"read data you shouldn't" problem. The same hole in a write statement can
self-escalate privilege with a single, otherwise-unremarkable request.

## Where the name comes from

Named for where the injection lands: a write statement (INSERT, UPDATE, or
DELETE) rather than a SELECT. The mechanism is identical to any other
string-concatenation bug — what changes is the consequence, since a write
statement can alter data (and privileges) directly instead of only
reading it.

## In the app

- Watch a closing quote and a comma extend an ordinary bio update into an
  extra column assignment, in the same statement.
- Compare a `Role`-blacklist (bypassed by targeting `IsAdmin` instead)
  against the real fix: parameterization.
- Challenge: get your own bio update to also grant your account a
  privileged role.

## Learn more

- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet)
- [PortSwigger Web Security Academy — SQL injection](https://portswigger.net/web-security/sql-injection)

Back to the **[Attack Catalog](overview.md)**.
