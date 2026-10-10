# Comment Truncation

> Classic / In-Band · you don't need a clever trick, just a comment marker

**The premise:** a login form checks a username and password — the same
shape as the tautology scenario, but this time the attacker already knows
a valid username and doesn't need any always-true condition at all.

**Why it matters:** this is the one that proves tautologies aren't the
only way in. A comment marker doesn't make a check pass — it erases the
check entirely.

## Where the name comes from

Named for the mechanism, not a logic trick: a SQL comment marker truncates
— cuts off — everything the developer wrote after it, as far as the
engine is concerned. It's often confused with tautology-based bypasses
because both commonly target logins, but the two work completely
differently: one makes a check pass, the other erases the check.

## In the app

- Watch the password check vanish from the generated SQL the instant a
  comment marker appears after a real username.
- Compare a `--`-blacklist (bypassed by `/*`, SQL Server's other comment
  style) against the real fix: parameterization.
- Challenge: log in as `alice` without ever providing her real password.

## Learn more

- [PortSwigger Web Security Academy — SQL injection](https://portswigger.net/web-security/sql-injection)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet)

Related: [Tautology / Login Bypass](tautology-login-bypass.md) targets the
same kind of form with a different mechanism entirely. Back to the
**[Attack Catalog](overview.md)**.
