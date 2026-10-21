---
support_id: injectionlab.catalog.time-based-blind-injection
---
# Time-Based Blind Injection

> Blind / Inferential · when there's truly nothing to read, a stopwatch
> becomes the whole attack

**The premise:** an order-status page locked down even further than the
boolean-blind one — it shows the exact same confirmation page no matter
what you submit. There's genuinely nothing to see.

**Why it matters:** this is the technique of last resort for in-band
responses — and it still works. If an attacker can make your database
pause on command, they can ask it anything, one timed yes/no question at a
time.

## Where the name comes from

Still "blind" — no data or error ever comes back — but here the oracle is
"time-based": the signal is a measurable delay (`WAITFOR DELAY`) instead of
a visible true/false difference, used when even that much of a difference
isn't observable.

## In the app

- See how wrapping a delay in a condition turns a stopwatch into the same
  kind of yes/no oracle as boolean-blind injection.
- Deliberately single-fix, for the same reason as boolean-blind: there's no
  honest partial mitigation to contrast against real parameterization.
- Challenge: make the server visibly pause for several seconds, with
  absolutely no other observable change.

## Learn more

- [OWASP — Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection) (covers the time-based variant)
- [PortSwigger Web Security Academy — Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind)

Related: [Boolean-Blind Injection](boolean-blind-injection.md) is the same
idea read off the page instead of a stopwatch. Back to the
**[Attack Catalog](overview.md)**.
