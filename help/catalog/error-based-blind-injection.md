# Error-Based Blind Injection

> Blind / Inferential · when there's no delay and no visible difference,
> whether it errors out at all is still a signal

**The premise:** an order-status page shows the exact same confirmation
text no matter what — no data, no true/false difference, nothing. But like
most apps, an unhandled database exception still surfaces as a generic
"Something went wrong" error page instead of a silent failure.

**Why it matters:** this closes the loop on the blind-injection family —
even when content *and* timing give you nothing, whether the request
crashes is its own one-bit channel.

## Where the name comes from

Still "blind" — no data or content difference is ever visible — but the
oracle here is "error-based": the signal is whether the request errors out
at all, forced via a conditional divide-by-zero, rather than a visible
true/false difference (boolean-blind) or a measurable delay (time-based
blind).

## In the app

- Watch a `CASE WHEN ... THEN 1/0 ELSE 1 END` expression flip the page
  between a normal response and a generic error, based on a condition
  buried inside it.
- Compare a `1/0`-blacklist (bypassed by spacing it out, or by `CAST`)
  against the real fix: parameterization.
- Challenge: make the order check throw a visible error using a condition
  that's true, with no other observable change.

## Learn more

- [PortSwigger Web Security Academy — Blind SQL injection (conditional errors)](https://portswigger.net/web-security/sql-injection/blind)
- [OWASP — Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)

Related: [Error-Based Injection](error-based-injection.md) uses the same
conversion-failure idea, but the error message itself carries the leaked
data. Back to the **[Attack Catalog](overview.md)**.
