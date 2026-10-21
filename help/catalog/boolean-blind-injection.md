---
support_id: injectionlab.catalog.boolean-blind-injection
---
# Boolean-Blind Injection

> Blind / Inferential · the app shows you nothing, and that's still not enough

**The premise:** a support chat widget's "check my order" feature returns
only "Found" or "Not found" — never any actual data.

**Why it matters:** this is the technique that proves "we never show the
attacker any data" is not a defense. A single bit of information, asked
enough times, can reconstruct an entire database.

## Where the name comes from

"Blind" because the response never shows data or a database error — the
only observable signal is which of two outcomes you get. "Boolean"
specifies which signal: a true/false (yes/no) difference in the page
itself, as opposed to the time-based variant's measurable delay.

## In the app

- Watch the response flip between "Found" and "Not found" as your
  condition changes, and see why that alone is enough to extract real data
  one character at a time.
- This is deliberately single-fix: blind techniques work precisely because
  they don't depend on any one keyword, so there's no honest
  "weaker-but-real" mitigation to contrast against parameterization.
- Challenge: make the order check lie about an order that really exists.

## Learn more

- [OWASP — Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
- [PortSwigger Web Security Academy — Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind)

Related: [Time-Based Blind Injection](time-based-blind-injection.md) is
the same idea with the visible signal replaced by a measurable delay. Back
to the **[Attack Catalog](overview.md)**.
