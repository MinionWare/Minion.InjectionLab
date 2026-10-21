---
support_id: injectionlab.catalog.like-wildcard-abuse
---
# LIKE Wildcard Abuse

> Classic / In-Band · the one scenario where "parameterize it" isn't the
> whole answer

**The premise:** a search box feeds straight into a `LIKE` pattern.

**Why it matters:** this is the one attack in the catalog where
parameterizing the query — the fix for everything else here — genuinely
isn't enough on its own. It's a deliberate, honest exception to the
pattern, not a mistake.

## Where the name comes from

This isn't classic injection at all — no quote ever breaks, no keyword
ever gets added. It abuses SQL's own `LIKE` pattern language: `%` and `_`
are wildcards inside a `LIKE` pattern, so passing them through unescaped
lets user input change what the pattern *matches*, even though the query's
structure never changes.

## In the app

- See why a fully parameterized `LIKE` query can still behave unexpectedly
  if the wildcard characters inside the parameter aren't escaped.
- The "Partial" fix here is unusual: it's a real, complete fix for a
  *different* problem than the one that's still open — not a fake/naive
  pattern like most other Partial fixes in this catalog.
- Challenge: make a search return far more (or different) results than
  intended, using nothing but ordinary wildcard characters.

## Learn more

- [Microsoft Learn — LIKE (Transact-SQL), including the ESCAPE clause](https://learn.microsoft.com/sql/t-sql/language-elements/like-transact-sql)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet)

Back to the **[Attack Catalog](overview.md)**.
