# Second-Order Injection

> Delivery & Obfuscation · the entry point and the actual bug are two
> different features

**The premise:** Step 1, a profile page lets you set your display name —
fully parameterized, genuinely safe. Step 2, much later, an unrelated admin
"Recent Activity" report concatenates that *already stored* name into a
brand-new query, trusting it because "it's already in our own database."

**Why it matters:** this is the scenario that defeats "we reviewed the
risky input field and it's fine." The field really is fine. The bug lives
somewhere else entirely, in code that never directly touched user input at
all.

## Where the name comes from

"Second-order" because the payload does nothing on its first pass — it's
only stored. The actual injection happens on a later, separate query that
reuses the stored value, which is what makes it so easy to miss: the input
that looked safe and the query that gets exploited are never the same
request.

## In the app

- Watch the exact same value pass through two completely different code
  paths — one safely parameterized, one not — and see the generated SQL
  for both.
- Compare a keyword blacklist on the *second* query against actually
  parameterizing it too.
- Challenge: get a value stored as your display name to execute as SQL
  later, somewhere that never directly touched your input.

## Learn more

- [Halfond, Viegas & Orso — "A Classification of SQL Injection Attacks and Countermeasures"](https://sites.cc.gatech.edu/home/orso/papers/halfond.viegas.orso.ISSSE06.pdf) (classifies second-order injection as its own mechanism)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet)

Related: [Hex-Encoded Literal Bypass](hex-encoded-bypass.md) is the other
"gets past a filter that looks reasonable" scenario in this catalog. Back
to the **[Attack Catalog](overview.md)**.
