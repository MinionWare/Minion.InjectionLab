# Comment/Whitespace Obfuscation

> Delivery & Obfuscation · the filter matched a phrase. SQL Server matched
> something broader.

**The premise:** the same product search box as the UNION scenario —
except this time a filter specifically rejects any request containing the
literal phrase "UNION SELECT" (with a space), on the theory that blocking
the exact attack phrase stops the attack.

**Why it matters:** this is the cleanest demonstration in the catalog of
why phrase-matching filters fail — the filter and the SQL parser don't
agree on what counts as "the same text."

## Where the name comes from

Named for the evasion method, not a new attack: the underlying technique
is still UNION-based injection. "Obfuscation" here specifically means
substituting an inline SQL comment for a space — valid, parser-neutral
whitespace that a literal-phrase filter was never built to recognize.

## In the app

- Watch `UNION/**/SELECT` produce the exact same parsed query as `UNION
  SELECT` with a real space — and sail past a filter checking for the
  literal phrase.
- Compare the phrase filter (bypassed regardless of difficulty — this is a
  structural gap, not a casing one) against the real fix: parameterization.
- Challenge: get the product search to leak usernames and password hashes,
  despite the phrase filter.

## Learn more

- [websec.ca — MSSQL Fuzzing and Obfuscation knowledge base](https://websec.ca/sql-injection-knowledge-base/mssql/fuzzing-obfuscation)
- [PortSwigger — Obfuscating attacks using encodings](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings)
- [OWASP — SQL Injection Bypassing WAF](https://wiki.owasp.org/index.php/SQL_Injection_Bypassing_WAF)

Related: [UNION-Based Injection](union-based-injection.md) is the
underlying technique this scenario evades a filter to reach. Back to the
**[Attack Catalog](overview.md)**.
