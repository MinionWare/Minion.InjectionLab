# Hex-Encoded Literal Bypass

> Delivery & Obfuscation · the filter checked the request. It never saw
> the attack.

**The premise:** an internal diagnostics tool runs whatever gets typed in
via `EXEC()` — support staff can type the command directly, or as a
`0x`-prefixed hex literal, a completely ordinary SQL Server feature for
representing binary data. `EXEC()` will run a hex literal exactly as if it
were the decoded text — quotes, keywords and all.

**Why it matters:** "block the dangerous character" is one of the most
common real-world mitigations, and this scenario shows exactly why it
fails: the dangerous character was never there to begin with. It only
exists after the database's own decode step, which happens *after* the
filter already approved the request.

## Where the name comes from

Named for the encoding it abuses, not a new SQL mechanism: SQL Server
already lets you write binary data as `0x` followed by hex digits, and
`EXEC()` will run that value as a command exactly as if you'd typed the
decoded text out in full. A filter that only inspects the characters you
typed never sees any of them, because they only exist after SQL Server's
own decode step.

## In the app

- Type (or paste — the sample payload text is selectable) a hex-encoded
  command and watch the app show you what it decodes to, live.
- Compare a quote-character blacklist (bypassed completely) against the
  real fix: decode first, *then* check the result against an allow-list.
- Challenge: get the tool to run a completely different command than the
  one it's meant for, despite the quote filter.

## Learn more

- [GoSecure — AWS WAF clients left vulnerable to SQL injection via MSSQL's EXEC() design](https://gosecure.ai/blog/2023/06/21/aws-waf-clients-left-vulnerable-to-sql-injection-due-to-unorthodox-mssql-design-choice/)
- [PortSwigger — Obfuscating attacks using encodings](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings)
- [OWASP — SQL Injection Bypassing WAF](https://wiki.owasp.org/index.php/SQL_Injection_Bypassing_WAF)

Related: [Second-Order Injection](second-order-injection.md) is the other
"a reasonable-looking filter misses this" scenario in this catalog. Back
to the **[Attack Catalog](overview.md)**.
