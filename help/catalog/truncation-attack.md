# Truncation Attack

> Delivery & Obfuscation · defending against one error reopens a much
> quieter bug

**The premise:** a registration page checks a new username before
inserting it — the Username column is VARCHAR(20). Inserting anything
longer would raise SQL Server's own "String or binary data would be
truncated" error, so the app defensively pre-truncates every username to
20 characters in code before it ever reaches a query.

**Why it matters:** this is a great example of a well-intentioned
defensive fix (avoid an ugly database error) reintroducing the exact bug
it was trying to route around.

## Where the name comes from

Sometimes called a "truncation" or "trimming" attack in web-security
literature, most commonly documented against databases (like MySQL in
non-strict mode) that silently cut oversized input down to fit. SQL Server
doesn't do that itself — it errors instead — but the identical bug
reappears the moment application code truncates defensively to dodge that
error.

## In the app

- See how a uniqueness check running against the *full* input can pass,
  while the *truncated* value collides with an existing account thanks to
  SQL Server's trailing-space-insensitive string comparison.
- Compare trimming trailing spaces first (bypassed by truncation alone,
  with no spaces involved) against the real fix: reject oversized input
  outright instead of truncating it.
- Challenge: register a username that's genuinely unique in full, but
  collides with the existing "admin" account once stored.

## Learn more

- [InfoSec Institute — SQL Truncation Attack](https://resources.infosecinstitute.com/sql-truncation-attack)
- [LIMSwiki — Web Application Security Guide: Truncation attacks, trimming attacks](https://limswiki.org/index.php/LII:Web_Application_Security_Guide/Truncation_attacks,_trimming_attacks)
- [SQLServerCentral — ANSI_PADDING, Trailing Whitespace, and Variable Character Columns](https://www.sqlservercentral.com/articles/ansi-padding-trailing-whitespace-and-variable-character-columns)

Back to the **[Attack Catalog](overview.md)**.
