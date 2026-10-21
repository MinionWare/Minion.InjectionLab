---
support_id: injectionlab.catalog.stacked-queries
---
# Stacked Queries

> Classic / In-Band · one character, and suddenly you're running a
> completely different command

**The premise:** an internal order-lookup tool builds one T-SQL batch per
request. SQL Server — and most drivers, by default — will happily run
several semicolon-separated statements in a single batch.

**Why it matters:** every other classic technique reshapes the *existing*
query. This one ends it and starts an entirely new, independent command —
often with far worse consequences than a reshaped `WHERE` clause.

## Where the name comes from

"Stacked" describes statements piled up one after another in a single
batch, separated by semicolons — the same idea some literature calls
"batched" or "piggy-backed" queries, since the extra statement rides along
on the back of the original request.

## In the app

- Watch a semicolon turn one lookup query into two independent statements.
- This is one of the three scenarios left deliberately single-fix (see the
  in-app "Why the fix works" note) — blacklisting the one required
  character doesn't have the same kind of realistic bypass a keyword does.
- Challenge: get a second, entirely different SQL statement to execute
  alongside the lookup.

## Learn more

- [PortSwigger — SQL injection cheat sheet (see "Batched (or stacked) queries")](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [Halfond, Viegas & Orso — "A Classification of SQL Injection Attacks and Countermeasures"](https://sites.cc.gatech.edu/home/orso/papers/halfond.viegas.orso.ISSSE06.pdf) (classifies this as "piggy-backed queries")

Related: [Out-of-Band Exfiltration (DNS)](out-of-band-exfiltration.md)
reuses this exact stacking mechanism to trigger a DNS lookup instead of a
visible result. Back to the **[Attack Catalog](overview.md)**.
