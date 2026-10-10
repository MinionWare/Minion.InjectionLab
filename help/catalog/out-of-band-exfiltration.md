# Out-of-Band Exfiltration (DNS)

> Out-of-Band · the response is identical every single time, and that
> doesn't mean it's safe

**The premise:** a report-export endpoint locked down even tighter than
the blind scenarios — it always returns the exact same "Export queued"
response, instantly, no matter what you submit. No data, no error, no
true/false difference, no measurable delay.

**Why it matters:** this is the technique for when every other channel has
been closed. It proves that "the response never changes" is not the same
thing as "nothing happens" — the database can still be made to reach out
over a network you don't control.

## Where the name comes from

"Out-of-band" (OOB) names the channel, not the payload shape: the attacker
never reads a result or a timing difference back through the same
request/response at all. Instead the database is made to reach out over an
entirely separate channel — here, DNS — that only the attacker controls,
and that channel carries the proof (or the data itself) out.

## In the app

- See how a stacked statement calling `xp_dirtree` with a UNC path forces
  an outbound DNS lookup — with the HTTP response never changing at all.
- Compare a blacklist on `xp_dirtree`/`xp_fileexist` against the real fix
  (parameterization) — and notice which extended procedure the blacklist
  never thought to list.
- Challenge: make the server perform an outbound DNS lookup to an
  attacker-controlled host, with zero visible change in the response.

## Learn more

- [NetSPI — Exploiting SQL Injection with DNS-Based Egress](https://www.netspi.com/blog/technical-blog/web-application-pentesting/second-order-sql-injection-with-stored-procedures-dns-based-egress/)
- [PowerUpSQL — UNC Path Injection cheat sheet](https://powershellgallery.com/packages/PowerUpSQL/1.103.8/Content/templates%5CCheatSheet_UncPathInjection.txt)
- [Invicti — Out-of-Band SQL Injection (OOB SQLi)](https://www.invicti.com/learn/out-of-band-sql-injection-oob-sqli)

Related: [Stacked Queries](stacked-queries.md) is the mechanism this
scenario builds on. Back to the **[Attack Catalog](overview.md)**.
