# Attack Catalog

Thirteen techniques, six categories. Every one gets real SQL/C#/PowerShell,
graded fixes where there's more than one honest mitigation to compare, full
terminology and external references, and a hands-on challenge.

## Classic / In-Band

The attack and the result travel through the same response — the most
direct form of injection.

- **[Tautology / Login Bypass](tautology-login-bypass.md)** — the one
  everybody's heard of: `' OR '1'='1`.
- **[UNION-Based Injection](union-based-injection.md)** — gluing a second,
  unrelated `SELECT` onto the first to pull data from a different table.
- **[Stacked Queries](stacked-queries.md)** — a semicolon ends one
  statement and starts an entirely independent one.
- **[Numeric Injection](numeric-injection.md)** — no quotes needed at all
  when the injection point is already unquoted.
- **[LIKE Wildcard Abuse](like-wildcard-abuse.md)** — not classic
  injection at all: abusing SQL's own pattern-matching wildcards.

## Blind / Inferential

No data, no error — just a yes/no, and that's still enough.

- **[Boolean-Blind Injection](boolean-blind-injection.md)** — a visible
  true/false difference is the whole channel.
- **[Time-Based Blind Injection](time-based-blind-injection.md)** — when
  even that much isn't visible, a measurable delay becomes the signal.

## Where Parameters Don't Help

Parameters only ever bind as *data* — some things in SQL aren't data at all.

- **[Identifier Injection (ORDER BY)](order-by-identifier-injection.md)** —
  column and table names can't be parameterized, full stop.
- **[Dynamic SQL in a Stored Procedure](dynamic-sql-stored-procedure.md)**
  — being inside a proc doesn't make string-built SQL safe.

## Delivery & Obfuscation

Getting a payload past a filter without changing what it ultimately does.

- **[Second-Order Injection](second-order-injection.md)** — the payload is
  stored safely, then fires later in a completely different query.
- **[Hex-Encoded Literal Bypass](hex-encoded-bypass.md)** — a quote-filter
  that's blind to a payload that never contains a literal quote at all.

## Out-of-Band

For when the response gives you *nothing* — not even a timing difference.

- **[Out-of-Band Exfiltration (DNS)](out-of-band-exfiltration.md)** — the
  proof (and the data) leaves through an entirely separate channel.

## SQL Server Agent & Jobs

Where SQL injection stops being about data and starts being about the
operating system.

- **[CmdExec Job Step Escalation](sql-agent-cmdexec-escalation.md)** — an
  OS command, running as whatever account SQL Server Agent uses — often far
  more privileged than the app's own database login.

---

Not sure where to start? The **[Opening Tutorial](../getting-started/tutorial-wizard.md)**
covers the concept behind the first four categories in about five minutes.
Already comfortable with the basics? **Out-of-Band**, **Hex-Encoded Literal
Bypass**, and **CmdExec Job Step Escalation** are the ones that tend to
surprise people who think they already know SQL injection cold.
