---
support_id: injectionlab.catalog
---
# Attack Catalog

Twenty-six techniques, seven categories. Every one gets real SQL/C#/PowerShell,
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
- **[Comment Truncation](comment-truncation.md)** — one known username and
  a comment marker, no always-true condition required.
- **[Error-Based Injection](error-based-injection.md)** — a type-conversion
  failure leaks its value straight into a visible error message.
- **[INSERT/UPDATE Injection](insert-update-injection.md)** — the same bug
  in a write statement, escalating a profile update to an admin account.
- **[Full-Text Search Injection](fulltext-contains-injection.md)** — a
  predicate with its own query syntax is still ordinary SQL underneath.
- **[JSON Path Injection](json-path-injection.md)** — a path argument SQL
  Server has let you parameterize since 2017, left unparameterized anyway.

## Blind / Inferential

No data, no error — just a yes/no, and that's still enough.

- **[Boolean-Blind Injection](boolean-blind-injection.md)** — a visible
  true/false difference is the whole channel.
- **[Time-Based Blind Injection](time-based-blind-injection.md)** — when
  even that much isn't visible, a measurable delay becomes the signal.
- **[Error-Based Blind Injection](error-based-blind-injection.md)** — when
  there's no delay either, whether the request errors out at all is the
  oracle.

## Where Parameters Don't Help

Parameters only ever bind as *data* — some things in SQL aren't data at all.

- **[Identifier Injection (ORDER BY)](order-by-identifier-injection.md)** —
  column and table names can't be parameterized, full stop.
- **[Dynamic SQL in a Stored Procedure](dynamic-sql-stored-procedure.md)**
  — being inside a proc doesn't make string-built SQL safe.
- **[QUOTENAME's 128-Character Limit](quotename-limit.md)** — the
  textbook-correct identifier fix has a documented edge case of its own.
- **[EXECUTE AS Escalation](execute-as-escalation.md)** — a procedure
  secured to run as a privileged account hands that same privilege to
  whatever gets injected into it.
- **[XQuery Injection](xquery-injection.md)** — the xml data type's own
  methods require a string literal, forcing the exact same dynamic-SQL trap.

## Delivery & Obfuscation

Getting a payload past a filter without changing what it ultimately does.

- **[Second-Order Injection](second-order-injection.md)** — the payload is
  stored safely, then fires later in a completely different query.
- **[Hex-Encoded Literal Bypass](hex-encoded-bypass.md)** — a quote-filter
  that's blind to a payload that never contains a literal quote at all.
- **[Comment/Whitespace Obfuscation](comment-whitespace-obfuscation.md)** —
  SQL Server treats a comment exactly like the space it replaced.
- **[Truncation Attack](truncation-attack.md)** — defensive pre-truncation,
  plus a trailing-space quirk, collides a new account with an existing one.

## Out-of-Band

For when the response gives you *nothing* — not even a timing difference.

- **[Out-of-Band Exfiltration (DNS)](out-of-band-exfiltration.md)** — the
  proof (and the data) leaves through an entirely separate channel.

## Post-Injection Impact

The ceiling, not the floor: what injection can escalate all the way to.

- **[xp_cmdshell Remote Code Execution](xp-cmdshell-rce.md)** — a sysadmin
  connection plus one stacked statement is a full OS command shell.
- **[Linked-Server Pivoting](linked-server-pivot.md)** — the sensitive data
  was never on this server at all; a trust relationship reaches it anyway.

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
Bypass**, **QUOTENAME's 128-Character Limit**, and **xp_cmdshell Remote Code
Execution** are the ones that tend to surprise people who think they already
know SQL injection cold.
