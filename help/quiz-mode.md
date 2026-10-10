# Quiz Mode

`View > Quiz mode`, or the "🏆 Quiz mode" button in the left nav, opens a
separate window with capstone missions, grouped by difficulty. Unlike
per-attack [Challenge Mode](challenge-mode.md), a quiz mission has no single
canonical answer: **any payload that genuinely achieves the stated goal
counts**, graded by rule-based pattern matching the same way everything
else in this app is, not a live database checking your work.

Expert currently has two missions, built for very different reasons — a
small picker row appears above the mission whenever a difficulty has more
than one.

## Beginner — "The Lazy Login"

Log in as `admin` without the real password. Both a tautology
(`' OR '1'='1`) and comment truncation (`admin'--`) are accepted —
whichever one you reach for.

## Intermediate — "The Customer List Leak"

Make a single-customer lookup return every row in the table. A tautology
or a (slightly roundabout) UNION both count.

## Expert, mission 1 — "Steal the Payment Data"

No schema is given up front. You have to discover the real table and
column names yourself — through the same `INFORMATION_SCHEMA` enumeration
real attackers use — before you can craft the final exfiltration payload.
No hints, and the answer can't be revealed at this difficulty.

It's a genuine multi-stage recon-then-exploit chain against one search box:

1. Work out the column count with a `UNION SELECT NULL,NULL--` probe.
2. Enumerate real table names via `INFORMATION_SCHEMA.TABLES`.
3. Enumerate a specific table's columns via `INFORMATION_SCHEMA.COLUMNS`.
4. Exfiltrate the actual data once you know where it lives.

## Expert, mission 2 — "The Guarded Admin Form"

There's no single goal here — **what you're able to get back out of the
form IS the goal, and it defines the level you solved it at.** Four
fields feed one combined query. Exactly one (`Account ID`) is a real bound
parameter; the other three aren't, and they're not equally exposed:

| Field | What it's actually vulnerable to | Tier if you crack it |
|---|---|---|
| Account ID | Nothing — it's a genuine, bound parameter | — |
| Sort by | ORDER BY identifier injection | 🥉 Bronze |
| Notes | UNION reaching low-value columns | 🥈 Silver |
| Order reference | UNION reaching `CreditCardNumber` directly | 🥇 Gold |

You don't have to solve it in one pass — your best tier is tracked and
carries over between attempts, the same way the recon mission's discovered
facts do.

## The "Discovered so far" list

In both Expert missions, each stage/tier you clear adds to a running
**"🔎 Discovered so far"** list in the window — your own build-up of
findings, the same way a real assessment accumulates evidence before the
final attack.

Back to the **[Feature List](features/overview.md)**.
