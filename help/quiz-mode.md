# Quiz Mode

`View > Quiz mode`, or the "🏆 Quiz mode" button in the left nav, opens a
separate window with three capstone missions — one per difficulty. Unlike
per-attack [Challenge Mode](challenge-mode.md), a quiz mission has no single
canonical answer: **any payload that genuinely achieves the stated goal
counts**, graded by rule-based pattern matching the same way everything
else in this app is, not a live database checking your work.

## The three missions

- **Beginner — "The Lazy Login"**: log in as `admin` without the real
  password. Both a tautology (`' OR '1'='1`) and comment truncation
  (`admin'--`) are accepted — whichever one you reach for.
- **Intermediate — "The Customer List Leak"**: make a single-customer
  lookup return every row in the table. A tautology or a (slightly
  roundabout) UNION both count.
- **Expert — "Steal the Payment Data"**: no schema is given up front. You
  have to discover the real table and column names yourself — through the
  same `INFORMATION_SCHEMA` enumeration real attackers use — before you can
  craft the final exfiltration payload. No hints, and the answer can't be
  revealed at this difficulty.

## How the Expert mission works

It's a genuine multi-stage recon-then-exploit chain against one search box:

1. Work out the column count with a `UNION SELECT NULL,NULL--` probe.
2. Enumerate real table names via `INFORMATION_SCHEMA.TABLES`.
3. Enumerate a specific table's columns via `INFORMATION_SCHEMA.COLUMNS`.
4. Exfiltrate the actual data once you know where it lives.

Each stage you clear adds to a running **"Discovered so far"** list in the
window — your own build-up of schema knowledge, the same way a real
assessment accumulates findings before the final attack.

Back to the **[Feature List](features/overview.md)**.
