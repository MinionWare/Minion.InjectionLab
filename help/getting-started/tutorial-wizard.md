---
support_id: injectionlab.tutorial
---
# The Opening Tutorial

On first launch, this nine-step wizard — **"How SQL Injection Actually
Works"** — pops up automatically on top of the [welcome screen](welcome.md),
built to teach the underlying concept once, clearly, assuming you've never
heard the term before. It's deliberately simpler than
the real [attack catalog](../catalog/overview.md): five of the nine steps
carry a tiny, single-field live demo (type something, see the real SQL it
builds and a plain-English, color-coded read of what just happened), and
the whole thing takes a few minutes.

## The nine steps

1. **What is a SQL injection, really?** — the core idea: a database can't
   tell your data from its own code once the two are glued together as text.
2. **The core flaw: your input becomes part of the command** *(demo)* —
   type a single quote mark and watch it break a query in half.
3. **Technique 1: the Always-True Trick** *(demo)* — the classic tautology
   login bypass (`' OR '1'='1`).
4. **Technique 2: UNION — asking for someone else's data** *(demo)* —
   gluing a second, unrelated `SELECT` onto the first.
5. **Technique 3: Blind injection — when there's nothing to see** *(demo)*
   — extracting a yes/no answer with no visible data at all.
6. **Technique 4: Stacked queries — smuggling in a second statement**
   *(demo)* — what a semicolon really does to a batch.
7. **Why this keeps happening** — the same root cause shows up anywhere a
   command and its data are built as one string, not just in SQL.
8. **The fix: treat data as data** — parameterization, explained
   conceptually, before you see it applied a dozen different ways in the
   catalog.
9. **You're ready — go explore** — a pointer to the catalog, the
   [Difficulty selector](difficulty-levels.md), and
   [Challenge Mode](../challenge-mode.md).

## Reopening it

Click **🎓 Tutorial** in the left nav, or `Help > Show tutorial` in the
menu bar, any time. It never shows itself automatically again after the
first run.

Once you've been through it, the **[Attack Catalog](../catalog/overview.md)**
is where the real depth lives — twenty-six techniques, each with full
SQL/C#/PowerShell, graded fixes, and a hands-on challenge. When you're
comfortable with it, **[Quiz Mode](../quiz-mode.md)** tests you across all
of them at once.
