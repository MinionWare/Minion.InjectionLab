# Difficulty Levels

The **Beginner / Intermediate / Expert** selector in the left nav changes
one specific thing: **how forgiving the weak "Partial" fixes are** at
catching an attack. It does not change which techniques exist, hide any
scenario, or alter the real mechanics shown in SQL/C#/PowerShell.

## What actually changes

Most "Partial" fixes in the [attack catalog](../catalog/overview.md) are a
keyword blacklist — the kind of fix real teams actually ship, and the kind
that always has a gap. The blacklist's strictness scales with difficulty:

| Difficulty | Matching | Example |
|---|---|---|
| **Beginner** | Exact case, the literal blocked word only | Typing `or` instead of `OR` sails straight through. |
| **Intermediate** | Case-insensitive | `or`, `Or`, `OR` are all caught. |
| **Expert** | Case-insensitive, plus one or two related keywords added to the list | e.g. `UNION` gets blocked alongside `OR`. |

The lesson is the same at every level, just harder to find as you go up:
**a blacklist can only ever catch a phrasing someone thought to list.**
Every scenario ships at least one sample payload that needs none of the
blocked words at all (the classic `admin'--` truncation has no `OR` in it
whatsoever) — and that payload sails through no matter which difficulty
you're on.

## Difficulty also controls your hint budget

[Challenge Mode](../challenge-mode.md) scales the other way — higher
difficulty means *less* help, not more attack to crack:

| Difficulty | Hints available | Can reveal the answer? |
|---|---|---|
| **Beginner** | All of them | Yes |
| **Intermediate** | About half | Yes |
| **Expert** | Just one | No — you have to crack it yourself |

## What never changes

- The real, generated SQL/C#/PowerShell for the Vulnerable version and the
  "Best" fix — those are difficulty-independent on purpose, since the real
  mechanics don't get easier or harder depending on skill level.
- Which attacks are in the catalog, their premise, or their challenge goal.

Difficulty is best thought of as **"how good is the naive mitigation, and
how much help do you get,"** not **"how hard is this attack."**

## A separate Difficulty selector in Quiz Mode

[Quiz Mode](../quiz-mode.md) has its own Beginner/Intermediate/Expert
selector, independent of this one — same labels, different job. There, it
controls how much of each question's own guidance (title, premise, goal,
hints) you're shown before solving it, not blacklist strictness or hint
budget. See **[Quiz Mode](../quiz-mode.md)** for the details.
