# Quiz Mode

`View > Quiz mode`, or the "🏆 Quiz mode" button in the left nav, opens a
real, multi-question quiz drawn live from the **entire attack catalog** —
six random scenarios every time you start one, no repeats, no fixed
question set.

Unlike per-attack [Challenge Mode](challenge-mode.md), a quiz question is
graded exactly the way the in-app decision-path diagram already classifies
your input for that scenario — there's no separate canonical answer to
memorize. You solve a question the same way you'd solve that scenario
anywhere else in the app.

## How difficulty works here

Difficulty doesn't change which scenarios can come up or how they're
graded — it changes **how much of the scenario's own guidance you're
shown before you have to solve it**:

| Difficulty | What you see |
|---|---|
| **Beginner** | Title, category, the full premise, the goal, and hints — the complete picture, same as Challenge Mode in the main catalog. |
| **Intermediate** | Just the premise. You know the story, but not which named technique applies or what the specific goal is. |
| **Expert** | **Only the bare mock form.** No premise, no title, no goal, no hints. Recognizing what's wrong and crafting a working payload with zero guidance is the whole test. |

That's deliberate: at Expert, you're not told "this is a UNION scenario"
or "try to leak the Users table" — figuring that out yourself is exactly
what distinguishes an expert from someone following a checklist.

## Playing a session

1. Pick a difficulty.
2. Read whatever the difficulty shows you, then fill in the mock form —
   the real SQL/C#/PowerShell update live, same as everywhere else.
3. Click **Submit**. If your input classifies as a genuine attack (not
   just an unusual-looking but harmless value), it counts — the same
   check that drives the "Where you're headed" diagram throughout the
   app.
4. Didn't solve it? Adjust and resubmit, or move on — **Next question**
   always advances regardless.
5. After six questions, see your final score and start a fresh,
   newly-randomized quiz any time.

Back to the **[Feature List](features/overview.md)**.
