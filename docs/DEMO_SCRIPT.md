# Demo voiceover — read straight down

Read it top to bottom, out loud, in order. Bracketed lines are stage directions —
skip them when you read. Nothing else is a note to yourself.

**Recorded against the live console on 2026-09-30.** Every value quoted below
was read off the screen that day.

---

## Before you press record — three things that will bite you

1. **The Forecast tab opens on the wrong window.** It defaults to window 72 of
   72, which reads `PEAK PROBABILITY 0.239`, `PREDICTED STAGE Benign`,
   `FORECAST LEAD not crossed`. That is a boring frame. **Drag the "Forecast
   from window" slider left, to about 40, before you talk.** A rerun takes a few
   seconds — wait for the numbers to change.
2. **This release bundle has no temporal model.** The Forecast tab says so
   itself: *"Temporal model artifacts were not provided; the probability
   timeline is a baseline-only decay estimate."* Do not say "GRU forecast" on
   camera. Say what the panel says.
3. **The console runs `synthetic-recon-lateral-v2`.** That is the corpus
   `hackathon/harden` replaces — the one where a single feature scores ROC-AUC
   0.9833 and 97 of 98 features are decoration. If a judge opens PR #9 and sees
   this, the demo is over. **Land PR #9 and redeploy before you record.**

Cold start is about 17 seconds. Start recording before you switch tabs and leave
the silence in — it looks deliberate and it saves you a re-record.

---

## Open

[black screen, type on screen: "is this flow malicious?"]

One flow. One score. Malicious, or not.

That's the whole question. And notice what it can't do. It can't tell the
difference between a hundred failed logins inside four seconds and one person
mistyping a password. It can't tell you what's coming. And — this is the one that
should worry you — it cannot tell you that it *doesn't know*. Every one of those
systems will confidently say "low" when what they actually mean is "I never
looked."

SENTINEL separates three answers. High risk. Low risk. *I don't know.* And it
never lets the third one quietly collapse into the second.

It also does something else, before you ask. It tells you what it was given.

[console, header line visible]

SENTINEL — network attack forecasting. And that header says, in plain words, that
this traffic is synthetic. Generated, not captured. It volunteers that, because
the whole point of the next four minutes is that the numbers you're about to see
are real measurements — and the data underneath them isn't.

And one more thing you'll see everywhere. Every panel is labelled *observed* or
*forecast*, and they are never the same colour. That's a rule, not a taste
thing. The one thing you cannot afford in this field is confusing a measurement
with a guess.

## The split

[Overview tab]

The split comes before the score. Whole scenarios go into train, validation or
test *before a single window is built*. So no window from an attack the model
studied ever appears in the number you're about to see.

That sounds fussy. It isn't. Train on a split, then measure on windows from the
same attack, and you didn't measure a detector — you measured your own memory.

## The forecast

[Forecast tab — **you have already dragged the slider to ~40**]

One window of traffic in. Out comes a probability timeline, five horizons ahead.

Under it, the stage. Not "suspicious" — a named stage, with the MITRE
technique number next to it.

[point at the stage block]

And here — read this line with me, because it's the one that matters. It says:
*"No documented stage rule fired on the current window. This is not a low-risk
reading."*

Think about that. The system has three options here: high risk, low risk, or I
don't know. It picked the third one. And it refused to let you read "I don't
know" as "probably fine." That's the behaviour you actually want from a thing
whose job is to wake someone up.

[driving features]

And under that — the why. Each feature, how far from normal it is, and which
direction it pushed. It says exactly what it is: *exact local attribution for a
linear model, not SHAP.* Not a story written after the fact. The model's own
arithmetic.

## The ledger

[Trust ledger block]

Press *Record alert*. Every alert is chained to the one before it by a hash.

[press Verify, then Simulate tampering, then Reset]

Now read the integrity stat before and after.

And I'll be exact, because this is the kind of word that gets stretched — it's a
local hash chain. It is not a blockchain. A determined rewrite would pass. What
it buys you is that *casual* tampering doesn't go unnoticed.

## Live

[Live tab]

Enough replay. This is live.

[Event source is already "Synthetic attack replay" — press ▶ Start, wait for the risk grid]

Same trained models, same threshold. Nine rules, each mapped to a technique.

Here's the whole attack surface at once — every attack type, every probability,
side by side — instead of one alert at a time.

[point at Correlated incidents]

And this. The system groups them. One intrusion, the likely path through it, the
assets in scope. An analyst doesn't get nineteen alerts. They get: this is one
thing, here's how it moves, here's what it can reach.

[scroll to Force Attack]

And this button doesn't simulate. Nine of them, one per phase, each labelled
with the technique it's aimed at. They fire real HTTP requests at a deliberately
vulnerable target — on loopback, inside this container, never on the internet.

## The world model

[World model tab]

This one's different. Everything so far forecasts a score. This learns the
*dynamics* of the network state and imagines forward with no observations at all.
Then we score it on states it had to invent.

[point at the metrics row, then the chart]

And here's the part a normal demo cuts. Open-loop skill — how much better it is
than just repeating the last window — is around zero, and it goes *negative* as
you push further out. It does not reliably beat the trivial baseline.

We hoped it would. The number's on screen because we didn't tune it away.

## Shipped

[landing page, then the API /health response]

This isn't on my laptop. Same build. The API is authenticated — health is open,
everything else needs a key, and the published demo key is rejected. That's on
purpose.

## Close

[limitations card]

So what is this? A research prototype. Synthetic traffic, generated not captured —
the header says so in those words. No field-validated detection rate, and I
won't claim one. Lead time on this data is zero windows: nothing fires before an
attack starts. That's a property of the dataset, not the architecture.

What it does have is a probability that says where it came from, a stage that
refuses to guess, an explanation you can check against the features, and an
alert history that resists casual tampering.

Thanks.

---

## If you're cut short — the 90 second version

**Open → The split → The forecast → Close.** Four sections.

Drop the ledger, live, world model and shipped. If you only keep two sentences,
keep these:

> *"It picked 'I don't know' — and it refused to let you read that as
> 'probably fine'."*

> *"Open-loop skill is around zero. We hoped it would. The number's on screen
> because we didn't tune it away."*

---

## What to show, what to skip

| Screen | Show? | Why |
|---|---|---|
| Overview | yes | the split argument |
| **Forecast** | **yes, hero shot** | stage + attribution + the honesty line |
| World model | yes | the unflattering number |
| Live | yes | press Start first, or the risk grid never renders |
| Trust ledger | yes | three button presses, ten seconds |
| Metrics | one line | point at the Split audit — "disjoint scenarios: yes" |
| Replay | skip | needs a button press, same ground as Forecast |
| States | skip | raw features, no argument |
| Comparison | skip | model-vs-model table |
| Demo | skip | overlaps Live |
| Attack story | skip | pretty, not load-bearing |

## Cut list

Do not show: the sidebar dataset expander (invites "which dataset?" mid-demo),
the `Replay` walk-forward, or anything under `States`. Do not read the feature
names aloud — there are ninety-eight and they mean nothing out loud.

## Pre-flight

```bash
uv run pytest -q
uv run python scripts/check_claims.py
```

Still frames, captioned, of every screen this script mentions:
`docs/shots/index.html` — regenerate with
`uv run --with playwright python scripts/capture_demo_frames.py core`, then
`live`, then `deck`.

Then, in the browser, on the deployed console:

- [ ] Header line reads `SYNTHETIC — generated, not captured traffic`
- [ ] Forecast tab: drag the window slider, confirm the stage block fills in
- [ ] Live tab: press ▶ Start, confirm the risk grid appears
- [ ] Force Attack: press one button, confirm it responds — **this one pushes to
      the hosted API, which needs a key. If it errors, cut it.**
- [ ] Trust ledger: Record alert → Verify → Simulate tampering → Reset

## Numbers that are safe to say out loud

Only these five were measured on the deployed console on 2026-09-30:

- Cold start **~17 s**.
- Header: **432 windows**, **98 features**, **seed 42**.
- Forecast threshold on the release bundle: **0.45**.
- World model: **test reconMSE 0.3447**, **stage macro-F1 0.985**.
- Open-loop skill: **around zero, negative at longer horizons**.

Everything else — point at it. Never say a number you cannot see on screen at
the moment you're saying it. That rule is the whole project.
