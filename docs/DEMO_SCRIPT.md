# Demo voiceover — read straight down

~650 words, about 4 minutes 30 at a normal pace. Bracketed lines are stage
directions — skip them when you read. Everything else is said out loud, in
order, top to bottom. Don't stop to think. If you lose your place, the last
sentence you remember is always the one that matters.

---

## Open

[black screen, type on screen: "is this flow malicious?"]

That's the question an intrusion detection system answers. One flow, one score.

And it's the right question. It's just a bad question to *stop* at. Because by
the time a system has decided that this flow is malicious — the data has already
left.

SENTINEL asks the next one. Not what is happening. What happens next, and why.

## Provenance

[cold start is about seventeen seconds — start talking over the title card, not the console]

Here's the console. Before I touch anything, look at the header. It says what
dataset this is, how many windows, what the model was trained on, how many
features it reads. Nothing was trained just now. It loaded a bundle that was
built once, and checksummed.

[point at the header — don't read the numbers]

One more thing you'll see everywhere. Every panel is labelled *observed* or
*forecast*, and they are never the same colour. That's a rule, not a taste
thing. The one thing you cannot afford in this field is confusing a measurement
with a guess.

## Split

[Overview tab]

The split comes before the score. Scenarios go into train, validation and test
*whole*. So no window from an attack the model studied ever shows up in the
number you're about to see.

That sounds fussy. It isn't. If you train on a split and then measure on windows
from the same attack, you didn't measure a detector. You measured your own
memory.

## Forecast

[Forecast tab — this is the centre of the video, pause and let it breathe]

One window of traffic in. Out comes a probability timeline — five horizons out.

Under it, the stage. Not "suspicious". Lateral movement. With the MITRE
technique number next to it.

[show the attribution panel]

And under that — the why. These are the driving features, ranked by how much
each one actually moved the probability. Not a story written after the fact.
These are the model's own contributions.

[point at the warning on the panel]

And one caveat, which is printed on the panel and which I'm going to say out
loud anyway. This capture was flow-only. The packet-level features weren't
available, so the forecast says so. It does not quietly substitute a zero for
something it never measured. If we can't see it, it tells you it's missing.

## Ledger

[ledger panel on the same tab]

Press *Record alert*. It's written to an append-only hash chain, and every
record commits to the one before it. Read the integrity stat.

Now — I want to be exact about that, because it's the kind of word that gets
stretched. It is a local hash chain. It is not a blockchain. A full rewrite and
re-hash would pass. What it buys you is that casual tampering doesn't go
unnoticed.

## Live

[Live tab]

Enough replay. This is live detection.

[attack-type risk grid]

Nine rules, each mapped to a technique, each with a measured threshold. Here's
the whole attack surface at once — every attack type, every probability, side by
side — instead of one alert at a time.

[correlated incidents]

And this. The system groups them. One intrusion, the likely path through it, and
the assets in scope. An analyst doesn't get nineteen alerts. They get: this is
one thing, here's how it moves, here's what it can reach.

[Force Attack]

And this button doesn't simulate anything. It runs the actual attack scripts and
detects the result. The target is deliberately vulnerable and it listens on
loopback inside this container, so it's never on the internet.

## World model

[World model tab]

This one's different. Most of this is score forecasting. This learns the dynamics
of the network state and imagines forward with *no observations at all*. Then we
score it on states it had to invent.

[show the skill figure — pause]

And here's the part a normal demo would cut. Open-loop skill — how much better it
is than just repeating the last window — is negative right now. It doesn't beat
the trivial baseline. We hoped it would.

The number's on screen because we didn't tune it away.

## Shipped

[landing page, then /health]

This isn't running on my laptop. Same build that's live there. The API is
authenticated — health is open, everything else needs a key, and the published
demo key is rejected. That's on purpose.

## Close

[limitations card]

So what is this? It's a research prototype. Synthetic replay — which shows the
pipeline learns structure instead of a shortcut. There's no field-validated
detection rate here and I won't claim one. Forecast lead time on this data is
zero windows: nothing fires before an attack starts. That's a property of the
dataset, not the architecture.

What it does have is a probability that says where it came from, a stage with a
MITRE reference, an explanation you can check against the features, and an alert
history that resists casual tampering.

Thanks.

---

## Cut list

Don't show these: Replay, States, Comparison, Metrics, Demo, Attack story. Same
ground as tabs above, no new argument. Attack story is fine as outro B-roll if
you need to reach five minutes.

**Ninety-second version:** Open → Split → Forecast → Close. Keep the attribution
in Forecast and keep the negative skill in Close. Drop everything else. Those two
are the difference between a pitch and evidence.

## Pre-flight

```bash
uv run pytest -q
uv run python scripts/check_claims.py
```

Then click through the console once yourself. Don't record a build you haven't
seen.

## The only four things you may say out loud

Console cold start is about **17 seconds**. Health returns **`status: ok`**. The
API **rejects the demo key**. Open-loop skill is **negative**.

Everything else — point at it. Never recite a number you can't see on screen at
the moment you're saying it.
