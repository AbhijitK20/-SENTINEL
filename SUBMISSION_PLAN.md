# Submission Plan

## Required Deliverables

- Source code link
- README with setup and usage
- Architecture document, maximum two pages
- Demo video, maximum two minutes
- Technical presentation, maximum five slides

## Idea Presentation

The six-slide idea deck follows `PRESENTATION_OUTLINE.md` and is generated, not hand-edited:

```text
uv run --group presentation python scripts/build_deck.py --pdf
```

Outputs land in `deliverables/` as `Trajectory_SIH26153_Idea_Deck.pptx` and `.pdf`. Every unverified value (Team ID, market figures, metrics, links) is rendered as a highlighted `[ADD ...]` placeholder; the deck is not submittable until `pdftotext deliverables/Trajectory_SIH26153_Idea_Deck.pdf - | grep -c "\[ADD"` returns zero. Note the two different slide limits: the idea PPT is six slides (SIH template), while the technical presentation listed above is capped at five.

## Supporting Evidence

- Dataset preparation and license notes
- Training configuration and model weights
- Baseline and temporal metrics
- Forecast lead-time result
- Explainability example
- Limitations and offline verification

## Final Audit

- PS ID and title are correct.
- Flow and packet-level support is demonstrated or accurately qualified.
- Model performs state-transition forecasting and K-step rollout.
- Logistic-regression comparison is present.
- All claims in video and slides match implementation and results.
