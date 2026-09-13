"""Append-only analyst feedback store.

Feedback is recorded for threshold recalibration and rule-improvement review.
There is deliberately no retraining path here: production models are never
retrained from unreviewed analyst input.
"""

from __future__ import annotations

import json
from pathlib import Path

from trajectory.schemas import AnalystFeedback

VERDICTS = {
    "true_positive",
    "false_positive",
    "wrong_attack_type",
    "late_alert",
    "insufficient_evidence",
    "useful_alert",
}


class FeedbackStore:
    """JSONL-backed store; every record is timestamped and append-only."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def record(
        self,
        subject_id: str,
        verdict: str,
        analyst: str,
        *,
        comment: str = "",
        recorded_at=None,
    ) -> AnalystFeedback:
        if verdict not in VERDICTS:
            raise ValueError(f"unknown verdict: {verdict}")
        if recorded_at is None:
            from datetime import UTC, datetime

            recorded_at = datetime.now(UTC)
        feedback = AnalystFeedback(
            subject_id=subject_id,
            verdict=verdict,  # type: ignore[arg-type]
            analyst=analyst,
            recorded_at=recorded_at,
            comment=comment,
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(feedback.model_dump(mode="json")) + "\n")
        return feedback

    def load(self) -> list[AnalystFeedback]:
        if not self.path.exists():
            return []
        return [
            AnalystFeedback.model_validate_json(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def verdict_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for feedback in self.load():
            counts[feedback.verdict] = counts.get(feedback.verdict, 0) + 1
        return counts

    def false_positive_rate(self) -> float | None:
        """Share of verdicts that are false positives; None when no feedback."""
        records = self.load()
        if not records:
            return None
        fps = sum(1 for f in records if f.verdict == "false_positive")
        return fps / len(records)
