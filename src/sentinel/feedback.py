# SPDX-License-Identifier: Apache-2.0
"""Append-only analyst feedback store.

Feedback is recorded for threshold recalibration and rule-improvement review.
There is deliberately no retraining path here: production models are never
retrained from unreviewed analyst input.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from sentinel.schemas import AnalystFeedback, SignedFeedback

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


SIGNING_KEY_VERSION = "hmac-v1"


def sign_feedback(feedback: AnalystFeedback, signing_key: bytes) -> SignedFeedback:
    """HMAC-sign a feedback record over its canonical JSON (Phase 6)."""
    digest = hmac.new(signing_key, feedback.model_dump_json().encode("utf-8"), hashlib.sha256)
    return SignedFeedback(
        feedback=feedback,
        signature=digest.hexdigest(),
        key_version=SIGNING_KEY_VERSION,
    )


def verify_feedback(signed: SignedFeedback, signing_key: bytes) -> bool:
    """True when the signature matches; detects post-hoc tampering of stores."""
    expected = hmac.new(
        signing_key, signed.feedback.model_dump_json().encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signed.signature)
