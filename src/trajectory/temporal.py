"""GRU-based temporal state-transition model with multi-horizon probability prediction.

Requires the optional ``deep-learning`` extra (PyTorch)::

    uv sync --extra deep-learning

The model trains one binary classifier per horizon so the full probability
timeline is produced without recursive state prediction. This is the honest
MVP: multi-horizon prediction using the same leakage-safe sequence samples
and training-only feature schema as the logistic-regression baseline.
"""

from __future__ import annotations

import hashlib
import platform
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from trajectory.features import FeatureSchema, vectorize_states
from trajectory.metrics import BinaryMetrics, compute_binary_metrics
from trajectory.schemas import SequenceSample, SplitManifest

MODEL_VERSION = "gru-temporal-v1"
SPLIT_NAMES = ("train", "validation", "test")

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset
except ImportError:
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]


def _require_torch() -> None:
    if torch is None:
        raise RuntimeError("Temporal model requires PyTorch: uv sync --extra deep-learning")


class TemporalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hidden_size: int = Field(default=32, ge=4)
    num_layers: int = Field(default=1, ge=1)
    dropout: float = Field(default=0.1, ge=0, lt=1)
    learning_rate: float = Field(default=1e-3, gt=0)
    batch_size: int = Field(default=32, ge=4)
    max_epochs: int = Field(default=100, ge=1)
    early_stopping_patience: int = Field(default=10, ge=1)


class HorizonResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    horizon: int = Field(ge=1)
    metrics: dict[str, BinaryMetrics]
    best_epoch: int = Field(ge=0)
    training_seconds: float
    model_sha256: str


class TemporalResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model_version: str = MODEL_VERSION
    config: TemporalConfig
    feature_schema: FeatureSchema
    split_manifest: SplitManifest
    horizons: list[HorizonResult]
    feature_names: list[str]
    runtime: dict[str, str]


@dataclass(frozen=True)
class TemporalRun:
    models: dict[int, nn.Module]
    result: TemporalResult


class _GRUClassifier(nn.Module):  # type: ignore[misc]
    def __init__(self, input_dim: int, hidden_size: int, num_layers: int, dropout: float):
        super().__init__()
        self.gru = nn.GRU(
            input_dim,
            hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        self.head = nn.Linear(hidden_size, 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        _, h = self.gru(x)
        return self.head(h[-1]).squeeze(-1)


def train_temporal(
    labelled_states: list,
    samples: list[SequenceSample],
    manifest: SplitManifest,
    *,
    feature_schema: FeatureSchema,
    config: TemporalConfig,
    seed: int,
    max_horizon: int = 5,
) -> TemporalRun:
    _require_torch()
    torch.manual_seed(seed)
    np.random.seed(seed)
    torch.use_deterministic_algorithms(True)

    states_by_key = {item.state_key: item for item in labelled_states}
    assignment = _assignment(manifest)
    feature_dim = feature_schema.width
    seq_len = len(samples[0].input_state_keys)

    horizon_results: list[HorizonResult] = []
    models: dict[int, _GRUClassifier] = {}

    for horizon in range(1, max_horizon + 1):
        from trajectory.targets import build_sequence_samples as _build

        h_samples = _build(labelled_states, sequence_length=seq_len, horizon=horizon)
        if not h_samples:
            continue

        grouped = _group_by_split(h_samples, assignment)
        if not grouped["train"] or not grouped["test"]:
            continue

        train_x, train_y = _vectorize_group(grouped["train"], states_by_key, feature_schema)
        val_x, val_y = _vectorize_group(
            grouped.get("validation", []), states_by_key, feature_schema
        )
        test_x, test_y = _vectorize_group(grouped["test"], states_by_key, feature_schema)

        if len(np.unique(train_y)) < 2:
            continue

        model, best_epoch, train_sec = _train_one(
            train_x, train_y, val_x, val_y, feature_dim, config, seed
        )
        models[horizon] = model

        metrics: dict[str, BinaryMetrics] = {}
        for name, x, y in [
            ("train", train_x, train_y),
            ("validation", val_x, val_y),
            ("test", test_x, test_y),
        ]:
            if y.size == 0:
                continue
            with torch.no_grad():
                probs = torch.sigmoid(model(torch.tensor(x))).numpy()
            metrics[name] = compute_binary_metrics(y, probs, threshold=0.5)

        import io

        buf = io.BytesIO()
        torch.save(model.state_dict(), buf)
        checksum = hashlib.sha256(buf.getvalue()).hexdigest()

        horizon_results.append(
            HorizonResult(
                horizon=horizon,
                metrics=metrics,
                best_epoch=best_epoch,
                training_seconds=train_sec,
                model_sha256=checksum,
            )
        )

    result = TemporalResult(
        config=config,
        feature_schema=feature_schema,
        split_manifest=manifest,
        horizons=horizon_results,
        feature_names=feature_schema.names,
        runtime={
            "python": platform.python_version(),
            "torch": torch.__version__,
            "numpy": np.__version__,
            "platform": platform.platform(),
        },
    )
    return TemporalRun(models=models, result=result)


def _train_one(
    train_x: np.ndarray,
    train_y: np.ndarray,
    val_x: np.ndarray,
    val_y: np.ndarray,
    feature_dim: int,
    config: TemporalConfig,
    seed: int,
) -> tuple[_GRUClassifier, int, float]:
    torch.manual_seed(seed)
    model = _GRUClassifier(feature_dim, config.hidden_size, config.num_layers, config.dropout)
    pos = int(train_y.sum())
    neg = len(train_y) - pos
    pos_weight = torch.tensor([neg / max(pos, 1)], dtype=torch.float32)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.Adam(model.parameters(), lr=config.learning_rate)
    train_ds = TensorDataset(torch.tensor(train_x), torch.tensor(train_y))
    train_loader = DataLoader(train_ds, batch_size=config.batch_size, shuffle=True)

    best_val_loss = float("inf")
    best_epoch = 0
    best_state = None
    patience = 0

    started = time.perf_counter()
    for epoch in range(config.max_epochs):
        model.train()
        for xb, yb in train_loader:
            optimizer.zero_grad()
            loss = criterion(model(xb), yb)
            loss.backward()
            optimizer.step()

        if val_y.size > 0:
            model.eval()
            with torch.no_grad():
                val_loss = criterion(model(torch.tensor(val_x)), torch.tensor(val_y)).item()
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                best_epoch = epoch + 1
                best_state = {k: v.clone() for k, v in model.state_dict().items()}
                patience = 0
            else:
                patience += 1
                if patience >= config.early_stopping_patience:
                    break

    if best_state is not None:
        model.load_state_dict(best_state)
    return model, max(best_epoch, 1), time.perf_counter() - started


def predict_horizon(model: _GRUClassifier, sequence: np.ndarray) -> float:
    model.eval()
    with torch.no_grad():
        return float(torch.sigmoid(model(torch.tensor(sequence))).item())


def save_temporal_artifacts(run: TemporalRun, output_dir: str | Path) -> dict[str, Path]:
    """Persist the result JSON, report, and per-horizon GRU weights to disk."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    result_path = out / "temporal_result.json"
    result_path.write_text(run.result.model_dump_json(indent=2), encoding="utf-8")
    report_path = out / "temporal_report.md"
    report_path.write_text(_render_report(run.result), encoding="utf-8")
    weights_dir = out / "weights"
    weights_dir.mkdir(parents=True, exist_ok=True)
    for horizon, model in run.models.items():
        torch.save(model.state_dict(), weights_dir / f"model_h{horizon}.pt")
    return {"result": result_path, "report": report_path, "weights": weights_dir}


def load_temporal_models(result: TemporalResult, model_dir: str | Path) -> dict[int, nn.Module]:
    """Load per-horizon GRU weights previously written by save_temporal_artifacts.

    Horizons whose weight file is missing are simply absent from the returned
    mapping, so callers can degrade explicitly instead of guessing.
    """
    _require_torch()
    weights_dir = Path(model_dir) / "weights"
    models: dict[int, nn.Module] = {}
    for horizon_result in result.horizons:
        path = weights_dir / f"model_h{horizon_result.horizon}.pt"
        if not path.is_file():
            continue
        model = _GRUClassifier(
            len(result.feature_names),
            result.config.hidden_size,
            result.config.num_layers,
            result.config.dropout,
        )
        model.load_state_dict(torch.load(path, map_location="cpu"))
        model.eval()
        models[horizon_result.horizon] = model
    return models


def _render_report(result: TemporalResult) -> str:
    lines = [
        "# Temporal Model Report",
        "",
        "## Experiment Identity",
        "",
        f"- Feature version: {result.feature_schema.version}",
        "- Split strategy: scenario-held-out (same as baseline)",
        f"- Model version: {result.model_version}",
        f"- Horizons evaluated: {', '.join(str(h.horizon) for h in result.horizons)}",
        f"- Configuration: `{result.config.model_dump_json()}`",
        f"- Runtime: {', '.join(f'{k}={v}' for k, v in result.runtime.items())}",
        "",
    ]
    for h in result.horizons:
        lines += [
            f"### Horizon +{h.horizon}",
            "",
            f"- Best epoch: {h.best_epoch}",
            f"- Training time: {h.training_seconds * 1000:.1f} ms",
            f"- Model SHA-256: `{h.model_sha256}`",
            "",
            "| Metric | " + " | ".join(name for name in SPLIT_NAMES if name in h.metrics) + " |",
            "|---|" + "---:|" * len(h.metrics),
        ]
        for label, attr in [
            ("Precision", "precision"),
            ("Recall", "recall"),
            ("F1", "f1"),
            ("False-positive rate", "false_positive_rate"),
            ("PR-AUC", "pr_auc"),
        ]:
            vals = [
                _fmt(getattr(h.metrics[name], attr)) for name in SPLIT_NAMES if name in h.metrics
            ]
            lines.append(f"| {label} | " + " | ".join(vals) + " |")
        lines.append("")

    lines += [
        "## Interpretation",
        "",
        "- Each horizon trains an independent GRU on the same data with a different target window.",
        "- The full timeline is not a recursive rollout; it is a multi-horizon prediction.",
        "- Results describe the evaluated dataset and split only.",
        "",
    ]
    return "\n".join(lines)


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.4f}"


def _assignment(manifest: SplitManifest) -> dict[str, str]:
    assignment: dict[str, str] = {}
    for name, scenarios in (
        ("train", manifest.train_scenarios),
        ("validation", manifest.validation_scenarios),
        ("test", manifest.test_scenarios),
    ):
        for scenario in scenarios:
            assignment[scenario] = name
    return assignment


def _group_by_split(
    samples: list[SequenceSample], assignment: dict[str, str]
) -> dict[str, list[SequenceSample]]:
    grouped: dict[str, list[SequenceSample]] = {name: [] for name in SPLIT_NAMES}
    for s in samples:
        split = assignment.get(s.scenario_id)
        if split:
            grouped[split].append(s)
    return grouped


def _vectorize_group(
    samples: list[SequenceSample],
    states_by_key: dict[str, object],
    schema: FeatureSchema,
) -> tuple[np.ndarray, np.ndarray]:
    if not samples:
        return np.empty((0, 0), dtype=np.float32), np.empty((0,), dtype=np.float32)
    xs, ys = [], []
    for s in samples:
        features = [
            vectorize_states([states_by_key[k].state], schema)[0] for k in s.input_state_keys
        ]
        xs.append(np.array(features, dtype=np.float32))
        ys.append(float(s.target.target_infiltration))
    return np.stack(xs), np.array(ys, dtype=np.float32)
