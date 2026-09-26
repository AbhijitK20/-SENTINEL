# SPDX-License-Identifier: Apache-2.0
"""Train the RSSM world model on windowed network states.

The training signal is the state trajectory itself, not a flow label:

    reconstruct o_t  +  KL(q(z_t | h_t, e_t) || p(z_t | h_t))
                    +  BCE(risk_t, infiltration_t) + CE(stage_t, stage_t)

Only *training* scenarios contribute gradients; the validation split selects the
epoch and the test split is scored exactly once, at the end. Feature statistics
come from the caller-supplied ``FeatureSchema``, which is fitted on training
states elsewhere in the pipeline, so no window of another split is seen here.

Artifacts written by :func:`save_world_model_artifacts` are the on-disk twin of
``sentinel.temporal``'s: a result JSON, the weights, and a markdown report.
"""

from __future__ import annotations

import hashlib
import io
import platform
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from sentinel.features import FeatureSchema, vectorize_states
from sentinel.metrics import BinaryMetrics, compute_binary_metrics
from sentinel.schemas import SPLIT_NAMES, SplitManifest, split_assignment
from sentinel.targets import LabelledState
from sentinel.world_model.model import (
    CORE_TYPES,
    WORLD_MODEL_VERSION,
    RSSMCore,
    dream_consistency,
    dream_trajectory,
    kl_divergence,
    kl_weight,
    rssm_loss,
)

try:
    import torch
    from torch.utils.data import DataLoader, TensorDataset
except ImportError:  # pragma: no cover - exercised only without the extra
    torch = None  # type: ignore[assignment]

CoreType = Literal["lstm", "gru", "transformer"]


def _require_torch() -> None:
    if torch is None:
        raise RuntimeError("World model training requires PyTorch: uv sync --extra deep-learning")


class WorldModelConfig(BaseModel):
    """Architecture and optimisation settings for one training run."""

    model_config = ConfigDict(extra="forbid")

    core_type: CoreType = "lstm"
    hidden_size: int = Field(default=64, ge=4)
    latent_dim: int = Field(default=16, ge=2)
    num_layers: int = Field(default=1, ge=1)
    num_heads: int = Field(default=4, ge=1)
    learning_rate: float = Field(default=3e-3, gt=0)
    weight_decay: float = Field(default=1e-5, ge=0)
    batch_size: int = Field(default=32, ge=1)
    max_epochs: int = Field(default=60, ge=1)
    early_stopping_patience: int = Field(default=12, ge=1)
    grad_clip: float = Field(default=5.0, gt=0)
    kl_free_nats: float = Field(default=1.0, ge=0)
    kl_anneal_epochs: int = Field(default=10, ge=0)
    risk_loss_weight: float = Field(default=1.0, ge=0)
    stage_loss_weight: float = Field(default=0.5, ge=0)
    imagination_samples: int = Field(default=64, ge=1)
    rollout_steps: int = Field(default=3, ge=0)
    rollout_loss_weight: float = Field(default=1.0, ge=0)


class WorldModelMetrics(BaseModel):
    """Loss components plus detection, stage, and open-loop metrics for one split."""

    model_config = ConfigDict(extra="forbid")

    windows: int = Field(ge=0)
    timesteps: int = Field(ge=0)
    reconstruction_mse: float
    kl_nats: float
    risk: BinaryMetrics | None = None
    stage_accuracy: float | None = None
    stage_macro_f1: float | None = None
    open_loop_mae: list[float] = Field(default_factory=list)
    open_loop_persistence_mae: list[float] = Field(default_factory=list)

    @property
    def open_loop_skill(self) -> float | None:
        """Mean per-step 1 - model/persistence error; <= 0 means no better than
        repeating the last observed window."""
        pairs = list(zip(self.open_loop_mae, self.open_loop_persistence_mae, strict=True))
        usable = [(m, p) for m, p in pairs if p > 0]
        if not usable:
            return None
        return float(np.mean([1.0 - (m / p) for m, p in usable]))


class WorldModelResult(BaseModel):
    """Everything needed to rebuild the model and audit the run."""

    model_config = ConfigDict(extra="forbid")

    model_version: str = WORLD_MODEL_VERSION
    config: WorldModelConfig
    feature_schema: FeatureSchema
    split_manifest: SplitManifest
    stage_vocabulary: list[str] = Field(min_length=1)
    observation_dim: int = Field(ge=1)
    sequence_length: int = Field(ge=1)
    metrics: dict[str, WorldModelMetrics] = Field(default_factory=dict)
    train_history: list[dict[str, float]] = Field(default_factory=list)
    best_epoch: int = Field(ge=0)
    training_seconds: float
    model_sha256: str
    runtime: dict[str, str]


@dataclass(frozen=True)
class WorldSequence:
    """One contiguous same-scenario observation window with per-step labels."""

    scenario_id: str
    state_keys: list[str]
    infiltration: np.ndarray  # (seq_len,) float32
    stage_index: np.ndarray  # (seq_len,) int64


@dataclass(frozen=True)
class WorldModelRun:
    core: RSSMCore
    result: WorldModelResult


def build_world_sequences(
    labelled_states: list[LabelledState],
    *,
    sequence_length: int,
    stage_vocabulary: list[str] | None = None,
) -> list[WorldSequence]:
    """Contiguous same-scenario windows, labelled per timestep.

    Windows never straddle a scenario boundary, so no sample can mix two
    scenarios' dynamics. ``stage_vocabulary`` fixes the stage index mapping; it
    defaults to the sorted stage names present in the given states, which is
    always a subset of the vocabulary the caller trained with.
    """
    if sequence_length < 1:
        raise ValueError("sequence_length must be positive")
    if not labelled_states:
        raise ValueError("at least one labelled state is required")

    vocabulary = stage_vocabulary or sorted({item.label.attack_stage for item in labelled_states})
    index_of = {name: index for index, name in enumerate(vocabulary)}

    by_scenario: dict[str, list[LabelledState]] = {}
    for item in labelled_states:
        by_scenario.setdefault(item.scenario_id, []).append(item)

    sequences: list[WorldSequence] = []
    for scenario_id in sorted(by_scenario):
        states = sorted(by_scenario[scenario_id], key=lambda item: item.state.window_start)
        for start in range(0, len(states) - sequence_length + 1):
            window = states[start : start + sequence_length]
            if any(item.label.attack_stage not in index_of for item in window):
                continue  # unseen stage: skip rather than invent a label
            sequences.append(
                WorldSequence(
                    scenario_id=scenario_id,
                    state_keys=[item.state_key for item in window],
                    infiltration=np.array(
                        [float(item.label.infiltration) for item in window], dtype=np.float32
                    ),
                    stage_index=np.array(
                        [index_of[item.label.attack_stage] for item in window], dtype=np.int64
                    ),
                )
            )
    return sequences


def stage_vocabulary(labelled_states: list[LabelledState], splits: SplitManifest) -> list[str]:
    """Sorted stage names seen in *training* scenarios only.

    The stage head must not be sized by labels the model will be scored on, so
    test-only stage names are deliberately excluded; a test window carrying an
    unseen stage is skipped by :func:`build_world_sequences`.
    """
    train = set(splits.train_scenarios)
    names = sorted(
        {item.label.attack_stage for item in labelled_states if item.scenario_id in train}
    )
    if not names:
        raise ValueError("no training states to derive a stage vocabulary from")
    return names


def train_world_model(
    labelled_states: list[LabelledState],
    manifest: SplitManifest,
    *,
    feature_schema: FeatureSchema,
    config: WorldModelConfig,
    seed: int,
    sequence_length: int,
) -> WorldModelRun:
    """Fit the world model; early stopping uses the validation split only."""
    _require_torch()
    if config.core_type not in CORE_TYPES:
        raise ValueError(f"core_type must be one of {CORE_TYPES}")

    torch.manual_seed(seed)
    np.random.seed(seed)
    torch.use_deterministic_algorithms(True)

    vocabulary = stage_vocabulary(labelled_states, manifest)
    sequences = build_world_sequences(
        labelled_states, sequence_length=sequence_length, stage_vocabulary=vocabulary
    )
    assignment = split_assignment(manifest)
    grouped: dict[str, list[WorldSequence]] = {name: [] for name in SPLIT_NAMES}
    for sequence in sequences:
        grouped[assignment.get(sequence.scenario_id, "")].append(sequence)
    if not grouped["train"]:
        raise ValueError("no training sequences after split filtering")

    tensors = {
        name: _stack(group, labelled_states, feature_schema) for name, group in grouped.items()
    }
    train_x, train_risk, train_stage = tensors["train"]

    core = RSSMCore(
        obs_dim=feature_schema.width,
        hidden_dim=config.hidden_size,
        latent_dim=config.latent_dim,
        core_type=config.core_type,
        num_stages=len(vocabulary),
        num_layers=config.num_layers,
        num_heads=config.num_heads,
    )
    optimizer = torch.optim.Adam(
        core.parameters(), lr=config.learning_rate, weight_decay=config.weight_decay
    )
    positives = float(train_risk.sum())
    negatives = float(train_risk.numel() - positives)
    pos_weight = torch.tensor([negatives / max(positives, 1.0)], dtype=torch.float32)
    loader = DataLoader(
        TensorDataset(train_x, train_risk, train_stage),
        batch_size=config.batch_size,
        shuffle=True,
        generator=torch.Generator().manual_seed(seed),
    )

    best_loss = float("inf")
    best_epoch = 0
    best_state: dict[str, torch.Tensor] | None = None
    patience = 0
    history: list[dict[str, float]] = []

    started = time.perf_counter()
    for epoch in range(1, config.max_epochs + 1):
        core.train()
        epoch_totals: dict[str, float] = {}
        # KL stays off for the first `kl_anneal_epochs` epochs so the posterior
        # learns to explain the observations before the prior is pulled onto it.
        beta = 0.0 if epoch <= config.kl_anneal_epochs else _kl_scale(core, loader, config)
        for batch_x, batch_risk, batch_stage in loader:
            optimizer.zero_grad()
            states, recon, risk_logits, stage_logits = core.forward_sequence(batch_x)
            rollout_mse = (
                dream_consistency(core, batch_x, config.rollout_steps)
                if config.rollout_steps > 0 and config.rollout_loss_weight > 0
                else None
            )
            loss, parts = rssm_loss(
                batch_x,
                recon,
                risk_logits,
                stage_logits,
                states,
                risk_labels=batch_risk,
                stage_labels=batch_stage,
                beta=beta,
                lambda_risk=config.risk_loss_weight,
                gamma_stage=config.stage_loss_weight,
                pos_weight=pos_weight,
                rollout_mse=rollout_mse,
                gamma_rollout=config.rollout_loss_weight,
            )
            loss.backward()
            torch.nn.utils.clip_grad_norm_(core.parameters(), config.grad_clip)
            optimizer.step()
            for key, value in parts.items():
                epoch_totals[key] = epoch_totals.get(key, 0.0) + value

        steps = max(len(loader), 1)
        row = {key: value / steps for key, value in epoch_totals.items()}
        history.append({"epoch": float(epoch), "kl_weight": beta, **row})

        validation = tensors["validation"]
        if validation is None:
            continue
        validation_loss = _score(core, validation, config, pos_weight)
        row["validation"] = validation_loss
        if validation_loss < best_loss:
            best_loss = validation_loss
            best_epoch = epoch
            best_state = {k: v.detach().clone() for k, v in core.state_dict().items()}
            patience = 0
        else:
            patience += 1
            if patience >= config.early_stopping_patience:
                break

    if best_state is not None:
        core.load_state_dict(best_state)
    training_seconds = time.perf_counter() - started

    metrics = {
        name: _evaluate(core, tensors[name], vocabulary, config.rollout_steps)
        for name in SPLIT_NAMES
        if tensors[name] is not None
    }
    result = WorldModelResult(
        config=config,
        feature_schema=feature_schema,
        split_manifest=manifest,
        stage_vocabulary=vocabulary,
        observation_dim=feature_schema.width,
        sequence_length=sequence_length,
        metrics=metrics,
        train_history=history,
        best_epoch=best_epoch,
        training_seconds=training_seconds,
        model_sha256=_checksum(core),
        runtime={
            "python": platform.python_version(),
            "torch": torch.__version__,
            "numpy": np.__version__,
            "platform": platform.platform(),
        },
    )
    return WorldModelRun(core=core, result=result)


def _kl_scale(core: RSSMCore, loader: DataLoader, config: WorldModelConfig) -> float:
    """Dreamer-style free-nats scale measured on the first training batch."""
    if config.kl_free_nats <= 0:
        return 1.0
    batch_x = next(iter(loader))[0]
    core.eval()
    with torch.no_grad():
        states, _recon, _risk, _stage = core.forward_sequence(batch_x)
        scale = kl_weight(kl_divergence(states), config.kl_free_nats)
    core.train()
    return min(1.0, scale)


def _stack(
    sequences: list[WorldSequence],
    labelled_states: list[LabelledState],
    schema: FeatureSchema,
):
    if not sequences:
        return None
    states_by_key = {item.state_key: item for item in labelled_states}
    observations = np.stack(
        [
            vectorize_states([states_by_key[key].state for key in sequence.state_keys], schema)
            for sequence in sequences
        ]
    ).astype(np.float32)
    risk = np.stack([sequence.infiltration for sequence in sequences])
    stage = np.stack([sequence.stage_index for sequence in sequences])
    return (
        torch.tensor(observations, dtype=torch.float32),
        torch.tensor(risk, dtype=torch.float32),
        torch.tensor(stage, dtype=torch.int64),
    )


def _score(core: RSSMCore, batch, config: WorldModelConfig, pos_weight) -> float:
    """Validation objective used for early stopping (lower is better).

    The open-loop term is included so the selected epoch is the one that both
    reconstructs and simulates, not the one that only reconstructs.
    """
    core.eval()
    with torch.no_grad():
        states, recon, risk_logits, stage_logits = core.forward_sequence(batch[0])
        rollout_mse = (
            dream_consistency(core, batch[0], config.rollout_steps)
            if config.rollout_steps > 0 and config.rollout_loss_weight > 0
            else None
        )
        loss, _ = rssm_loss(
            batch[0],
            recon,
            risk_logits,
            stage_logits,
            states,
            risk_labels=batch[1],
            stage_labels=batch[2],
            beta=1.0 if config.kl_anneal_epochs < config.max_epochs else 0.0,
            lambda_risk=config.risk_loss_weight,
            gamma_stage=config.stage_loss_weight,
            pos_weight=pos_weight,
            rollout_mse=rollout_mse,
            gamma_rollout=config.rollout_loss_weight,
        )
    core.train()
    return float(loss)


def _evaluate(core: RSSMCore, batch, vocabulary: list[str], steps: int) -> WorldModelMetrics:
    """One-shot scoring of a split: losses plus detection, stage, and open-loop metrics.

    The open-loop columns are measured with the realized tail of each window as
    ground truth and are the numbers that distinguish a transition model from a
    classifier; ``open_loop_skill`` compares them against persistence.
    """
    core.eval()
    torch.manual_seed(0)  # the imagination is stochastic; pin it for repeatability
    with torch.no_grad():
        states, recon, risk_logits, stage_logits = core.forward_sequence(batch[0])
        recon_loss = float(((recon - batch[0]) ** 2).mean())
        kl = float(kl_divergence(states))
        model_mae: list[float] = []
        persistence_mae: list[float] = []
        if 0 < steps < batch[0].size(1):
            imagined = dream_trajectory(core, batch[0], steps)
            realized = batch[0][:, batch[0].size(1) - steps :]
            last = batch[0][:, batch[0].size(1) - steps - 1 : batch[0].size(1) - steps]
            model_mae = [float(v) for v in (imagined - realized).abs().mean(dim=(0, 2)).numpy()]
            persistence_mae = [float(v) for v in (last - realized).abs().mean(dim=(0, 2)).numpy()]
    probabilities = torch.sigmoid(risk_logits).numpy().reshape(-1)
    truth = batch[1].numpy().reshape(-1)
    stage_probabilities = torch.softmax(stage_logits, dim=-1).numpy().reshape(-1, len(vocabulary))
    stage_truth = batch[2].numpy().reshape(-1)
    risk_metrics = compute_binary_metrics(truth, probabilities, threshold=0.5)
    accuracy, macro_f1 = _stage_scores(stage_truth, stage_probabilities, len(vocabulary))
    core.train()
    return WorldModelMetrics(
        windows=int(batch[0].shape[0]),
        timesteps=int(batch[0].shape[0] * batch[0].shape[1]),
        reconstruction_mse=recon_loss,
        kl_nats=kl,
        risk=risk_metrics,
        stage_accuracy=accuracy,
        stage_macro_f1=macro_f1,
        open_loop_mae=model_mae,
        open_loop_persistence_mae=persistence_mae,
    )


def _stage_scores(
    truth: np.ndarray, probabilities: np.ndarray, classes: int
) -> tuple[float, float]:
    predicted = probabilities.argmax(axis=1)
    accuracy = float(np.mean(predicted == truth)) if truth.size else 0.0
    f1s = []
    for klass in range(classes):
        tp = int(np.sum((predicted == klass) & (truth == klass)))
        fp = int(np.sum((predicted == klass) & (truth != klass)))
        fn = int(np.sum((predicted != klass) & (truth == klass)))
        if tp + fp + fn == 0:
            continue
        # A class that is predicted but absent from the truth has no recall to report.
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1s.append(
            0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
        )
    macro = float(np.mean(f1s)) if f1s else 0.0
    return accuracy, macro


def _checksum(core: RSSMCore) -> str:
    buffer = io.BytesIO()
    torch.save(core.state_dict(), buffer)
    return hashlib.sha256(buffer.getvalue()).hexdigest()


def save_world_model_artifacts(run: WorldModelRun, output_dir: str | Path) -> dict[str, Path]:
    """Write ``world_model.json``, ``world_model.pt``, and a markdown report."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    result_path = out / "world_model.json"
    result_path.write_text(run.result.model_dump_json(indent=2), encoding="utf-8")
    weights_path = out / "world_model.pt"
    torch.save(run.core.state_dict(), weights_path)
    report_path = out / "world_model_report.md"
    report_path.write_text(render_report(run.result), encoding="utf-8")
    return {"result": result_path, "weights": weights_path, "report": report_path}


def load_world_model(result: WorldModelResult, model_dir: str | Path) -> RSSMCore:
    """Rebuild a trained core from the result JSON and the saved weights."""
    _require_torch()
    path = Path(model_dir) / "world_model.pt"
    if not path.is_file():
        raise FileNotFoundError(f"World model weights not found: {path}")
    core = RSSMCore(
        obs_dim=result.observation_dim,
        hidden_dim=result.config.hidden_size,
        latent_dim=result.config.latent_dim,
        core_type=result.config.core_type,
        num_stages=len(result.stage_vocabulary),
        num_layers=result.config.num_layers,
        num_heads=result.config.num_heads,
    )
    core.load_state_dict(torch.load(path, map_location="cpu", weights_only=True))
    core.eval()
    return core


def render_report(result: WorldModelResult) -> str:
    """Human-readable summary; every number comes from the result object."""
    lines = [
        "# World Model Report",
        "",
        "## Experiment Identity",
        "",
        f"- Model version: `{result.model_version}`",
        f"- Core: `{result.config.core_type}` (hidden {result.config.hidden_size}, "
        f"latent {result.config.latent_dim}, layers {result.config.num_layers})",
        f"- Observation dim: {result.observation_dim} · sequence length: {result.sequence_length}",
        f"- Stage vocabulary: {', '.join(result.stage_vocabulary)}",
        f"- Feature version: {result.feature_schema.version}",
        f"- Best epoch: {result.best_epoch} · training time: {result.training_seconds:.1f} s",
        f"- Model SHA-256: `{result.model_sha256}`",
        f"- Configuration: `{result.config.model_dump_json()}`",
        "",
        "## Split Metrics",
        "",
        "| Split | Windows | Recon MSE | KL (nats) | F1 | FPR | PR-AUC "
        "| Stage acc | Stage macro-F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name in SPLIT_NAMES:
        metrics = result.metrics.get(name)
        if metrics is None:
            continue
        risk = metrics.risk
        lines.append(
            f"| {name} | {metrics.windows} | {metrics.reconstruction_mse:.4f} | "
            f"{metrics.kl_nats:.4f} | {_f(risk.f1 if risk else None)} | "
            f"{_f(risk.false_positive_rate if risk else None)} | "
            f"{_f(risk.pr_auc if risk else None)} | {_f(metrics.stage_accuracy)} | "
            f"{_f(metrics.stage_macro_f1)} |"
        )
    lines += [
        "",
        "## Open-Loop State Prediction (per step, imagined vs realized)",
        "",
        "| Step | World model MAE | Persistence MAE | Skill |",
        "|---:|---:|---:|---:|",
    ]
    test_metrics = result.metrics.get("test")
    if test_metrics and test_metrics.open_loop_mae:
        for index, step in enumerate(range(1, len(test_metrics.open_loop_mae) + 1)):
            model_error = test_metrics.open_loop_mae[index]
            baseline = test_metrics.open_loop_persistence_mae[index]
            skill = 1.0 - (model_error / baseline) if baseline > 0 else 0.0
            lines.append(f"| +{step} | {model_error:.4f} | {baseline:.4f} | {skill:+.3f} |")
    else:
        lines.append("| — | — | — | open-loop metrics were not evaluated |")

    lines += [
        "",
        "## Interpretation",
        "",
        "- The reconstruction term is what makes the latent a state model: the",
        "  decoder must explain the telemetry, not just the label.",
        "- KL is reported in nats. A KL near zero means the prior, which never sees",
        "  the observation, already predicts the posterior that does — that is the",
        "  condition for open-loop imagination to be a simulation.",
        "- Skill is 1 - model error / persistence error on standardized state",
        "  features. Positive means open-loop simulation beats repeating the last",
        "  window; negative means it does not, and the number is reported either way.",
        "- Risk and stage metrics come from the heads at the observed windows;",
        "  open-loop behaviour is the table above and the imagination benchmark.",
        "- Results describe the evaluated dataset and split only.",
        "",
    ]
    return "\n".join(lines)


def _f(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.4f}"


__all__ = [
    "WORLD_MODEL_VERSION",
    "WorldModelConfig",
    "WorldModelMetrics",
    "WorldModelResult",
    "WorldModelRun",
    "WorldSequence",
    "build_world_sequences",
    "load_world_model",
    "render_report",
    "save_world_model_artifacts",
    "stage_vocabulary",
    "train_world_model",
]
