# SPDX-License-Identifier: Apache-2.0
"""Recurrent State-Space Model (RSSM) — the world-model backbone.

Architecture (one timestep)::

    o_t  = fused observation (standardized state feature vector)
    e_t  = Enc(o_t)                                    MLP d -> hidden
    h_t  = Core(h_{t-1}, [e_t, z_{t-1}])               LSTM | GRU | Transformer
    q(z_t | h_t, e_t) = N(mu_q, sigma_q)                posterior — sees evidence
    p(z_t | h_t)      = N(mu_p, sigma_p)                prior — never does
    o^_t ~ p(o_t | h_t, z_t)                           decoder
    risk_t  = risk_head([h_t, z_t])                    logit of P(infiltration)
    stage_t = stage_head([h_t, z_t])                   logits over stage vocabulary

    L = recon(o^_t, o_t) + beta * KL(q || p) + BCE(risk_t, y_t) + CE(stage_t, s_t)

Three rules make this a world model rather than a classifier:

1. **The observation is never optional during training.** Reconstruction forces
   ``p(o_t | h_t, z_t)`` to explain the telemetry, so the latent state carries
   the dynamics rather than only the label.
2. **The prior never sees the observation.** It is trained by the KL term to
   match the posterior, which is what makes open-loop sampling from ``p`` a
   simulation instead of a decoder applied to fresh inputs.
3. **Heads emit logits.** Sigmoid/softmax are applied by the loss and by
   callers, so cross-entropy and BCE see unsaturated values.

The stage head's width is ``num_stages`` from the training label vocabulary, not
a hard-coded constant: a 10-way head is untrainable against a 3-stage dataset.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import torch
import torch.nn as nn
import torch.nn.functional as F

WORLD_MODEL_VERSION = "world-model-rssm-v1"

CoreType = Literal["lstm", "gru", "transformer"]
CORE_TYPES: tuple[str, ...] = ("lstm", "gru", "transformer")

# Floor on the Gaussian scale so log(sigma) never diverges during training.
MIN_SIGMA = 0.1


@dataclass
class RSSMState:
    """RSSM state at a single timestep.

    ``c`` is the LSTM cell state (``None`` for GRU/transformer). ``memory`` is
    the transformer core's growing sequence of core inputs (``None`` otherwise);
    it makes the attention core autoregressive, so open-loop imagination can
    feed the model its own decoded observations.
    """

    h: torch.Tensor  # (batch, hidden_dim) recurrent or attention summary
    z: torch.Tensor  # (batch, latent_dim) stochastic latent
    c: torch.Tensor | None  # (batch, hidden_dim) LSTM cell state
    memory: torch.Tensor | None  # (batch, steps, hidden_dim) transformer core inputs
    mu_p: torch.Tensor  # (batch, latent_dim) prior mean
    sigma_p: torch.Tensor  # (batch, latent_dim) prior scale
    mu_q: torch.Tensor  # (batch, latent_dim) posterior mean
    sigma_q: torch.Tensor  # (batch, latent_dim) posterior scale


class Encoder(nn.Module):
    """Observation encoder: MLP obs_dim -> hidden_dim."""

    def __init__(self, obs_dim: int, hidden_dim: int) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(obs_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, hidden_dim),
        )

    def forward(self, obs: torch.Tensor) -> torch.Tensor:
        return self.net(obs)


class CausalSelfAttentionCore(nn.Module):
    """Transformer recurrent core.

    The full core-input sequence is re-encoded at every step with a causal mask
    instead of caching keys/values. Sequences here are ``burn_in + horizon``
    steps long (tens), so the O(L^2) recompute is cheaper than the bookkeeping
    a KV cache would need, and it keeps the state a single plain tensor.
    """

    def __init__(self, dim: int, out_dim: int, num_heads: int, num_layers: int) -> None:
        super().__init__()
        self.layer = nn.TransformerEncoderLayer(
            d_model=dim,
            nhead=num_heads,
            dim_feedforward=2 * dim,
            dropout=0.0,
            activation="gelu",
            batch_first=True,
            norm_first=True,
        )
        self.core = nn.TransformerEncoder(
            self.layer, num_layers=num_layers, enable_nested_tensor=False
        )
        # Project back to hidden_dim so every core yields a hidden_dim summary.
        self.out = nn.Linear(dim, out_dim)

    def forward(self, memory: torch.Tensor) -> torch.Tensor:
        """Return the summary at the newest position for a (batch, steps, dim) memory."""
        steps = memory.size(1)
        mask = torch.triu(
            torch.ones(steps, steps, dtype=torch.bool, device=memory.device), diagonal=1
        )
        return self.out(self.core(memory, mask=mask)[:, -1])


class RSSMCore(nn.Module):
    """Recurrent core with a stochastic latent space and forecast heads."""

    def __init__(
        self,
        obs_dim: int,
        hidden_dim: int = 128,
        latent_dim: int = 64,
        core_type: CoreType = "lstm",
        num_stages: int = 3,
        num_layers: int = 1,
        num_heads: int = 4,
    ) -> None:
        super().__init__()
        if core_type not in CORE_TYPES:
            raise ValueError(f"core_type must be one of {CORE_TYPES}, got {core_type!r}")
        if num_stages < 1:
            raise ValueError("num_stages must be positive")
        if core_type == "transformer" and hidden_dim % num_heads:
            raise ValueError("hidden_dim must be divisible by num_heads for the transformer core")

        self.obs_dim = obs_dim
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim
        self.core_type: CoreType = core_type
        self.num_stages = num_stages

        self.encoder = Encoder(obs_dim, hidden_dim)

        # Prior: p(z_t | h_{t-1}) — no observation input, by construction.
        self.prior_net = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, latent_dim * 2),
        )
        # Posterior: q(z_t | h_{t-1}, e_t).
        self.posterior_net = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, latent_dim * 2),
        )

        core_input_dim = hidden_dim + latent_dim
        if core_type == "lstm":
            self.core: nn.Module = nn.LSTMCell(core_input_dim, hidden_dim)
        elif core_type == "gru":
            self.core = nn.GRUCell(core_input_dim, hidden_dim)
        else:
            self.core = CausalSelfAttentionCore(core_input_dim, hidden_dim, num_heads, num_layers)

        self.decoder = nn.Sequential(
            nn.Linear(core_input_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, obs_dim),
        )
        self.risk_head = nn.Sequential(
            nn.Linear(core_input_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, 1),
        )
        self.stage_head = nn.Sequential(
            nn.Linear(core_input_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, num_stages),
        )

    # ── state ────────────────────────────────────────────────────────────

    def initial_state(self, batch_size: int = 1) -> RSSMState:
        """Zero state on the module's device."""
        device = next(self.parameters()).device
        return RSSMState(
            h=torch.zeros(batch_size, self.hidden_dim, device=device),
            z=torch.zeros(batch_size, self.latent_dim, device=device),
            c=torch.zeros(batch_size, self.hidden_dim, device=device),
            memory=None,
            mu_p=torch.zeros(batch_size, self.latent_dim, device=device),
            sigma_p=torch.ones(batch_size, self.latent_dim, device=device),
            mu_q=torch.zeros(batch_size, self.latent_dim, device=device),
            sigma_q=torch.ones(batch_size, self.latent_dim, device=device),
        )

    # ── observed (teacher-forced) dynamics ───────────────────────────────

    def forward_step(
        self,
        obs: torch.Tensor,
        prev_state: RSSMState,
    ) -> tuple[RSSMState, torch.Tensor, torch.Tensor, torch.Tensor]:
        """One step conditioned on a real observation.

        Returns ``(state, reconstruction, risk_logit, stage_logits)``.
        """
        encoded = self.encoder(obs)
        state = self._advance(prev_state, encoded, use_posterior=True)
        return (*self._heads(state), state, encoded)

    def forward_sequence(
        self,
        observations: torch.Tensor,
    ) -> tuple[list[RSSMState], torch.Tensor, torch.Tensor, torch.Tensor]:
        """Teacher-forced pass over ``(batch, seq_len, obs_dim)`` observations."""
        batch_size, seq_len, _ = observations.shape
        state = self.initial_state(batch_size)
        states: list[RSSMState] = []
        reconstructions, risks, stages = [], [], []
        for step in range(seq_len):
            recon, risk_logit, stage_logits, state, _ = self.forward_step(
                observations[:, step], state
            )
            states.append(state)
            reconstructions.append(recon)
            risks.append(risk_logit)
            stages.append(stage_logits)
        return (
            states,
            torch.stack(reconstructions, dim=1),
            torch.stack(risks, dim=1),
            torch.stack(stages, dim=1),
        )

    # ── imagined (open-loop) dynamics ────────────────────────────────────

    def imagine_step(
        self,
        prev_state: RSSMState,
        imagined_obs: torch.Tensor | None = None,
        *,
        temperature: float = 1.0,
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, RSSMState]:
        """One open-loop step from the prior, with no observation evidence.

        ``imagined_obs`` is the previous step's *decoded* observation (Dreamer
        style); it only feeds the core input, never the posterior, so no
        information from the real future can leak in. It is required by the
        transformer core, whose attention is over the core-input sequence.

        Returns ``(reconstruction, risk_logit, stage_logits, new_state)``.
        """
        encoded = (
            self.encoder(imagined_obs)
            if imagined_obs is not None
            else torch.zeros(prev_state.h.size(0), self.hidden_dim, device=prev_state.h.device)
        )
        state = self._advance(prev_state, encoded, use_posterior=False, temperature=temperature)
        recon, risk_logit, stage_logits = self._heads(state)
        return recon, risk_logit, stage_logits, state

    # ── internals ────────────────────────────────────────────────────────

    def _advance(
        self,
        prev_state: RSSMState,
        encoded: torch.Tensor,
        *,
        use_posterior: bool,
        temperature: float = 1.0,
    ) -> RSSMState:
        prior_mu, prior_sigma = self._split(self.prior_net(prev_state.h))
        if use_posterior:
            posterior_mu, posterior_sigma = self._split(
                self.posterior_net(torch.cat([prev_state.h, encoded], dim=-1))
            )
        else:
            # No evidence: the posterior statistics are carried forward unchanged
            # so the KL term of a later (hypothetical) observation stays defined.
            posterior_mu, posterior_sigma = prev_state.mu_q, prev_state.sigma_q

        mean = posterior_mu if use_posterior else prior_mu
        sigma = posterior_sigma if use_posterior else prior_sigma
        z = mean + sigma * torch.randn_like(sigma) * temperature

        core_input = torch.cat([encoded, z], dim=-1)
        if self.core_type == "lstm":
            cell = prev_state.c if prev_state.c is not None else torch.zeros_like(prev_state.h)
            h, c = self.core(core_input, (prev_state.h, cell))
            memory = None
        elif self.core_type == "gru":
            h = self.core(core_input, prev_state.h)
            c, memory = None, None
        else:
            previous = prev_state.memory
            memory = (
                core_input.unsqueeze(1)
                if previous is None
                else torch.cat([previous, core_input.unsqueeze(1)], dim=1)
            )
            h = self.core(memory)
            c = None

        return RSSMState(
            h=h,
            z=z,
            c=c,
            memory=memory,
            mu_p=prior_mu,
            sigma_p=prior_sigma,
            mu_q=posterior_mu,
            sigma_q=posterior_sigma,
        )

    def _split(self, raw: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        mu, sigma = raw.chunk(2, dim=-1)
        return mu, F.softplus(sigma) + MIN_SIGMA

    def _heads(self, state: RSSMState) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        head_input = torch.cat([state.h, state.z], dim=-1)
        return self.decoder(head_input), self.risk_head(head_input), self.stage_head(head_input)


def kl_divergence(states: list[RSSMState]) -> torch.Tensor:
    """Mean per-step KL(q || p) in nats, averaged over latent dims and batch."""
    if not states:
        raise ValueError("at least one state is required to compute a divergence")
    total = states[0].h.new_zeros(())
    for state in states:
        elementwise = (
            torch.log(state.sigma_p / state.sigma_q)
            + (state.sigma_q.square() + (state.mu_q - state.mu_p).square())
            / (2 * state.sigma_p.square())
            - 0.5
        )
        total = total + elementwise.sum(dim=-1).mean()
    return total / len(states)


def kl_weight(kl_nats: torch.Tensor, free_nats: float) -> float:
    """Dreamer-style KL scale: free nats before the latent is pulled together."""
    if free_nats <= 0:
        return 1.0
    return float(free_nats / kl_nats.detach().clamp(min=1e-8))


def rssm_loss(
    observations: torch.Tensor,
    reconstructions: torch.Tensor,
    risks: torch.Tensor,
    stages: torch.Tensor,
    states: list[RSSMState],
    risk_labels: torch.Tensor | None = None,
    stage_labels: torch.Tensor | None = None,
    beta: float = 1.0,
    lambda_risk: float = 1.0,
    gamma_stage: float = 1.0,
    pos_weight: torch.Tensor | None = None,
    rollout_mse: torch.Tensor | None = None,
    gamma_rollout: float = 0.0,
) -> tuple[torch.Tensor, dict[str, float]]:
    """World-model loss: reconstruction + beta * KL + risk BCE + stage CE.

    ``observations``/``reconstructions`` are ``(batch, seq, obs_dim)``; ``risks``
    and ``stages`` are logits. Labels are optional so the same function scores a
    reconstruction-only ablation.

    ``rollout_mse`` is the open-loop error from :func:`dream_consistency` and is
    weighted by ``gamma_rollout``. It is the only term that trains the
    imagination path: teacher forcing alone never shows the model its own decoded
    states, so without it open-loop simulation drifts off the observed manifold
    and scores worse than repeating the last window.
    """
    recon_loss = F.mse_loss(reconstructions, observations)
    kl = kl_divergence(states)

    risk_loss = recon_loss.new_zeros(())
    if risk_labels is not None:
        risk_loss = F.binary_cross_entropy_with_logits(
            risks.reshape(-1), risk_labels.reshape(-1).float(), pos_weight=pos_weight
        )

    stage_loss = recon_loss.new_zeros(())
    if stage_labels is not None:
        stage_loss = F.cross_entropy(
            stages.reshape(-1, stages.size(-1)), stage_labels.reshape(-1).long()
        )

    rollout = recon_loss.new_zeros(())
    if rollout_mse is not None and gamma_rollout > 0:
        rollout = rollout_mse

    total = (
        recon_loss
        + beta * kl
        + lambda_risk * risk_loss
        + gamma_stage * stage_loss
        + gamma_rollout * rollout
    )
    metrics = {
        "recon": float(recon_loss.detach()),
        "kl": float(kl.detach()),
        "risk": float(risk_loss.detach()),
        "stage": float(stage_loss.detach()),
        "rollout": float(rollout.detach()),
        "total": float(total.detach()),
    }
    return total, metrics


def dream_trajectory(core: RSSMCore, observations: torch.Tensor, steps: int) -> torch.Tensor:
    """Open-loop decoded states for the tail of a sequence: ``(batch, steps, obs_dim)``.

    The leading ``T - steps`` windows are burned in through the posterior (real
    evidence), then the model is rolled forward ``steps`` times from the prior
    with no observations. Gradients flow through the whole chain, so this is the
    differentiable simulation the open-loop objective is built on.
    """
    if steps < 1:
        raise ValueError("steps must be positive")
    sequence_length = observations.size(1)
    if steps >= sequence_length:
        raise ValueError("steps must be shorter than the sequence length")
    burn_in = sequence_length - steps

    state = core.initial_state(observations.size(0))
    for step in range(burn_in):
        _recon, _risk, _stage, state, _encoded = core.forward_step(observations[:, step], state)

    imagined: list[torch.Tensor] = []
    previous: torch.Tensor | None = None
    for _step in range(steps):
        recon, _risk, _stage, state = core.imagine_step(state, previous)
        imagined.append(recon)
        previous = recon
    return torch.stack(imagined, dim=1)


def dream_consistency(core: RSSMCore, observations: torch.Tensor, steps: int) -> torch.Tensor:
    """Open-loop state error against the realized tail of a sequence.

    This is the training signal for ``P(S_{t+1} | S_t)``. Teacher forcing alone
    never shows the model its own decoded states, so without it open-loop
    simulation drifts off the observed manifold and scores worse than repeating
    the last window.
    """
    imagined = dream_trajectory(core, observations, steps)
    return F.mse_loss(imagined, observations[:, observations.size(1) - steps :])
