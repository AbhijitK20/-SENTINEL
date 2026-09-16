# SPDX-License-Identifier: Apache-2.0
"""Recurrent State-Space Model (RSSM) — the world model backbone.

Architecture:
    o_t  = fused observation (tabular v3 ⊕ graph embedding)
    e_t  = Enc(o_t)                                   MLP d → 128
    h_t  = Core(h_{t-1}, [z_{t-1}, e_t])              LSTM | Transformer | GRU
    q(z_t | h_t, e_t) = N(μ_q, σ_q)                   posterior — sees evidence
    p(z_t | h_t)      = N(μ_p, σ_p)                   prior — does not
    ô_t  ~ p(o_t | h_t, z_t)                          decoder
    risk  = σ(MLP([h_t, z_t]))                        P(infiltration)
    stage = softmax(MLP([h_t, z_t]))                  MITRE distribution

    L = recon_nll(ô_t, o_t) + β·KL(q ‖ p) + λ·BCE(risk, y) + γ·CE(stage, s)

The KL term forces the prior — which never sees the future observation — to
match the posterior that does. That is how the model learns to imagine
rather than classify.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import torch
import torch.nn as nn
import torch.nn.functional as F


@dataclass
class RSSMState:
    """State of the RSSM at a single timestep."""

    h: torch.Tensor  # Recurrent hidden state
    z: torch.Tensor  # Stochastic latent
    mu_p: torch.Tensor  # Prior mean
    sigma_p: torch.Tensor  # Prior std
    mu_q: torch.Tensor  # Posterior mean
    sigma_q: torch.Tensor  # Posterior std


class Encoder(nn.Module):
    """Observation encoder: MLP d → 128."""

    def __init__(self, obs_dim: int, hidden_dim: int = 128) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(obs_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, hidden_dim),
        )

    def forward(self, obs: torch.Tensor) -> torch.Tensor:
        return self.net(obs)


class RSSMCore(nn.Module):
    """Recurrent core with stochastic latent space.

    Supports LSTM, GRU, or Transformer as the recurrent backbone.
    """

    def __init__(
        self,
        obs_dim: int,
        hidden_dim: int = 128,
        latent_dim: int = 64,
        core_type: Literal["lstm", "gru", "transformer"] = "lstm",
    ) -> None:
        super().__init__()
        self.obs_dim = obs_dim
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim
        self.core_type = core_type

        self.encoder = Encoder(obs_dim, hidden_dim)

        # Prior: p(z_t | h_t)
        self.prior_net = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, latent_dim * 2),  # mu, log_sigma
        )

        # Posterior: q(z_t | h_t, e_t)
        self.posterior_net = nn.Sequential(
            nn.Linear(hidden_dim + hidden_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, latent_dim * 2),  # mu, log_sigma
        )

        # Recurrent core
        if core_type == "lstm":
            self.core = nn.LSTMCell(hidden_dim + latent_dim, hidden_dim)
        elif core_type == "gru":
            self.core = nn.GRUCell(hidden_dim + latent_dim, hidden_dim)
        else:  # transformer
            self.core = nn.GRUCell(hidden_dim + latent_dim, hidden_dim)  # fallback

        # Decoder: p(o_t | h_t, z_t)
        self.decoder = nn.Sequential(
            nn.Linear(hidden_dim + latent_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, obs_dim),
        )

        # Risk head: P(infiltration)
        self.risk_head = nn.Sequential(
            nn.Linear(hidden_dim + latent_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid(),
        )

        # Stage head: MITRE tactic distribution
        self.stage_head = nn.Sequential(
            nn.Linear(hidden_dim + latent_dim, hidden_dim),
            nn.ELU(),
            nn.Linear(hidden_dim, 10),  # 10 MITRE stages
            nn.Softmax(dim=-1),
        )

    def initial_state(self, batch_size: int = 1) -> RSSMState:
        """Create initial zero state."""
        device = next(self.parameters()).device
        return RSSMState(
            h=torch.zeros(batch_size, self.hidden_dim, device=device),
            z=torch.zeros(batch_size, self.latent_dim, device=device),
            mu_p=torch.zeros(batch_size, self.latent_dim, device=device),
            sigma_p=torch.ones(batch_size, self.latent_dim, device=device),
            mu_q=torch.zeros(batch_size, self.latent_dim, device=device),
            sigma_q=torch.ones(batch_size, self.latent_dim, device=device),
        )

    def forward_step(
        self,
        obs: torch.Tensor,
        prev_state: RSSMState,
    ) -> tuple[RSSMState, torch.Tensor, torch.Tensor, torch.Tensor]:
        """Single forward step.

        Args:
            obs: (batch, obs_dim) current observation.
            prev_state: Previous RSSM state.

        Returns:
            state: New RSSM state.
            reconstruction: (batch, obs_dim) decoded observation.
            risk: (batch, 1) infiltration probability.
            stage: (batch, 10) stage distribution.
        """
        # Encode observation
        e = self.encoder(obs)  # (batch, hidden_dim)

        # Prior: p(z | h)
        prior_input = prev_state.h
        prior_out = self.prior_net(prior_input)
        mu_p, sigma_p = prior_out.chunk(2, dim=-1)
        sigma_p = F.softplus(sigma_p) + 0.1

        # Posterior: q(z | h, e)
        posterior_input = torch.cat([prev_state.h, e], dim=-1)
        posterior_out = self.posterior_net(posterior_input)
        mu_q, sigma_q = posterior_out.chunk(2, dim=-1)
        sigma_q = F.softplus(sigma_q) + 0.1

        # Sample z from posterior (training) or prior (inference)
        if self.training:
            z = mu_q + sigma_q * torch.randn_like(sigma_q)
        else:
            z = mu_p + sigma_p * torch.randn_like(sigma_p)

        # Recurrent core
        core_input = torch.cat([e, z], dim=-1)
        if self.core_type == "lstm":
            h, _ = self.core(core_input, (prev_state.h, prev_state.z))
        else:
            h = self.core(core_input, prev_state.h)

        # Decode
        decoder_input = torch.cat([h, z], dim=-1)
        reconstruction = self.decoder(decoder_input)

        # Risk and stage
        risk = self.risk_head(decoder_input)
        stage = self.stage_head(decoder_input)

        state = RSSMState(
            h=h,
            z=z,
            mu_p=mu_p,
            sigma_p=sigma_p,
            mu_q=mu_q,
            sigma_q=sigma_q,
        )

        return state, reconstruction, risk, stage

    def forward_sequence(
        self,
        observations: torch.Tensor,
    ) -> tuple[list[RSSMState], torch.Tensor, torch.Tensor, torch.Tensor]:
        """Forward pass over a sequence of observations.

        Args:
            observations: (batch, seq_len, obs_dim) observation sequence.

        Returns:
            states: List of RSSM states for each timestep.
            reconstructions: (batch, seq_len, obs_dim) decoded observations.
            risks: (batch, seq_len, 1) infiltration probabilities.
            stages: (batch, seq_len, 10) stage distributions.
        """
        batch_size, seq_len, _ = observations.shape
        state = self.initial_state(batch_size)

        states = []
        recons = []
        risks = []
        stages = []

        for t in range(seq_len):
            state, recon, risk, stage = self.forward_step(observations[:, t], state)
            states.append(state)
            recons.append(recon)
            risks.append(risk)
            stages.append(stage)

        return (
            states,
            torch.stack(recons, dim=1),
            torch.stack(risks, dim=1),
            torch.stack(stages, dim=1),
        )


def rssm_loss(
    observations: torch.Tensor,
    reconstructions: torch.Tensor,
    risks: torch.Tensor,
    stages: torch.Tensor,
    states: list[RSSMState],
    risk_labels: torch.Tensor | None = None,
    stage_labels: torch.Tensor | None = None,
    beta: float = 0.1,
    lambda_risk: float = 1.0,
    gamma_stage: float = 0.5,
) -> tuple[torch.Tensor, dict[str, float]]:
    """Compute the RSSM loss.

    L = recon_nll(ô_t, o_t) + β·KL(q ‖ p) + λ·BCE(risk, y) + γ·CE(stage, s)

    Returns:
        loss: Total loss.
        metrics: Dict of individual loss components.
    """
    # Reconstruction loss
    recon_loss = F.mse_loss(reconstructions, observations)

    # KL divergence: KL(q(z|h,e) || p(z|h))
    kl_loss = 0.0
    for state in states:
        kl = (
            torch.log(state.sigma_p / state.sigma_q)
            + ((state.sigma_q**2 + (state.mu_q - state.mu_p) ** 2) / (2 * state.sigma_p**2))
            - 0.5
        )
        kl_loss += kl.sum(dim=-1).mean()
    kl_loss /= len(states)

    # Risk loss
    risk_loss = torch.tensor(0.0, device=observations.device)
    if risk_labels is not None:
        risk_loss = F.binary_cross_entropy(risks.squeeze(-1), risk_labels)

    # Stage loss
    stage_loss = torch.tensor(0.0, device=observations.device)
    if stage_labels is not None:
        stage_loss = F.cross_entropy(stages.view(-1, stages.size(-1)), stage_labels.view(-1))

    total = recon_loss + beta * kl_loss + lambda_risk * risk_loss + gamma_stage * stage_loss

    metrics = {
        "recon": recon_loss.item(),
        "kl": kl_loss.item(),
        "risk": risk_loss.item(),
        "stage": stage_loss.item(),
        "total": total.item(),
    }

    return total, metrics
