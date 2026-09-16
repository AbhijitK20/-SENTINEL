# SPDX-License-Identifier: Apache-2.0
"""Imagine — forward simulation using the RSSM prior.

Rolls the PRIOR forward k steps with no observations, sampling z each step.
This is how the model generates imagined futures.
"""

from __future__ import annotations

from dataclasses import dataclass

import torch

from sentinel.world_model.model import RSSMCore, RSSMState


@dataclass
class ImaginedRollout:
    """Result of a forward simulation."""

    observations: torch.Tensor  # (batch, k, obs_dim) imagined observations
    risks: torch.Tensor  # (batch, k, 1) per-sample risk
    stages: torch.Tensor  # (batch, k, 10) per-sample stage distribution
    prior_divergence: torch.Tensor  # (batch, k) KL divergence at each step
    z_samples: torch.Tensor  # (batch, k, latent_dim) sampled latents


def imagine(
    core: RSSMCore,
    history: list[RSSMState],
    k: int,
    n_samples: int = 100,
    temperature: float = 1.0,
) -> ImaginedRollout:
    """Roll the PRIOR forward k steps with no observations.

    Args:
        core: The RSSM core module.
        history: List of past RSSM states (from observations).
        k: Number of future steps to simulate.
        n_samples: Number of parallel samples.
        temperature: Sampling temperature (higher = more diverse).

    Returns:
        ImaginedRollout with decoded states, risks, stages, and diagnostics.
    """
    device = next(core.parameters()).device

    # Start from the last observed state
    last_state = history[-1]
    batch_size = n_samples

    # Expand to n_samples
    h = last_state.h.expand(batch_size, -1).clone()
    z = last_state.z.expand(batch_size, -1).clone()

    observations = []
    risks = []
    stages = []
    divergences = []
    z_samples = []

    for step in range(k):
        # Prior: p(z | h)
        prior_out = core.prior_net(h)
        mu_p, log_sigma_p = prior_out.chunk(2, dim=-1)
        sigma_p = F.softplus(log_sigma_p) + 0.1

        # Sample z from prior (with temperature)
        z = mu_p + sigma_p * torch.randn_like(sigma_p) * temperature
        z_samples.append(z)

        # Recurrent core (no observation input)
        e = torch.zeros(batch_size, core.hidden_dim, device=device)
        core_input = torch.cat([e, z], dim=-1)

        if core.core_type == "lstm":
            h, _ = core.core(core_input, (h, z))
        else:
            h = core.core(core_input, h)

        # Decode
        decoder_input = torch.cat([h, z], dim=-1)
        obs = core.decoder(decoder_input)
        observations.append(obs)

        # Risk and stage
        risk = core.risk_head(decoder_input)
        risks.append(risk)

        stage = core.stage_head(decoder_input)
        stages.append(stage)

        # Compute prior-posterior divergence (for diagnostics)
        # During imagine, we only have the prior, so divergence is 0
        divergences.append(torch.zeros(batch_size, device=device))

    return ImaginedRollout(
        observations=torch.stack(observations, dim=1),
        risks=torch.stack(risks, dim=1),
        stages=torch.stack(stages, dim=1),
        prior_divergence=torch.stack(divergences, dim=1),
        z_samples=torch.stack(z_samples, dim=1),
    )


def compute_diagnostics(
    rollout: ImaginedRollout,
    threshold: float = 0.5,
) -> dict[str, float]:
    """Compute diagnostics from an imagined rollout.

    Returns:
        Dict with metrics like mean_risk, crossing_rate, uncertainty_spread.
    """
    risks = rollout.risks.squeeze(-1)  # (batch, k)

    # Mean risk over samples and time
    mean_risk = risks.mean().item()

    # Crossing rate: fraction of samples that ever cross the threshold
    crossing_rate = (risks.max(dim=1).values > threshold).float().mean().item()

    # Uncertainty spread: std of risk across samples at final step
    uncertainty_spread = risks[:, -1].std().item()

    # Mean divergence
    mean_divergence = rollout.prior_divergence.mean().item()

    return {
        "mean_risk": mean_risk,
        "crossing_rate": crossing_rate,
        "uncertainty_spread": uncertainty_spread,
        "mean_divergence": mean_divergence,
    }
