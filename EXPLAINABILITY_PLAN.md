# Explainability Plan

## Objective

Allow an analyst to understand which observed traffic evidence contributed to a forecast and which entities are involved.

## Methods

- Feature attribution such as SHAP or a comparable local method.
- Model attention only when it is not presented as causal proof.
- Evidence extraction from the input windows for human-readable context.

## Explanation Output

Each forecast should show:

1. Forecast probability and horizon.
2. Ranked features with direction and magnitude where available.
3. Supporting events or entities.
4. Data-coverage warnings.
5. A statement that association is not proof of causation.

## Failure Behaviour

If attribution is unavailable or unstable, show that explicitly and avoid a fabricated explanation. Explanations are part of the prediction contract, not decorative UI.
