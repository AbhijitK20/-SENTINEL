# SPDX-License-Identifier: Apache-2.0
"""The host/flow graph view of a network window.

``build_network_graph`` turns a ``NetworkState`` into nodes (hosts) and directed
edges (observed host pairs) with behavioural features only - no one-hot IPs and
no hostname embeddings, because identity is exactly the thing that must not leak
into a behavioural model.

There is deliberately no graph neural network here. A hand-rolled multi-head GAT
lived in this package for a while: 200 lines of plain PyTorch, with no caller,
no trained weights, and no path to a forecast. Nothing in the pipeline built a
graph for it, so it could not have been exercised and it never was. Wiring a GAT
in properly would mean a trained graph classifier, a fusion layer, an
evaluation, and shipped weights - a new model, not a cleanup - so it was deleted
rather than left to look like a capability. The graph builder stayed because it
is used and tested.

If a graph encoder is ever added, it has to arrive with weights, a measured
result against this baseline, and a place in the forecast path. Add it then, not
before.
"""
