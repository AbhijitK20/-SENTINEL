from trajectory.case_studies import (
    case_study_topology,
    dubsmash_inspired_case,
    packet_flow_steps,
    replay_topology,
)
from trajectory.dashboard.network_graphs import kill_chain_figure, topology_figure
from trajectory.sequence_detector import ATTACK_TRANSITIONS


def test_case_study_is_synthetic_and_has_complete_flow() -> None:
    phases = dubsmash_inspired_case()
    assert len(phases) == 5
    assert phases[0].source == "credential-dump"
    assert phases[-1].destination == "external-destination"
    assert all(phase.port > 0 for phase in phases)


def test_packet_flow_covers_tcp_http_and_database_layers() -> None:
    layers = {step.layer for step in packet_flow_steps()}
    assert layers == {"TCP", "HTTP", "DB"}
    assert any(step.status == "malicious" for step in packet_flow_steps())


def test_topology_and_kill_chain_figures_have_traces() -> None:
    nodes, edges = case_study_topology()
    topology = topology_figure(nodes, edges)
    kill_chain = kill_chain_figure(ATTACK_TRANSITIONS, active={"credential_abuse"})
    assert len(topology.data) > 0
    assert len(kill_chain.data) > 0


def test_replay_progresses_and_containment_prunes_attacker_edges() -> None:
    _, early_edges = replay_topology(2)
    _, contained_edges = replay_topology(5, contained=True)
    assert len(early_edges) == 2
    assert contained_edges
    assert all(edge["source"] != "attacker-01" for edge in contained_edges)
    assert all(edge["blocked"] is True for edge in contained_edges)
