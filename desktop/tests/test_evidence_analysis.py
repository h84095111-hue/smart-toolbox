from types import SimpleNamespace
from smartintel.match_scoring import assess_evidence_risk
from smartintel.identity_graph import build_identity_graph

def test_evidence_risk_uses_real_case_values_and_factors():
    evidence=[SimpleNamespace(id="1",source="A",title="Profile",url="https://a.test",content="Contact alice@example.com",observed_at="2026-11-01"),
              SimpleNamespace(id="2",source="B",title="Profile",url="https://b.test",content="Contact alice@example.com",observed_at="2026-11-02")]
    result=assess_evidence_risk(evidence)
    assert result.score < 55
    assert any(x["factor"]=="exact_email" for x in result.factors)
    assert any(x["factor"]=="independent_sources" for x in result.factors)
    assert result.calibration=="uncalibrated_heuristic"

def test_graph_links_identifiers_coobserved_with_provenance():
    evidence=[SimpleNamespace(id="ev-1",source="Public page",title="Alice",url="https://example.test/a",
        content="Contact alice@example.com and profile @alice_dev",observed_at="2026-11-01")]
    graph=build_identity_graph(evidence)
    assert any(e.relation=="co_observed" and "ev-1" in e.evidence_ids for e in graph.edges)
    assert all(e.evidence_ids for e in graph.edges)
