from types import SimpleNamespace
import pytest
from smartintel.identity_graph import build_identity_graph, validate_graph
from smartintel.match_scoring import assess_false_positive_risk, calibration_status

def test_graph_links_extracted_identifiers_to_sources():
    ev=SimpleNamespace(id="e1",source="Public page",title="Profile",url="https://example.org/u/tester",content="Contact: analyst@example.org @tester")
    graph=build_identity_graph([ev])
    kinds={n.kind for n in graph.nodes}
    assert {"source","email","username","profile_or_url"} <= kinds
    assert graph.edges and all(e.evidence_ids==["e1"] for e in graph.edges)
    validate_graph(graph)

def test_same_identifier_keeps_multiple_evidence_refs():
    items=[SimpleNamespace(id="e1",source="A",title="",url="",content="mail a@example.org"),
           SimpleNamespace(id="e2",source="B",title="",url="",content="mail a@example.org")]
    graph=build_identity_graph(items)
    email=next(n for n in graph.nodes if n.kind=="email")
    assert set(email.evidence_ids)=={"e1","e2"}

def test_contradictions_increase_false_positive_risk():
    base=assess_false_positive_risk()
    conflict=assess_false_positive_risk(contradictions=2)
    assert conflict.score>base.score

def test_stronger_cross_links_reduce_risk_but_not_to_zero():
    result=assess_false_positive_risk(exact_email=True,cross_linked_profile=True,independent_sources=2)
    assert 0<result.score<55
    assert result.calibration=="uncalibrated_heuristic"

def test_name_only_is_high_risk():
    assert assess_false_positive_risk(display_name_only=True).score > assess_false_positive_risk().score

def test_calibration_requires_labeled_examples():
    assert calibration_status(12).startswith("uncalibrated")
    assert "candidate" in calibration_status(150)


def test_local_ai_prompt_contains_evidence_and_untrusted_data_warning():
    from smartintel.ai_analysis import build_analysis_prompt
    evidence=SimpleNamespace(id="ev-1",title="Public profile",source="Example",url="https://example.org",observed_at="2026-01-01T00:00:00Z",content="A profile bio")
    prompt=build_analysis_prompt("summarize",{"nodes":[],"edges":[]},{"score":55},[evidence])
    assert "ev-1" in prompt and "A profile bio" in prompt
    assert "untrusted data" in prompt.lower()
    assert "Do not convert the heuristic risk index into a probability" in prompt
