from types import SimpleNamespace
from smartintel.match_scoring import assess_evidence_risk
from smartintel.identity_graph import build_identity_graph

def test_risk_only_rewards_the_selected_exact_email_identifier():
    evidence=[SimpleNamespace(id="1",source="A",title="Profile",url="https://a.test",content="Contact alice@example.com",observed_at="2026-11-01")]
    email=SimpleNamespace(kind="email",label="alice@example.com")
    unrelated=SimpleNamespace(kind="email",label="bob@example.com")
    supported=assess_evidence_risk(evidence,subject=email)
    unsupported=assess_evidence_risk(evidence,subject=unrelated)
    assert supported.score < unsupported.score
    assert any(f["factor"]=="exact_email" for f in supported.factors)
    assert not any(f["factor"]=="exact_email" for f in unsupported.factors)

def test_unrelated_email_does_not_reduce_username_risk():
    evidence=[SimpleNamespace(id="1",source="A",title="Public profile @alice",url="",content="Contact unrelated@example.com",observed_at="2026-11-01")]
    subject=SimpleNamespace(kind="username",label="alice")
    result=assess_evidence_risk(evidence,subject=subject)
    assert not any(f["factor"]=="exact_email" for f in result.factors)
    assert result.score>=55

def test_staleness_uses_rolling_age_not_hard_coded_years():
    old=[SimpleNamespace(id="1",source="A",title="Old",url="",content="",observed_at="2020-01-01T00:00:00+00:00")]
    fresh=[SimpleNamespace(id="2",source="A",title="Fresh",url="",content="",observed_at="2026-11-27T00:00:00+00:00")]
    subject=SimpleNamespace(kind="username",label="alice")
    assert assess_evidence_risk(old,subject=subject).score > assess_evidence_risk(fresh,subject=subject).score

def test_graph_links_identifiers_coobserved_with_provenance():
    evidence=[SimpleNamespace(id="ev-1",source="Public page",title="Alice",url="https://example.test/a",
        content="Contact alice@example.com and profile @alice_dev",observed_at="2026-11-01")]
    graph=build_identity_graph(evidence)
    assert any(e.relation=="co_observed" and "ev-1" in e.evidence_ids for e in graph.edges)
    assert all(e.evidence_ids for e in graph.edges)
