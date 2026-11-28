from types import SimpleNamespace
from smartintel.identity_graph import build_identity_graph

def test_semantic_html_email_and_profile_links_are_extracted():
    evidence=SimpleNamespace(
        id="html-1",source="HTML fixture",title="Profile",
        url="https://example.org/profile",
        content='<html><head><meta itemprop="email" content="person@example.org"></head>'
                '<body><a href="mailto:contact@example.org">Contact</a>'
                '<a href="https://social.example/@person">Social profile</a></body></html>')
    graph=build_identity_graph([evidence])
    pairs={(node.kind,node.label) for node in graph.nodes}
    assert ("email","person@example.org") in pairs
    assert ("email","contact@example.org") in pairs
    assert ("profile_or_url","https://social.example/@person") in pairs
    assert all(edge.evidence_ids==["html-1"] for edge in graph.edges)
