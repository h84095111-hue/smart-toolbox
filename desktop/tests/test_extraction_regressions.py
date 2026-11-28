from types import SimpleNamespace
from smartintel.identity_graph import build_identity_graph

def test_semantic_html_email_and_profile_links_are_extracted():
    evidence=SimpleNamespace(id="html-1",source="HTML fixture",title="Profile",
        url="https://example.org/profile",
        content='<html><head><meta itemprop="email" content="person@example.org"></head>'
                '<body><a href="mailto:contact@example.org">Contact</a>'
                '<a href="https://social.example/@person" rel="me">Social profile</a></body></html>')
    graph=build_identity_graph([evidence])
    pairs={(node.kind,node.label) for node in graph.nodes}
    assert ("email","person@example.org") in pairs
    assert ("email","contact@example.org") in pairs
    assert ("profile_or_url","https://social.example/@person") in pairs
    assert all(edge.evidence_ids==["html-1"] for edge in graph.edges)

def test_phone_attribute_token_matching_does_not_match_hotel_or_intel():
    evidence=SimpleNamespace(id="html-2",source="HTML fixture",title="Metadata",
        url="https://example.org",content='<meta name="hotel" content="Grand Hotel">'
                '<meta name="intel" content="Intel Corporation">'
                '<meta itemprop="telephone" content="1234567">'
                '<meta itemprop="telephone" content="+60123456789">')
    graph=build_identity_graph([evidence])
    phones=[node.label for node in graph.nodes if node.kind=="phone"]
    assert phones==["+60123456789"]

def test_collector_semantic_identifier_json_survives_html_stripping():
    evidence=SimpleNamespace(id="json-1",source="HTTP public page",title="Website",
        url="https://example.org",content='{"semantic_identifiers":[{"kind":"phone","value":"1234567"},{"kind":"phone","value":"+60123456789","reason":"tel link"}]}')
    graph=build_identity_graph([evidence])
    phones=[node.label for node in graph.nodes if node.kind=="phone"]
    assert phones==["+60123456789"]
