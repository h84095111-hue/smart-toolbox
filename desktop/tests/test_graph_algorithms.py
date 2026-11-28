from types import SimpleNamespace
from smartintel.identity_graph import build_identity_graph
from smartintel.graph_algorithms import connected_components, filter_graph, force_layout

def make_graph():
    evidence=[
        SimpleNamespace(id="a",source="A",title="a@example.org @alpha",url="",content=""),
        SimpleNamespace(id="b",source="B",title="a@example.org @alpha",url="",content=""),
        SimpleNamespace(id="c",source="C",title="separate@example.net @beta",url="",content=""),
    ]
    return build_identity_graph(evidence)

def test_connected_components_groups_linked_identifiers():
    graph=make_graph()
    clusters=connected_components(graph.nodes,graph.edges)
    assert clusters
    assert clusters[next(n.id for n in graph.nodes if n.label=="a@example.org")] == clusters[next(n.id for n in graph.nodes if n.label=="alpha")]
    assert clusters[next(n.id for n in graph.nodes if n.label=="separate@example.net")] != clusters[next(n.id for n in graph.nodes if n.label=="a@example.org")]

def test_filters_apply_kind_relation_and_label_query():
    graph=make_graph()
    nodes,edges=filter_graph(graph,"email","All relationships","example.org")
    assert nodes and all(n.kind=="email" and "example.org" in n.label for n in nodes)
    assert all(e.source in {n.id for n in nodes} and e.target in {n.id for n in nodes} for e in edges)
    _,co_edges=filter_graph(graph,"All types","co_observed","")
    assert all(e.relation=="co_observed" for e in co_edges)

def test_force_layout_is_deterministic_and_returns_every_node():
    graph=make_graph()
    first=force_layout(graph.nodes,graph.edges)
    second=force_layout(graph.nodes,graph.edges)
    assert first==second
    assert set(first)=={n.id for n in graph.nodes}
    assert all(len(point)==2 for point in first.values())
