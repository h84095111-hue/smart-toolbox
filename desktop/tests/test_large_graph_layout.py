from types import SimpleNamespace
from smartintel.graph_algorithms import force_layout

def test_large_graph_uses_scalable_component_layout():
    nodes=[SimpleNamespace(id=f"n{i}") for i in range(500)]
    edges=[SimpleNamespace(source=f"n{i}",target=f"n{i+1}") for i in range(0,498,2)]
    positions=force_layout(nodes,edges)
    assert len(positions)==500
    assert all(-450<=x<=450 and -325<=y<=325 for x,y in positions.values())
