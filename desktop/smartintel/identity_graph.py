"""Evidence-backed identity graph. Nodes are leads, never proof of a person's identity."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any
import hashlib, json, re
from urllib.parse import urlparse

@dataclass
class GraphNode:
    id: str
    kind: str
    label: str
    evidence_ids: list[str]

@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str
    evidence_ids: list[str]
    rationale: str
    confidence: str = "low"

@dataclass
class IdentityGraph:
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    generated_at: str
    def to_dict(self) -> dict[str, Any]:
        return {"generated_at": self.generated_at, "nodes":[asdict(n) for n in self.nodes], "edges":[asdict(e) for e in self.edges]}
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
_URL = re.compile(r"https?://[^\s<>'\"]+", re.I)
_HANDLE = re.compile(r"(?<![\w@])@([A-Za-z0-9_]{2,30})")
_PHONE = re.compile(r"(?<!\w)(?:\+\d[\d\s().-]{7,}\d)(?!\w)")

def _node_id(kind: str, value: str) -> str:
    return kind + ":" + hashlib.sha256((kind+":"+value.casefold()).encode()).hexdigest()[:16]

def build_identity_graph(evidence: list[Any]) -> IdentityGraph:
    """Extract conservative public identifiers and attach each to its evidence source."""
    nodes: dict[str, GraphNode] = {}
    edges: dict[tuple[str,str,str], GraphEdge] = {}
    def node(kind: str, label: str, eid: str) -> str:
        key=_node_id(kind,label)
        if key not in nodes: nodes[key]=GraphNode(key,kind,label,[])
        if eid not in nodes[key].evidence_ids: nodes[key].evidence_ids.append(eid)
        return key
    for item in evidence:
        eid=str(getattr(item,"id","") or "unknown")
        source_label=str(getattr(item,"source","Unknown") or "Unknown")
        title=str(getattr(item,"title","") or "")
        url=str(getattr(item,"url","") or "")
        content=str(getattr(item,"content","") or "")
        source_id=node("source",source_label,eid)
        candidates=[]
        for value in _EMAIL.findall(title+" "+url+" "+content):
            candidates.append(("email",value.lower(),"Exact email string found in supplied evidence"))
        for value in _HANDLE.findall(title+" "+url+" "+content):
            candidates.append(("username",value,"Public handle-like string found in supplied evidence"))
        for value in _PHONE.findall(title+" "+content):
            normalized=re.sub(r"[^\d+]","",value)
            if len(re.sub(r"\D","",normalized))>=8:
                candidates.append(("phone",normalized,"Phone-like string found; ownership is not verified"))
        for value in _URL.findall(title+" "+content):
            clean=value.rstrip(".,);]")
            host=urlparse(clean).hostname
            if host:
                candidates.append(("profile_or_url",clean,"URL explicitly present in supplied evidence"))
        if url:
            host=urlparse(url).hostname
            if host: candidates.append(("profile_or_url",url,"Evidence record URL"))
        seen=set()
        for kind,label,why in candidates:
            token=(kind,label.casefold())
            if token in seen: continue
            seen.add(token)
            target=node(kind,label,eid)
            key=(source_id,target,"observed_in")
            if key not in edges: edges[key]=GraphEdge(source_id,target,"observed_in",[eid],why,"low")
            elif eid not in edges[key].evidence_ids: edges[key].evidence_ids.append(eid)
    return IdentityGraph(list(nodes.values()),list(edges.values()),datetime.now(timezone.utc).isoformat())

def validate_graph(graph: IdentityGraph) -> None:
    ids={n.id for n in graph.nodes}
    for edge in graph.edges:
        if edge.source not in ids or edge.target not in ids: raise ValueError("Graph edge references an unknown node")
        if not edge.evidence_ids: raise ValueError("Every graph edge must cite evidence")
