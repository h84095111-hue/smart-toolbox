"""Evidence-backed identity graph. Nodes are leads, never proof of a person's identity."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any
import hashlib, json, re
from urllib.parse import urlparse, unquote

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
        return {"generated_at":self.generated_at,"nodes":[asdict(n) for n in self.nodes],"edges":[asdict(e) for e in self.edges]}
    def to_json(self) -> str:
        return json.dumps(self.to_dict(),ensure_ascii=False,indent=2)

_EMAIL=re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
_URL=re.compile(r"https?://[^\s<>'\"]+",re.I)
_HANDLE=re.compile(r"(?<![\w@])@([A-Za-z0-9_]{2,30})")
_PHONE=re.compile(r"(?<!\w)(?:\+\d[\d\s().-]{7,}\d)(?!\w)")

def _node_id(kind: str,value: str)->str:
    return kind+":"+hashlib.sha256((kind+":"+value.casefold()).encode()).hexdigest()[:16]

def _structured_candidates(title: str,url: str,content: str):
    """Read semantic HTML attributes and link schemes before text-pattern fallback."""
    found=[]
    try:
        from bs4 import BeautifulSoup
        soup=BeautifulSoup(content,"html.parser")
        for tag in soup.find_all(True):
            attrs=tag.attrs
            key=" ".join(str(attrs.get(k,"")) for k in ("itemprop","name","property","rel","class","id")).casefold()
            value=str(attrs.get("content") or attrs.get("value") or "").strip()
            if value:
                if any(word in key for word in ("email","e-mail")):
                    found.append(("email",value,"Email value from semantic HTML metadata"))
                if any(word in key for word in ("telephone","phone","tel")):
                    found.append(("phone",value,"Phone value from semantic HTML metadata"))
                if any(word in key for word in ("author","username","screen_name","twitter:creator")):
                    found.append(("username",value.lstrip("@"),"Account label from semantic HTML metadata"))
            href=str(attrs.get("href") or "").strip()
            if href.lower().startswith("mailto:"):
                found.append(("email",unquote(href[7:].split("?")[0]),"mailto link in supplied HTML"))
            elif href.lower().startswith("tel:"):
                found.append(("phone",unquote(href[4:].split("?")[0]),"tel link in supplied HTML"))
            elif href.startswith(("https://","http://")):
                found.append(("profile_or_url",href,"HTTP link in supplied HTML"))
        text=soup.get_text(" ",strip=True)
    except Exception:
        text=content
    return found,text

def build_identity_graph(evidence: list[Any])->IdentityGraph:
    """Extract structured identifiers plus text-pattern leads with evidence provenance."""
    nodes={}; edges={}
    def node(kind,label,eid):
        key=_node_id(kind,label)
        if key not in nodes:nodes[key]=GraphNode(key,kind,label,[])
        if eid not in nodes[key].evidence_ids:nodes[key].evidence_ids.append(eid)
        return key
    for item in evidence:
        eid=str(getattr(item,"id","") or "unknown")
        source_label=str(getattr(item,"source","Unknown") or "Unknown")
        title=str(getattr(item,"title","") or "")
        url=str(getattr(item,"url","") or "")
        content=str(getattr(item,"content","") or "")
        structured,visible_text=_structured_candidates(title,url,content)
        source_id=node("source",source_label,eid)
        candidates=list(structured)
        searchable=" ".join((title,url,visible_text))
        candidates.extend(("email",value.lower(),"Email-like text pattern in supplied evidence") for value in _EMAIL.findall(searchable))
        candidates.extend(("username",value,"Handle-like text pattern in supplied evidence") for value in _HANDLE.findall(searchable))
        for value in _PHONE.findall(searchable):
            normalized=re.sub(r"[^\d+]","",value)
            if len(re.sub(r"\D","",normalized))>=8:
                candidates.append(("phone",normalized,"Phone-like text pattern; ownership is not verified"))
        candidates.extend(("profile_or_url",value.rstrip(".,);]"),"URL text pattern in supplied evidence") for value in _URL.findall(searchable))
        if url and urlparse(url).hostname:candidates.append(("profile_or_url",url,"Evidence record URL"))
        seen=set(); observed=[]
        for kind,label,why in candidates:
            label=str(label).strip()
            if not label:continue
            if kind=="email":label=label.casefold()
            token=(kind,label.casefold())
            if token in seen:continue
            seen.add(token)
            target=node(kind,label,eid); observed.append((target,kind,label))
            key=(source_id,target,"observed_in")
            if key not in edges:edges[key]=GraphEdge(source_id,target,"observed_in",[eid],why,"low")
            elif eid not in edges[key].evidence_ids:edges[key].evidence_ids.append(eid)
        # Same-record co-occurrence is a lead only, never an ownership assertion.
        observed=observed[:20]
        for i,(left,lk,ll) in enumerate(observed):
            for right,rk,rl in observed[i+1:]:
                if left==right:continue
                a,b=sorted((left,right)); key=(a,b,"co_observed")
                rationale=f"{lk} '{ll}' and {rk} '{rl}' occur in the same evidence record; this is not proof of common ownership."
                if key not in edges:edges[key]=GraphEdge(a,b,"co_observed",[eid],rationale,"low")
                elif eid not in edges[key].evidence_ids:edges[key].evidence_ids.append(eid)
    return IdentityGraph(list(nodes.values()),list(edges.values()),datetime.now(timezone.utc).isoformat())

def validate_graph(graph: IdentityGraph)->None:
    ids={n.id for n in graph.nodes}
    for edge in graph.edges:
        if edge.source not in ids or edge.target not in ids:raise ValueError("Graph edge references an unknown node")
        if not edge.evidence_ids:raise ValueError("Every graph edge must cite evidence")
