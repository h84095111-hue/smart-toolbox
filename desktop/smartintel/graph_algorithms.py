"""Graph filtering, connected-component clustering and deterministic force layout."""
from __future__ import annotations
import hashlib
import math
from collections import defaultdict, deque
from typing import Iterable

def connected_components(nodes, edges):
    ids={n.id for n in nodes}
    adjacency={node_id:set() for node_id in ids}
    for edge in edges:
        if edge.source in ids and edge.target in ids:
            adjacency[edge.source].add(edge.target)
            adjacency[edge.target].add(edge.source)
    groups=[]; seen=set()
    for start in sorted(ids):
        if start in seen: continue
        queue=deque([start]); seen.add(start); group=[]
        while queue:
            current=queue.popleft(); group.append(current)
            for neighbor in sorted(adjacency[current]):
                if neighbor not in seen:
                    seen.add(neighbor); queue.append(neighbor)
        groups.append(sorted(group))
    return {node_id:index for index,group in enumerate(groups) for node_id in group}

def filter_graph(graph, node_kind="All types", relation="All relationships", query=""):
    """Return visible nodes/edges; edge evidence provenance remains unchanged."""
    needle=(query or "").casefold().strip()
    nodes=[n for n in graph.nodes if (node_kind=="All types" or n.kind==node_kind)
           and (not needle or needle in n.label.casefold())]
    visible={n.id for n in nodes}
    edges=[e for e in graph.edges if e.source in visible and e.target in visible
           and (relation=="All relationships" or e.relation==relation)]
    # A relationship filter can leave isolated nodes visible intentionally.
    return nodes,edges

def force_layout(nodes, edges, iterations=120, width=900.0, height=650.0):
    """Small deterministic Fruchterman-Reingold layout; no third-party dependency."""
    count=len(nodes)
    if not count: return {}
    if count==1: return {nodes[0].id:(0.0,0.0)}
    # Exact all-pairs repulsion is useful for small graphs but quadratic for large cases.
    # For larger graphs use a deterministic component-aware layout with O(V+E) work.
    if count > 180:
        components=connected_components(nodes,edges)
        groups={}
        for node in nodes: groups.setdefault(components[node.id],[]).append(node)
        ordered=[groups[key] for key in sorted(groups)]
        cols=max(1,math.ceil(math.sqrt(len(ordered))))
        rows=math.ceil(len(ordered)/cols)
        cell_w=width/cols; cell_h=height/rows
        result={}
        for index,group in enumerate(ordered):
            col=index%cols; row=index//cols
            cx=-width/2+(col+0.5)*cell_w; cy=-height/2+(row+0.5)*cell_h
            radius=min(cell_w,cell_h)*0.32
            for j,node in enumerate(sorted(group,key=lambda item:item.id)):
                angle=2*math.pi*j/max(1,len(group))-math.pi/2
                local=radius*min(1.0,math.sqrt(len(group)/12))
                result[node.id]=(cx+local*math.cos(angle),cy+local*math.sin(angle))
        return result
    area=width*height; k=math.sqrt(area/count)
    positions={}
    for node in nodes:
        digest=hashlib.sha256(node.id.encode()).digest()
        angle=int.from_bytes(digest[:4],"big")/2**32*2*math.pi
        radius=0.28*min(width,height)*(0.35+digest[4]/255*0.65)
        positions[node.id]=[radius*math.cos(angle),radius*math.sin(angle)]
    ids=[n.id for n in nodes]; allowed=set(ids)
    pairs=[(e.source,e.target) for e in edges if e.source in allowed and e.target in allowed]
    temperature=min(width,height)*0.12
    for step in range(max(1,iterations)):
        disp={key:[0.0,0.0] for key in ids}
        for i,left in enumerate(ids):
            lx,ly=positions[left]
            for right in ids[i+1:]:
                rx,ry=positions[right]; dx=lx-rx; dy=ly-ry
                distance=max(0.01,math.hypot(dx,dy)); force=k*k/distance
                fx=dx/distance*force; fy=dy/distance*force
                disp[left][0]+=fx; disp[left][1]+=fy
                disp[right][0]-=fx; disp[right][1]-=fy
        for left,right in pairs:
            if left==right: continue
            lx,ly=positions[left]; rx,ry=positions[right]; dx=lx-rx; dy=ly-ry
            distance=max(0.01,math.hypot(dx,dy)); force=distance*distance/k
            fx=dx/distance*force; fy=dy/distance*force
            disp[left][0]-=fx; disp[left][1]-=fy
            disp[right][0]+=fx; disp[right][1]+=fy
        for key in ids:
            dx,dy=disp[key]; magnitude=max(0.01,math.hypot(dx,dy))
            step_size=min(magnitude,temperature)
            x=positions[key][0]+dx/magnitude*step_size
            y=positions[key][1]+dy/magnitude*step_size
            positions[key]=[max(-width/2,min(width/2,x)),max(-height/2,min(height/2,y))]
        temperature*=0.965
    return {key:(value[0],value[1]) for key,value in positions.items()}
