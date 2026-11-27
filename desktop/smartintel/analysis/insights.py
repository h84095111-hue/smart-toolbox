"""Evidence deduplication, source rating, transparent triage and graph extraction."""
import hashlib,json,re
def canonical_fingerprint(item):
    raw=json.dumps({k:item.get(k) for k in ("title","source","url","content")},sort_keys=True,ensure_ascii=False,default=str).encode()
    return hashlib.sha256(raw).hexdigest()
def deduplicate(items):
    seen=set(); out=[]
    for item in items:
        fp=canonical_fingerprint(item)
        if fp not in seen: seen.add(fp); out.append({**item,"fingerprint":fp})
    return out
def source_credibility(source):
    s=(source or "").lower()
    if any(x in s for x in ("rdap","icann","official registry","government")): label,score="Primary/official",.95
    elif any(x in s for x in ("virustotal","abuseipdb","censys","shodan","otx","misp","crt.sh","urlscan","securitytrails")): label,score="Specialist data provider",.8
    elif any(x in s for x in ("gdelt","news","media")): label,score="Secondary reporting",.65
    else: label,score="Unverified / user supplied",.4
    return {"label":label,"heuristic_score":score,"note":"Source-type heuristic, not proof an individual record is true."}
def risk_score(indicators):
    weights={"malicious":35,"suspicious":15,"abuse":20,"phishing":30,"clean":-5}; total=0; reasons=[]
    for item in indicators:
        label=str(item.get("label","")).lower(); w=next((v for k,v in weights.items() if k in label),0)
        if w: total+=w; reasons.append({"indicator":label,"contribution":w,"source":item.get("source","unknown")})
    score=max(0,min(100,total))
    band="High" if score>=60 else "Elevated" if score>=30 else "Low observed signals" if reasons else "Insufficient data"
    return {"score":score,"band":band,"reasons":reasons,"caveat":"Heuristic triage only. No findings does not mean safe; verify context and freshness."}
def entity_edges(text,source="evidence"):
    import ipaddress
    domains=set(re.findall(r"(?i)\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}\\b",text))
    ips=set(re.findall(r"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b",text)); urls=set(re.findall(r"https?://[^\\s\\]\\[<>\\\"']+",text)); nodes=[]
    nodes += [{"type":"domain","value":x.lower().rstrip("."),"source":source} for x in sorted(domains)]
    for ip in sorted(ips):
        try:
            if ipaddress.ip_address(ip).is_global: nodes.append({"type":"public_ip","value":ip,"source":source})
        except ValueError: pass
    nodes += [{"type":"url","value":x.rstrip(".,);"),"source":source} for x in sorted(urls)]
    return nodes
