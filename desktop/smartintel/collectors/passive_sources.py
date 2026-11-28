"""Rate-limited passive public-source OSINT integrations. No scanning or access-control bypass."""
import os,json,time,threading
from urllib.parse import quote
import requests
TIMEOUT=15
UA={"User-Agent":"SmartIntel/2.0 (public research client)"}
_last={}
_rate_lock=threading.Lock()
def _get(url,params=None,headers=None,timeout=TIMEOUT):
    host=requests.utils.urlparse(url).netloc
    now=time.monotonic()
    with _rate_lock:
        next_allowed=_last.get(host,0.0)
        delay=max(0.0,next_allowed-now)
        _last[host]=max(now,next_allowed)+1.0
    if delay: time.sleep(delay)
    r=requests.get(url,params=params,headers={**UA,**(headers or {})},timeout=timeout); r.raise_for_status(); return r
def _key(provider):
    try:
        import keyring
        value=keyring.get_password("smart-intel",provider.lower())
        if value:return value
    except Exception: pass
    return os.getenv("SMART_INTEL_"+provider.upper().replace(".","_")+"_API_KEY")
def _finding(title,data,source,url="",confidence="Medium"):
    return {"title":title,"content":json.dumps(data,indent=2,ensure_ascii=False,default=str),"source":source,"url":url,"confidence":confidence,"kind":"Passive OSINT"}
def certificate_transparency(domain):
    domain=domain.strip().lower().lstrip("*.")
    if not domain or "/" in domain or " " in domain: raise ValueError("Enter a domain only")
    url="https://crt.sh/"; rows=_get(url,{"q":"%."+domain,"output":"json"}).json(); names=set()
    for row in rows[:5000]:
        for n in row.get("name_value","").splitlines():
            n=n.strip().lower().lstrip("*.")
            if n==domain or n.endswith("."+domain): names.add(n)
    return _finding("Certificate transparency names",{"domain":domain,"names":sorted(names),"records_reviewed":min(len(rows),5000),"note":"CT records do not prove a hostname is currently live."},"crt.sh Certificate Transparency",url)
def wayback(target):
    target=target.strip()
    if not target: raise ValueError("Enter a domain or URL")
    if "://" not in target: target="https://"+target
    if not target.startswith(("http://","https://")): raise ValueError("Only HTTP(S) URLs are supported")
    url="https://web.archive.org/cdx/search/cdx"
    rows=_get(url,{"url":target,"output":"json","fl":"timestamp,original,statuscode,mimetype,digest","filter":"statuscode:200","collapse":"digest","limit":100}).json()
    return _finding("Wayback Machine captures",{"target":target,"captures":rows[1:101] if len(rows)>1 else []},"Internet Archive CDX",url)
def _need(provider):
    key=_key(provider)
    if not key: raise RuntimeError("Configure "+provider+" API key in the OS credential store or SMART_INTEL_"+provider.upper()+"_API_KEY")
    return key
def virustotal_domain(domain):
    key=_need("virustotal"); url="https://www.virustotal.com/api/v3/domains/"+quote(domain,safe="")
    a=_get(url,headers={"x-apikey":key}).json().get("data",{}).get("attributes",{})
    return _finding("VirusTotal domain reputation",{k:a.get(k) for k in ("reputation","last_analysis_stats","last_analysis_date","categories","whois","total_votes")},"VirusTotal API",url)
def abuseipdb_ip(ip):
    key=_need("abuseipdb"); url="https://api.abuseipdb.com/api/v2/check"
    d=_get(url,{"ipAddress":ip,"maxAgeInDays":90},{"Key":key,"Accept":"application/json"}).json().get("data",{})
    return _finding("AbuseIPDB IP reputation",{k:d.get(k) for k in ("ipAddress","isPublic","countryCode","abuseConfidenceScore","totalReports","lastReportedAt","usageType","isp","domain")},"AbuseIPDB API",url)
def urlscan_search(domain):
    url="https://urlscan.io/api/v1/search/"; data=_get(url,{"q":"domain:"+domain,"size":50}).json()
    rows=[]
    for x in data.get("results",[])[:50]:
        p=x.get("page",{}); rows.append({"scan_id":x.get("_id"),"time":x.get("task",{}).get("time"),"url":x.get("task",{}).get("url"),"domain":p.get("domain"),"ip":p.get("ip"),"verdicts":x.get("verdicts")})
    return _finding("urlscan public scan search",{"domain":domain,"results":rows},"urlscan.io",url)
def otx_domain(domain):
    key=_need("otx"); url="https://otx.alienvault.com/api/v1/indicators/domain/"+quote(domain,safe="")+"/general"
    d=_get(url,headers={"X-OTX-API-KEY":key}).json()
    return _finding("AlienVault OTX domain pulses",{"pulse_info":d.get("pulse_info"),"validation":d.get("validation")},"AlienVault OTX API",url)
def _public_ip(ip):
    import ipaddress
    address=ipaddress.ip_address(ip.strip())
    if not address.is_global: raise ValueError("Only globally routable public IP addresses are supported")
    return str(address)
def shodan_host(ip):
    ip=_public_ip(ip); key=_need("shodan"); url="https://api.shodan.io/shodan/host/"+quote(ip,safe="")
    d=_get(url,{"key":key}).json()
    # Deliberately omit port/service/vulnerability fingerprint fields.
    return _finding("Shodan existing host metadata",{k:d.get(k) for k in ("ip_str","org","isp","asn","country_name","last_update","tags")},"Shodan API (existing observations)",url)
def censys_host(ip):
    ip=_public_ip(ip); key=_need("censys"); url="https://api.platform.censys.io/v3/global/asset/host/"+quote(ip,safe="")
    d=_get(url,headers={"Authorization":"Bearer "+key}).json()
    # Keep only coarse host/ownership metadata; exclude services and port fingerprints.
    root=d.get("result",d)
    allowed=("ip","last_updated_at","location","autonomous_system","labels","resource")
    summary={k:root.get(k) for k in allowed if k in root and k!="resource"}
    return _finding("Censys existing host metadata",summary,"Censys API (existing observations)",url)
def passive_dns_history(domain):
    key=_need("securitytrails"); url="https://api.securitytrails.com/v1/history/"+quote(domain,safe="")+"/dns/a"
    return _finding("Passive DNS history",_get(url,headers={"APIKEY":key}).json(),"SecurityTrails API",url)
def misp_search(base_url,value):
    key=_need("misp"); base=base_url.strip().rstrip("/")
    if not base.startswith("https://"): raise ValueError("MISP URL must use HTTPS")
    url=base+"/attributes/restSearch"
    r=requests.post(url,json={"value":value,"limit":50},headers={**UA,"Authorization":key,"Accept":"application/json"},timeout=20)
    r.raise_for_status()
    return _finding("MISP exact IOC matches",r.json(),"User-configured MISP instance",url)
def gdelt_news(query):
    if not query.strip(): raise ValueError("Enter a company, organization or topic")
    url="https://api.gdeltproject.org/api/v2/doc/doc"
    d=_get(url,{"query":query,"mode":"ArtList","format":"json","maxrecords":50,"sort":"DateDesc"}).json()
    return _finding("Public news results",d.get("articles",[]),"GDELT Project",url,"Low")
def public_username_reference(username):
    import re
    name=username.strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}",name): raise ValueError("Enter a valid public username")
    links={"GitHub":"https://github.com/"+name,"GitLab":"https://gitlab.com/"+name,"Reddit":"https://www.reddit.com/user/"+name+"/","X":"https://x.com/"+name}
    return _finding("Public profile reference links",{"username":name,"links":links,"note":"Search starting points only; no account existence, identity or ownership is verified."},"User-supplied public handle",confidence="Low")
def breach_check_guidance(identifier):
    if not identifier.strip(): raise ValueError("Enter an identifier you are authorized to assess")
    return _finding("Authorized breach-check workflow",{"identifier":identifier.strip(),"status":"Not queried","recommended":"Verified-domain search in Have I Been Pwned or an organization-approved breach notification provider.","privacy":"This app does not retrieve stolen credentials or password dumps. Do not assess identifiers without authorization."},"Smart Intel safety workflow","https://haveibeenpwned.com/DomainSearch","High")
