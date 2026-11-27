"""Orchestrate one target through relevant passive public-source connectors."""
import ipaddress,re
from urllib.parse import urlparse
from .passive import collect_domain, collect_ip, collect_website
from . import passive_sources as src

def run_all(target, misp_url=""):
    raw=(target or "").strip()
    if not raw: raise ValueError("Enter a domain, public IP address or website URL.")
    raw_is_email=bool(re.fullmatch(r"[^\\s@]+@[^\\s@]+\\.[^\\s@]+",raw))
    parsed=urlparse(raw if "://" in raw else "https://"+raw)
    is_url=("://" in raw) or ("/" in raw)
    host=raw if raw_is_email else (parsed.hostname if is_url else raw)
    if not host: raise ValueError("Could not identify a target host.")
    try:
        ip=ipaddress.ip_address(host)
        is_ip=True
    except ValueError:
        ip=None; is_ip=False
    findings=[]; failures=[]; skipped=[]
    def run(label, fn, *args):
        try:
            item=fn(*args)
            if item is None: skipped.append(label+": no result"); return
            values=item if isinstance(item,list) else [item]
            for value in values:
                if isinstance(value,dict):
                    findings.append(value)
                else:
                    findings.append({"title":getattr(value,"title","Finding"),"content":getattr(value,"value",str(value)),"source":getattr(value,"source",label),"url":getattr(value,"url",""),"confidence":getattr(value,"confidence","Medium"),"kind":"Passive OSINT"})
        except Exception as exc:
            message=str(exc).strip() or exc.__class__.__name__
            if "API key" in message or "not configured" in message or "credential" in message.lower():
                skipped.append(label+": provider key/configuration missing")
            else:
                failures.append(label+": "+message[:350])
    is_email=bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",host))
    is_username=not is_ip and not is_email and not is_url and "." not in host and bool(re.fullmatch(r"@?[A-Za-z0-9_.-]{2,64}",host))
    if is_ip:
        if not ip.is_global: raise ValueError("Only globally routable public IP addresses are supported.")
        run("IP RDAP and reverse DNS",collect_ip,str(ip))
        run("AbuseIPDB",src.abuseipdb_ip,str(ip))
        run("Shodan existing host metadata",src.shodan_host,str(ip))
        run("Censys existing host metadata",src.censys_host,str(ip))
        if misp_url.strip(): run("MISP exact IOC",src.misp_search,misp_url.strip(),str(ip))
    elif is_email:
        run("Authorized breach notification guidance",src.breach_check_guidance,host)
        skipped.append("Email enrichment: no personal email dossier or leaked-credential search is performed")
        if misp_url.strip(): run("MISP exact IOC",src.misp_search,misp_url.strip(),host)
    elif is_username:
        run("Public username reference links",src.public_username_reference,host)
        skipped.append("Username matches are references only; account ownership is not verified")
        if misp_url.strip(): run("MISP exact IOC",src.misp_search,misp_url.strip(),host)
    else:
        domain=host.lower().rstrip(".")
        if is_url:
            run("Public website metadata",collect_website,raw)
        run("DNS/RDAP/TLS metadata",collect_domain,domain)
        run("Certificate transparency",src.certificate_transparency,domain)
        run("Wayback archive",src.wayback,raw if is_url else domain)
        run("VirusTotal domain",src.virustotal_domain,domain)
        run("urlscan existing results",src.urlscan_search,domain)
        run("AlienVault OTX",src.otx_domain,domain)
        run("SecurityTrails passive DNS",src.passive_dns_history,domain)
        run("GDELT public news",src.gdelt_news,domain)
        if misp_url.strip(): run("MISP exact IOC",src.misp_search,misp_url.strip(),domain)
    return {"findings":findings,"failures":failures,"skipped":skipped,"target":raw}
