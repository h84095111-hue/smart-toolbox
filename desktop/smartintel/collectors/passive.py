"""Passive public-source OSINT collectors; no port scanning or exploitation."""
import json, socket, ssl, hashlib, ipaddress
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from ..config import USER_AGENT, REQUEST_TIMEOUT, MAX_PAGE_BYTES
from ..models import Finding
HEADERS={'User-Agent':USER_AGENT,'Accept':'text/html,application/json;q=0.9,*/*;q=0.8'}

def _rdap(url):
    from ..network import requests_proxy_map
    r=requests.get(url,headers=HEADERS,timeout=REQUEST_TIMEOUT,allow_redirects=False,proxies=requests_proxy_map())
    r.raise_for_status(); return r.json(),r.url

def _resolve_public_addresses(host, port):
    """Resolve once and reject the answer set if any address is non-public."""
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = sorted({answer[4][0] for answer in answers})
    if not addresses:
        raise ValueError("Host did not resolve.")
    if any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("Only publicly routable website hosts are supported.")
    return addresses


def collect_domain(domain):
    domain=domain.strip().lower().rstrip('.')
    if not domain or '/' in domain or ' ' in domain: raise ValueError('Enter a domain name only, e.g. example.com')
    out=[]; ips=[]
    try:
        ips=_resolve_public_addresses(domain,443)
        out.append(Finding('DNS address records',', '.join(ips),'System DNS',confidence='High'))
    except Exception as e: out.append(Finding('DNS lookup',str(e),'System DNS',confidence='Low'))
    try:
        d,u=_rdap('https://rdap.org/domain/'+domain)
        summary={'handle':d.get('handle'),'ldhName':d.get('ldhName'),'status':d.get('status',[]),'nameservers':[n.get('ldhName') for n in d.get('nameservers',[])],'events':d.get('events',[])}
        out.append(Finding('RDAP registration data',json.dumps(summary,indent=2),'ICANN RDAP',u,'High'))
    except Exception as e: out.append(Finding('RDAP lookup',str(e),'ICANN RDAP',confidence='Low'))
    try:
        ctx=ssl.create_default_context()
        if not ips: raise ValueError("No validated public DNS address is available for TLS.")
        from ..network import open_pinned_socket
        with open_pinned_socket(ips[0],443,server_hostname=domain,timeout=REQUEST_TIMEOUT,use_tls=True) as ss:
            cert=ss.getpeercert(); info={'subject':cert.get('subject'),'issuer':cert.get('issuer'),'notBefore':cert.get('notBefore'),'notAfter':cert.get('notAfter'),'protocol':ss.version(),'cipher':ss.cipher()}
        out.append(Finding('TLS certificate metadata',json.dumps(info,indent=2),'TLS handshake','https://'+domain,'High'))
    except Exception as e: out.append(Finding('TLS certificate',str(e),'TLS handshake','https://'+domain,'Low'))
    return out

def collect_ip(value):
    obj=ipaddress.ip_address(value.strip())
    if not obj.is_global: raise ValueError('Only globally routable public IP addresses are supported.')
    out=[]
    try:
        d,u=_rdap('https://rdap.org/ip/'+str(obj))
        summary={k:d.get(k) for k in ('name','handle','startAddress','endAddress','ipVersion','country','type','status','entities','events')}
        out.append(Finding('IP RDAP registration',json.dumps(summary,indent=2),'RDAP',u,'High'))
    except Exception as e: out.append(Finding('IP RDAP',str(e),'RDAP',confidence='Low'))
    try:
        name,aliases,addresses=socket.gethostbyaddr(str(obj)); out.append(Finding('Reverse DNS',json.dumps({'hostname':name,'aliases':aliases}),'System DNS',confidence='High'))
    except Exception as e: out.append(Finding('Reverse DNS',str(e),'System DNS',confidence='Low'))
    return out

def _semantic_identifiers(soup):
    """Preserve selected semantic identity hints before HTML is reduced to text."""
    import re
    from urllib.parse import unquote
    found=[]; seen=set()
    def add(kind,value,reason):
        value=str(value or "").strip()
        if not value:return
        if kind=="phone" and len(re.sub(r"\D","",value))<8:return
        key=(kind,value.casefold())
        if key not in seen:
            seen.add(key); found.append({"kind":kind,"value":value[:1000],"reason":reason})
    for tag in soup.find_all(True):
        attrs=tag.attrs
        semantic=" ".join(str(attrs.get(k,"")) for k in ("itemprop","name","property")).casefold()
        value=attrs.get("content") or attrs.get("value")
        tokens=set(re.split(r"[^a-z0-9]+",semantic))
        if value:
            if tokens.intersection({"email","e-mail"}):add("email",value,"Semantic HTML email metadata")
            if tokens.intersection({"telephone","phone","tel"}):add("phone",value,"Semantic HTML phone metadata")
        href=str(attrs.get("href") or "").strip()
        if href.lower().startswith("mailto:"):add("email",unquote(href[7:].split("?")[0]),"mailto link")
        elif href.lower().startswith("tel:"):add("phone",unquote(href[4:].split("?")[0]),"tel link")
        elif href.startswith(("https://","http://")):
            rel=attrs.get("rel") or []
            if isinstance(rel,str):rel=rel.split()
            if "me" in rel:add("profile_or_url",href,"Self-asserted rel=me profile link")
    return found


def _get_public_pinned(url):
    """Fetch one page from a validated public IP, through the selected route."""
    import http.client
    from requests import Response
    from requests.structures import CaseInsensitiveDict
    from ..network import open_pinned_socket

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only absolute HTTP(S) URLs are supported.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addresses = _resolve_public_addresses(parsed.hostname, port)
    except (socket.gaierror, ValueError) as exc:
        raise ValueError(f"Could not resolve a public host: {exc}") from exc
    headers = {**HEADERS, "Host": parsed.hostname, "Connection": "close"}
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    errors = []
    for pinned_ip in addresses:
        connection = None
        try:
            connection = http.client.HTTPConnection(parsed.hostname, port=port, timeout=REQUEST_TIMEOUT)
            connection.sock = open_pinned_socket(
                pinned_ip, port, server_hostname=parsed.hostname,
                timeout=REQUEST_TIMEOUT, use_tls=(parsed.scheme == "https"),
            )
            connection.putrequest("GET", path, skip_accept_encoding=True)
            for key, value in headers.items():
                connection.putheader(key, value)
            connection.endheaders()
            result = connection.getresponse()
            response = Response()
            response.status_code = result.status
            response.reason = result.reason
            response.headers = CaseInsensitiveDict(dict(result.getheaders()))
            response.url = url
            response.encoding = requests.utils.get_encoding_from_headers(response.headers)
            response._content = result.read(MAX_PAGE_BYTES + 1)
            response._content_consumed = True
            response.close = connection.close
            return response
        except Exception as exc:
            errors.append(f"{pinned_ip}: {exc.__class__.__name__}: {str(exc)[:180]}")
            if connection is not None:
                connection.close()
    raise ConnectionError("All validated public IP addresses failed: " + " | ".join(errors))

def collect_website(url):
    url=url.strip()
    if not urlparse(url).scheme: url='https://'+url
    p=urlparse(url)
    if p.scheme not in ('http','https') or not p.hostname: raise ValueError('Enter a valid public http(s) URL.')
    if p.username or p.password: raise ValueError('URLs containing credentials are not accepted.')
    if p.port not in (None, 80, 443): raise ValueError('Only standard HTTP and HTTPS ports are supported.')
    # Pin the validated DNS answer to the actual TCP connection.
    r=_get_public_pinned(url)
    raw=r.content[:MAX_PAGE_BYTES+1]
    if len(raw)>MAX_PAGE_BYTES: raw=raw[:MAX_PAGE_BYTES]
    text=raw.decode(r.encoding or 'utf-8',errors='replace'); soup=BeautifulSoup(text,'html.parser')
    semantic_identifiers=_semantic_identifiers(soup)
    for node in soup(['script','style','noscript']): node.decompose()
    title=soup.title.get_text(' ',strip=True) if soup.title else '(no title)'
    meta=soup.find('meta',attrs={'name':'description'}) or soup.find('meta',attrs={'property':'og:description'})
    description=meta.get('content','') if meta else ''
    links=[]
    for a in soup.find_all('a',href=True)[:60]:
        if a['href'].startswith(('http://','https://')): links.append({'text':a.get_text(' ',strip=True)[:100],'url':a['href']})
    allowed=('server','content-type','content-length','last-modified','etag','strict-transport-security','content-security-policy','x-frame-options','x-content-type-options','referrer-policy')
    headers={k:v for k,v in r.headers.items() if k.lower() in allowed}
    info={'requested_url':url,'status_code':r.status_code,'redirect_location':r.headers.get('Location'),'title':title,'description':description,'headers':headers,'links':links,'semantic_identifiers':semantic_identifiers,'body_excerpt':' '.join(soup.get_text(' ',strip=True).split())[:12000],'sha256_response_excerpt':hashlib.sha256(raw).hexdigest()}
    return [Finding('Public website snapshot',json.dumps(info,indent=2,ensure_ascii=False),'HTTP public page',url,'High')]
