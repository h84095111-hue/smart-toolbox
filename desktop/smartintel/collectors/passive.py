"""Passive public-source OSINT collectors; no port scanning or exploitation."""
import json, socket, ssl, hashlib, ipaddress
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from ..config import USER_AGENT, REQUEST_TIMEOUT, MAX_PAGE_BYTES
from ..models import Finding
HEADERS={'User-Agent':USER_AGENT,'Accept':'text/html,application/json;q=0.9,*/*;q=0.8'}

def _rdap(url):
    r=requests.get(url,headers=HEADERS,timeout=REQUEST_TIMEOUT,allow_redirects=True)
    r.raise_for_status(); return r.json(),r.url

def collect_domain(domain):
    domain=domain.strip().lower().rstrip('.')
    if not domain or '/' in domain or ' ' in domain: raise ValueError('Enter a domain name only, e.g. example.com')
    out=[]
    try:
        ips=sorted({x[4][0] for x in socket.getaddrinfo(domain,None)})
        out.append(Finding('DNS address records',', '.join(ips),'System DNS',confidence='High'))
    except Exception as e: out.append(Finding('DNS lookup',str(e),'System DNS',confidence='Low'))
    try:
        d,u=_rdap('https://rdap.org/domain/'+domain)
        summary={'handle':d.get('handle'),'ldhName':d.get('ldhName'),'status':d.get('status',[]),'nameservers':[n.get('ldhName') for n in d.get('nameservers',[])],'events':d.get('events',[])}
        out.append(Finding('RDAP registration data',json.dumps(summary,indent=2),'ICANN RDAP',u,'High'))
    except Exception as e: out.append(Finding('RDAP lookup',str(e),'ICANN RDAP',confidence='Low'))
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((domain,443),timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock,server_hostname=domain) as ss:
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

def collect_website(url):
    url=url.strip()
    if not urlparse(url).scheme: url='https://'+url
    p=urlparse(url)
    if p.scheme not in ('http','https') or not p.hostname: raise ValueError('Enter a valid public http(s) URL.')
    if p.username or p.password: raise ValueError('URLs containing credentials are not accepted.')
    # Resolve and reject private, loopback, link-local and other non-global destinations.
    try:
        addresses=socket.getaddrinfo(p.hostname,p.port or (443 if p.scheme=='https' else 80))
        if not addresses: raise ValueError('Host did not resolve.')
        for a in addresses:
            if not ipaddress.ip_address(a[4][0]).is_global: raise ValueError('Only publicly routable website hosts are supported.')
    except socket.gaierror as e: raise ValueError(f'Could not resolve public host: {e}')
    # Do not follow redirects: a public host could redirect to a private network address.
    r=requests.get(url,headers=HEADERS,timeout=REQUEST_TIMEOUT,allow_redirects=False,stream=True)
    raw=next(r.iter_content(MAX_PAGE_BYTES+1),b'')
    if len(raw)>MAX_PAGE_BYTES: raw=raw[:MAX_PAGE_BYTES]
    text=raw.decode(r.encoding or 'utf-8',errors='replace'); soup=BeautifulSoup(text,'html.parser')
    for node in soup(['script','style','noscript']): node.decompose()
    title=soup.title.get_text(' ',strip=True) if soup.title else '(no title)'
    meta=soup.find('meta',attrs={'name':'description'}) or soup.find('meta',attrs={'property':'og:description'})
    description=meta.get('content','') if meta else ''
    links=[]
    for a in soup.find_all('a',href=True)[:60]:
        if a['href'].startswith(('http://','https://')): links.append({'text':a.get_text(' ',strip=True)[:100],'url':a['href']})
    allowed=('server','content-type','content-length','last-modified','etag','strict-transport-security','content-security-policy','x-frame-options','x-content-type-options','referrer-policy')
    headers={k:v for k,v in r.headers.items() if k.lower() in allowed}
    info={'requested_url':url,'status_code':r.status_code,'redirect_location':r.headers.get('Location'),'title':title,'description':description,'headers':headers,'links':links,'body_excerpt':' '.join(soup.get_text(' ',strip=True).split())[:12000],'sha256_response_excerpt':hashlib.sha256(raw).hexdigest()}
    return [Finding('Public website snapshot',json.dumps(info,indent=2,ensure_ascii=False),'HTTP public page',url,'High')]
