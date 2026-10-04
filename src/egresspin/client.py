"""Validated IP connects; original HTTP/TLS identity; no implicit redirect client."""
import hashlib,http.client,io,ipaddress,re,socket,ssl,time
from urllib.parse import urljoin
from .model import Hop,PinError,Result,address

def system_resolver(host,port):
    return [item[4][0] for item in socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)]

class _DeadlineRaw(io.RawIOBase):
    def __init__(self,sock,deadline):self.sock=sock;self.deadline=deadline
    def readable(self):return True
    def readinto(self,buffer):
        remaining=self.deadline-time.monotonic()
        if remaining<=0:raise TimeoutError()
        self.sock.settimeout(remaining)
        return self.sock.recv_into(buffer)

class _Wire:
    def __init__(self,sock,deadline):self.sock=sock;self.deadline=deadline
    def makefile(self,mode):return io.BufferedReader(_DeadlineRaw(self.sock,self.deadline))

def _headers(values):
    if values is None:return {}
    if not isinstance(values,dict) or len(values)>32:raise PinError('invalid_headers')
    output={}
    reserved={'host','connection','content-length','transfer-encoding','accept-encoding','proxy-authorization','upgrade','trailer','te'}
    for name,value in values.items():
        if not isinstance(name,str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",name):raise PinError('invalid_headers')
        lower=name.lower()
        if lower in reserved or lower in output or not isinstance(value,str) or any(ord(c)<32 or ord(c)>126 for c in value):raise PinError('invalid_headers')
        output[lower]=value
    if sum(len(k)+len(v)+4 for k,v in output.items())>8192:raise PinError('headers_quota')
    return output

def _length(value,limit):
    if not value or re.fullmatch('[0-9]+',value) is None:raise PinError('invalid_response_length')
    clean=value.lstrip('0') or '0';bound=str(limit)
    if len(clean)>len(bound) or len(clean)==len(bound) and clean>bound:raise PinError('body_quota')
    return int(clean)

class Fetcher:
    def __init__(self,policy,*,resolver=system_resolver,cafile=None):
        self.policy=policy;self.resolver=resolver
        self.tls=ssl.create_default_context(cafile=cafile)
        self.tls.minimum_version=ssl.TLSVersion.TLSv1_2
    def fetch(self,url,*,headers=None):
        request_headers=_headers(headers);deadline=time.monotonic()+self.policy.timeout_ms/1000
        audit=[];visited=set();redirects=0
        while True:
            target=self.policy.target(url)
            if target.url in visited:raise PinError('redirect_loop',audit)
            visited.add(target.url);start=time.monotonic_ns();answers=[];attempts=[];peer=None;status=None;count=0;sock=None;response=None
            try:
                try:literal=address(target.host);raw=[str(literal)]
                except PinError:
                    raw=[]
                    for value in self.resolver(target.host,target.port):
                        raw.append(value)
                        if len(raw)>self.policy.max_addresses:raise PinError('dns_answers_quota')
                if not raw or len(raw)>self.policy.max_addresses:raise PinError('dns_answers_quota')
                answers=list(dict.fromkeys(str(address(value)) for value in raw))
                if not all(self.policy.permits(ip) for ip in answers):raise PinError('address_denied')
                last_failure='connect_failed'
                for ip in answers[:self.policy.max_attempts]:
                    remaining=deadline-time.monotonic()
                    if remaining<=0:raise PinError('timeout')
                    candidate=socket.socket(socket.AF_INET6 if ':' in ip else socket.AF_INET,socket.SOCK_STREAM)
                    candidate.settimeout(remaining)
                    try:
                        candidate.connect((ip,target.port))
                        actual=str(address(candidate.getpeername()[0]))
                        if actual!=ip:raise PinError('peer_mismatch')
                        peer=actual
                        if target.scheme=='https':
                            remaining=deadline-time.monotonic()
                            if remaining<=0:raise PinError('timeout')
                            candidate.settimeout(remaining)
                            candidate=self.tls.wrap_socket(candidate,server_hostname=target.host)
                        sock=candidate;peer=actual;attempts.append((ip,'connected'));break
                    except ssl.SSLCertVerificationError:
                        last_failure='tls_verification_failed';attempts.append((ip,last_failure));candidate.close()
                    except (OSError,ssl.SSLError):
                        last_failure='connect_failed';attempts.append((ip,last_failure));candidate.close()
                    except PinError:
                        candidate.close();raise
                if sock is None:raise PinError(last_failure)
                remaining=deadline-time.monotonic()
                if remaining<=0:raise PinError('timeout')
                sock.settimeout(remaining)
                request='GET '+target.path+' HTTP/1.1\r\nHost: '+target.authority+'\r\nConnection: close\r\nAccept-Encoding: identity\r\n'
                request+=''.join(k+': '+v+'\r\n' for k,v in request_headers.items())+'\r\n'
                sock.sendall(request.encode('ascii'))
                response=http.client.HTTPResponse(_Wire(sock,deadline));response.begin();status=response.status
                if not 200<=status<=599:raise PinError('unsupported_response_status')
                response_headers=response.getheaders()
                if sum(len(k)+len(v)+4 for k,v in response_headers)>self.policy.max_headers:raise PinError('response_headers_quota')
                lengths=response.headers.get_all('Content-Length') or []
                transfer=response.headers.get_all('Transfer-Encoding') or []
                if transfer and (len(transfer)!=1 or transfer[0].lower()!='chunked' or lengths):raise PinError('unsupported_transfer')
                if len(lengths)>1:raise PinError('ambiguous_response_length')
                expected=_length(lengths[0],self.policy.max_body) if lengths else None
                chunks=[]
                while True:
                    chunk=response.read1(min(65536,self.policy.max_body-count+1))
                    if not chunk:break
                    count+=len(chunk)
                    if count>self.policy.max_body:raise PinError('body_quota')
                    chunks.append(chunk)
                if expected is not None and count!=expected:raise PinError('incomplete_response')
                body=b''.join(chunks)
                audit.append(Hop(target.origin,hashlib.sha256(target.url.encode()).hexdigest(),tuple(answers),tuple(attempts),peer,status,count,time.monotonic_ns()-start,'received'))
                if status in {301,302,303,307,308}:
                    locations=response.headers.get_all('Location') or []
                    if len(locations)!=1:raise PinError('invalid_redirect',audit)
                    if not locations[0] or len(locations[0])>self.policy.max_url or any(ord(c)<33 or ord(c)>126 for c in locations[0]):raise PinError('invalid_redirect',audit)
                    if redirects>=self.policy.max_redirects:raise PinError('redirect_quota',audit)
                    following=self.policy.target(urljoin(target.url,locations[0]))
                    if following.origin!=target.origin:request_headers={k:v for k,v in request_headers.items() if k in {'accept','accept-language','user-agent'}}
                    url=following.url;redirects+=1;continue
                return Result(status,body,response.getheader('Content-Type',''),target.url,tuple(audit))
            except PinError as error:
                if not error.audit:
                    if not audit or audit[-1].url_sha256!=hashlib.sha256(target.url.encode()).hexdigest():
                        audit.append(Hop(target.origin,hashlib.sha256(target.url.encode()).hexdigest(),tuple(answers),tuple(attempts),peer,status,count,time.monotonic_ns()-start,error.code))
                    error.audit=tuple(audit)
                raise
            except (OSError,ssl.SSLError,http.client.HTTPException,ValueError) as error:
                code='timeout' if isinstance(error,(TimeoutError,socket.timeout)) else 'transport_error'
                audit.append(Hop(target.origin,hashlib.sha256(target.url.encode()).hexdigest(),tuple(answers),tuple(attempts),peer,status,count,time.monotonic_ns()-start,code))
                raise PinError(code,audit) from None
            finally:
                if response:response.close()
                if sock:sock.close()
