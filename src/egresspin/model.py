"""Finite, explicit URL/address policies. No ambient proxy or IDNA guessing."""
from dataclasses import dataclass,field
import ipaddress,re
from urllib.parse import urlsplit,urlunsplit

class PinError(Exception):
    def __init__(self,code,audit=()):
        super().__init__(code);self.code=code;self.audit=tuple(audit)

def integer(value,minimum,maximum):
    if type(value) is not int or not minimum<=value<=maximum:raise PinError('invalid_integer')
    return value

def address(text):
    if not isinstance(text,str) or '%' in text:raise PinError('invalid_address')
    try:ip=ipaddress.ip_address(text)
    except ValueError:raise PinError('invalid_address') from None
    return ip.ipv4_mapped if isinstance(ip,ipaddress.IPv6Address) and ip.ipv4_mapped else ip

@dataclass(frozen=True)
class Target:
    url:str
    scheme:str
    host:str
    port:int
    path:str
    @property
    def origin(self):return (self.scheme,self.host,self.port)
    @property
    def authority(self):
        host='['+self.host+']' if ':' in self.host else self.host
        return host if self.port==({'http':80,'https':443}[self.scheme]) else host+':'+str(self.port)

def normalize(url,max_url=8192):
    if not isinstance(url,str) or not 1<=len(url)<=max_url or any(ord(c)<33 or ord(c)>126 for c in url) or '\\' in url:
        raise PinError('invalid_url')
    if re.search(r'%(?![0-9A-Fa-f]{2})',url):raise PinError('invalid_url')
    try:
        parts=urlsplit(url)
        if parts.scheme not in {'http','https'} or not parts.netloc or parts.username is not None or parts.password is not None or parts.fragment:
            raise PinError('unsupported_url')
        host=parts.hostname;port=parts.port or (443 if parts.scheme=='https' else 80)
    except ValueError:raise PinError('invalid_url') from None
    if not host or '%' in host or not 1<=port<=65535:raise PinError('invalid_host')
    host=host.lower()
    try:host=str(address(host))
    except PinError:
        if len(host)>253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in host.split('.')) or host.startswith('xn--') or any(label.startswith('xn--') for label in host.split('.')):
            raise PinError('unsupported_host') from None
        # Reject numeric spellings which OS resolvers can interpret as alternate IP syntax.
        if re.fullmatch(r'[0-9.]+',host) or host.startswith('0x'):raise PinError('unsupported_host')
    path=parts.path or '/'
    request_path=path+('?' + parts.query if parts.query else '')
    temp=Target('',parts.scheme,host,port,request_path)
    normalized=urlunsplit((parts.scheme,temp.authority,path,parts.query,''))
    return Target(normalized,parts.scheme,host,port,request_path)

@dataclass(frozen=True)
class Policy:
    allowed_origins:tuple
    testing_ips:tuple=()
    max_body:int=1048576
    max_headers:int=32768
    max_url:int=8192
    max_addresses:int=16
    max_attempts:int=4
    max_redirects:int=4
    timeout_ms:int=5000
    def __post_init__(self):
        if not isinstance(self.allowed_origins,(tuple,list)) or not 1<=len(self.allowed_origins)<=64:raise PinError('invalid_origins')
        origins=[]
        for value in self.allowed_origins:
            target=normalize(value)
            if target.path!='/':raise PinError('origin_only')
            origins.append(target.origin)
        object.__setattr__(self,'allowed_origins',tuple(sorted(set(origins))))
        if not isinstance(self.testing_ips,(tuple,list)) or len(self.testing_ips)>16:raise PinError('invalid_testing_ips')
        object.__setattr__(self,'testing_ips',tuple(str(address(ip)) for ip in self.testing_ips))
        for name,low,high in [('max_body',0,16777216),('max_headers',1,65536),('max_url',1,8192),('max_addresses',1,64),('max_attempts',1,16),('max_redirects',0,16),('timeout_ms',1,60000)]:
            integer(getattr(self,name),low,high)
    def target(self,url):
        target=normalize(url,self.max_url)
        if target.origin not in self.allowed_origins:raise PinError('origin_denied')
        return target
    def permits(self,ip):
        value=address(ip)
        return str(value) in self.testing_ips or (value.is_global and not value.is_multicast and not value.is_unspecified)

@dataclass(frozen=True)
class Hop:
    origin:tuple
    url_sha256:str
    answers:tuple
    attempts:tuple
    peer:str|None
    status:int|None
    received_bytes:int
    elapsed_ns:int
    outcome:str

@dataclass(frozen=True)
class Result:
    status:int
    body:bytes
    content_type:str
    final_url:str
    audit:tuple[Hop,...]
