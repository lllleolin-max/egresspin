"""Actual same-policy curl/SDK, native received-request counters and full bodies."""
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit,urljoin
from unittest.mock import patch
import argparse,hashlib,ipaddress,json,socket,ssl,subprocess,time
from egresspin import Fetcher,PinError,Policy

p=argparse.ArgumentParser();p.add_argument('--output',required=True);a=p.parse_args();out=Path(a.output).resolve();out.mkdir()
fixture=Path(__file__).resolve().parents[1]/'tests/fixtures';cert=fixture/'public-lab-cert.pem';key=fixture/'public-lab-key.pem'
raw=json.dumps({'orders':[{'id':str(i),'amount_cents':97*i+23} for i in range(1000)]},separators=(',',':')).encode()
small=b'normal small laboratory response';events=[];sni=[];tls_peers=[];begun=time.perf_counter_ns()
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        events.append(dict(role=self.server.role,path=self.path,host=self.headers['Host'],authorization=self.headers.get('Authorization'),x_api_key=self.headers.get('X-Api-Key'),cookie=self.headers.get('Cookie')))
        if self.path in {'/relative','/cross','/denied'}:
            location='/orders' if self.path=='/relative' else (f'http://other.test:{secondary.server_port}/orders' if self.path=='/cross' else f'http://forbidden.test:{forbidden.server_port}/orders')
            self.send_response(302);self.send_header('Location',location);body=b''
        else:
            self.send_response(200);body=b'FORBIDDEN_RECEIVER_PUBLIC_LAB' if self.server.role=='forbidden' else (small if self.path=='/small' else raw)
        self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers()
        try:self.wfile.write(body)
        except (BrokenPipeError,ConnectionResetError):pass
    def log_message(self,*args):pass
def listener(ip,role,port=0,tls=False):
    s=ThreadingHTTPServer((ip,port),Handler);s.role=role;s.daemon_threads=True
    if tls:
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key)
        def observe(sock,host,ctx):
            sni.append(host);tls_peers.append(dict(sni=host,listener_address=sock.getsockname()[0],peer_address=sock.getpeername()[0]))
        ctx.set_servername_callback(observe);s.socket=ctx.wrap_socket(s.socket,server_side=True)
    t=Thread(target=s.serve_forever,daemon=True);t.start();return s,t
primary,pt=listener('127.0.0.1','primary');forbidden,ft=listener('127.0.0.2','forbidden',primary.server_port)
secondary,st=listener('127.0.0.1','secondary');secure,tt=listener('127.0.0.1','tls',tls=True)
setup_ns=time.perf_counter_ns()-begun
origins={('http','pin.test',primary.server_port),('http','other.test',secondary.server_port),('https','pin.test',secure.server_port),('https','wrong.test',secure.server_port)}
origin_strings=tuple(f'{s}://{h}:{port}' for s,h,port in origins)
caller={'Authorization':'PUBLIC_LAB_ONLY','X-Api-Key':'PUBLIC_LAB_KEY','Cookie':'PUBLIC_LAB_COOKIE','User-Agent':'PUBLIC_LAB_AGENT','Accept':'application/json'}

def origin(url):
    q=urlsplit(url);return (q.scheme,q.hostname,q.port or (443 if q.scheme=='https' else 80))
class Resolver:
    def __init__(self,case):self.case=case;self.calls=[]
    def __call__(self,host,port):
        self.calls.append((host,port))
        if self.case=='mixed':return ['127.0.0.1','::1']
        return ['127.0.0.2'] if self.case=='rebind' and len(self.calls)>1 else ['127.0.0.1']

def mature(url,resolver,directory):
    headers=caller.copy();hops=[];code=None;body=None
    for n in range(5):
        o=origin(url)
        if o not in origins:return dict(code='origin_denied',body=None,hops=hops)
        answers=resolver(o[1],o[2])
        # Independent baseline policy, not a call to product Policy.permits.
        if any(str(ipaddress.ip_address(ip))!='127.0.0.1' for ip in answers):return dict(code='address_denied',body=None,hops=hops)
        header_file=directory/f'hop{n}.headers';body_file=directory/f'hop{n}.body'
        cmd=['curl.exe' if socket.gethostname() and __import__('os').name=='nt' else 'curl','--disable','--silent','--show-error','--noproxy','*','--max-time','5','--resolve',f'{o[1]}:{o[2]}:{answers[0]}','--cacert',str(cert),'--dump-header',str(header_file),'--output',str(body_file),'--write-out','%{json}']
        if __import__('os').name=='nt':cmd+=['--ssl-no-revoke'] # Python default also does not perform CRL/OCSP checks.
        for k,v in headers.items():cmd+=['--header',k+': '+v]
        cmd+=[url];start=time.perf_counter_ns();r=subprocess.run(cmd,capture_output=True,timeout=8);elapsed=time.perf_counter_ns()-start
        (directory/f'hop{n}.stdout').write_bytes(r.stdout);(directory/f'hop{n}.stderr').write_bytes(r.stderr)
        stats=json.loads(r.stdout) if r.stdout else {};hops.append(dict(argv=cmd,exit=r.returncode,elapsed_ns=elapsed,stats=stats))
        if r.returncode:return dict(code='tls_verification_failed' if r.returncode==60 else 'transport_error',body=None,hops=hops)
        data=body_file.read_bytes();status=int(stats['http_code'])
        # Curl's own parser/framing/TLS is the mature implementation; native
        # dump headers supply Location only, with automatic -L disabled.
        fields={}
        for line in header_file.read_bytes().split(b'\r\n'):
            if b':' in line:
                name,value=line.split(b':',1);fields[name.decode('ascii').lower()]=value.strip().decode('ascii')
        if status in {301,302,303,307,308}:
            following=urljoin(url,fields['location'])
            if origin(following)!=o:headers={k:v for k,v in headers.items() if k.lower() in {'accept','accept-language','user-agent'}}
            url=following;continue
        return dict(code=None,body=data,hops=hops)
    return dict(code='redirect_quota',body=None,hops=hops)

cases=[('small',f'http://pin.test:{primary.server_port}/small',small,None),('orders',f'http://pin.test:{primary.server_port}/orders',raw,None),
       ('rebind',f'http://pin.test:{primary.server_port}/orders',raw,None),('mixed',f'http://pin.test:{primary.server_port}/orders',None,'address_denied'),
       ('relative',f'http://pin.test:{primary.server_port}/relative',raw,None),('cross',f'http://pin.test:{primary.server_port}/cross',raw,None),
       ('denied',f'http://pin.test:{primary.server_port}/denied',None,'origin_denied'),('tls',f'https://pin.test:{secure.server_port}/orders',raw,None),
       ('tls-relative',f'https://pin.test:{secure.server_port}/relative',raw,None),('wrong-hostname',f'https://wrong.test:{secure.server_port}/orders',None,'tls_verification_failed')]
reports=[]
try:
    for case,url,expected,expected_code in cases:
        for repetition in range(3):
            for mode in ['sdk','curl']:
                directory=out/f'{case}-{repetition}-{mode}';directory.mkdir();resolver=Resolver(case);before=len(events);before_sni=len(sni);before_tls=len(tls_peers);start=time.perf_counter_ns()
                if mode=='sdk':
                    prepare=time.perf_counter_ns();fetcher=Fetcher(Policy(origin_strings,testing_ips=('127.0.0.1',)),resolver=resolver,cafile=str(cert));prepare_ns=time.perf_counter_ns()-prepare
                    try:r=fetcher.fetch(url,headers=caller);result=dict(code=None,body=r.body,hops=[asdict(h) for h in r.audit])
                    except PinError as e:result=dict(code=e.code,body=None,hops=[asdict(h) for h in e.audit])
                else:prepare_ns=0;result=mature(url,resolver,directory)
                elapsed=time.perf_counter_ns()-start;actual=events[before:];body=result.pop('body')
                if body is not None:(directory/'complete-body.bin').write_bytes(body)
                okay=result['code']==expected_code and body==expected and not any(e['role']=='forbidden' for e in actual)
                if expected==raw and body is not None:
                    values=json.loads(body);okay=okay and len(values['orders'])==1000 and sum(o['amount_cents'] for o in values['orders'])==48474500
                if case=='cross':okay=okay and len(actual)==2 and actual[-1]['authorization'] is None and actual[-1]['cookie'] is None and actual[-1]['x_api_key'] is None
                report=dict(case=case,mode=mode,repetition=repetition,result='PASS' if okay else 'FAIL',fixture_setup_ns=setup_ns,client_prepare_ns=prepare_ns,total_client_ns=elapsed,
                            dns_calls=resolver.calls,actual_http_requests=actual,actual_sni=sni[before_sni:],native_tls_peers=tls_peers[before_tls:],body_bytes=None if body is None else len(body),body_sha256=None if body is None else hashlib.sha256(body).hexdigest(),**result)
                (directory/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');reports.append(report)
    # A weaker URL-only pattern is explicitly separate from mature equivalent
    # curl. Its actual ordinary connector performs a second changed DNS lookup.
    import http.client
    weak=Resolver('rebind');url=f'http://pin.test:{primary.server_port}/orders';assert origin(url) in origins;assert weak('pin.test',primary.server_port)==['127.0.0.1']
    before=len(events);original_getaddrinfo=socket.getaddrinfo
    def changed_dns(host,port,*args,**kw):
        return original_getaddrinfo(weak(host,port)[0],port,*args,**kw) if host=='pin.test' else original_getaddrinfo(host,port,*args,**kw)
    with patch('socket.getaddrinfo',side_effect=changed_dns):
        c=http.client.HTTPConnection('pin.test',primary.server_port,timeout=5);c.request('GET','/orders');response=c.getresponse();weak_body=response.read();c.close()
    weak_record=dict(control='explicitly weaker URL-only check+ordinary unpinned connection',dns_calls=weak.calls,actual_http_requests=events[before:],complete_body_sha256=hashlib.sha256(weak_body).hexdigest(),forbidden_request_count=sum(e['role']=='forbidden' for e in events[before:]))
    assert weak_record['forbidden_request_count']==1;(out/'weak-complete-body.bin').write_bytes(weak_body);(out/'weak-control.json').write_text(json.dumps(weak_record,indent=2)+'\n')
    summary=dict(result='PASS' if all(r['result']=='PASS' for r in reports) else 'FAIL',cases=len(reports),repetitions=3,shapes=10,setup_ns=setup_ns,
                 sdk_curl_equivalent_answers=all(r['result']=='PASS' for r in reports),weak_control_forbidden_requests=1,
                 scope='Same origins/address schedule/whole bodies/redirect header policy; curl RESOLVE + explicit every-hop validator, no automatic-L or environment proxy. Curl actual process/TLS/setup costs retained; no promised performance win. LAB credentials/cert/key are public test-only.')
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');(out/'all-results.json').write_text(json.dumps(reports,indent=2)+'\n');print(json.dumps(summary))
finally:
    for server,thread in [(primary,pt),(forbidden,ft),(secondary,st),(secure,tt)]:server.shutdown();server.server_close();thread.join()
raise SystemExit(0 if summary['result']=='PASS' else 1)
