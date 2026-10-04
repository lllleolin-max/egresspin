import contextlib,json,ssl,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
CERT=Path(__file__).parent/'fixtures/public-lab-cert.pem'
KEY=Path(__file__).parent/'fixtures/public-lab-key.pem'
BODY=json.dumps({'orders':[{'id':i,'amount_cents':i*117+3} for i in range(100)]},separators=(',',':')).encode()
class Listener:
    def __init__(self,tls=False):
        self.requests=[];self.sni=[];self.body=BODY;self.redirect=None
        owner=self
        class Handler(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def do_GET(self):
                owner.requests.append({'path':self.path,'headers':dict(self.headers)})
                if self.path=='/redirect':
                    self.send_response(302);self.send_header('Location',owner.redirect or '/data');raw=b''
                elif self.path=='/empty':self.send_response(200);raw=b''
                elif self.path=='/missing':self.send_response(404);raw=b'missing'
                else:self.send_response(200);raw=owner.body
                self.send_header('Content-Length',str(len(raw)));self.send_header('Content-Type','application/json');self.end_headers()
                try:self.wfile.write(raw)
                except (BrokenPipeError,ConnectionResetError):pass
            def log_message(self,*args):pass
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler);self.server.daemon_threads=True
        self.port=self.server.server_port
        if tls:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(CERT,KEY)
            context.set_servername_callback(lambda sock,name,ctx:self.sni.append(name))
            self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def close(self):self.server.shutdown();self.server.server_close();self.thread.join()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()
