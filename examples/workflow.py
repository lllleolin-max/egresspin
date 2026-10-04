"""Actual trusted URL-import application; native SQL and complete JSON consumer."""
from contextlib import closing
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from threading import Thread
import hashlib,json,sqlite3,tempfile
from egresspin import Fetcher,ImportStore,Policy

def main():
    expected={'orders':[{'id':str(i),'amount_cents':i*97+23} for i in range(1000)]}
    raw=json.dumps(expected,separators=(',',':')).encode();seen=[]
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(dict(path=self.path,host=self.headers['Host']))
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True;thread=Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            port=server.server_port;url=f'http://127.0.0.1:{port}/orders';policy=Policy((f'http://127.0.0.1:{port}',),testing_ips=('127.0.0.1',))
            store=ImportStore(str(Path(tmp)/'imports.sqlite'));first=store.import_url('daily-orders',url,Fetcher(policy));second=store.import_url('daily-orders',url,Fetcher(policy))
            body=store.export('daily-orders');assert body==raw and len(seen)==1 and not second['stored']
            parsed=json.loads(body);assert parsed==expected;total=sum(o['amount_cents'] for o in parsed['orders'])
            with closing(sqlite3.connect(store.path)) as db:rows=db.execute('SELECT body,sha256,audit FROM imports').fetchall()
            assert len(rows)==1 and bytes(rows[0][0])==raw and rows[0][1]==hashlib.sha256(raw).hexdigest()
            audit=json.loads(rows[0][2]);assert audit[0]['peer']=='127.0.0.1' and len(audit)==1
            print(json.dumps(dict(result='PASS',rows=1000,total_cents=total,bytes=len(body),sha256=first['sha256'],listener_requests=len(seen),native_sql_rows=len(rows),scope='Explicit loopback laboratory policy, actual complete order import; no customer/revenue evidence')))
    finally:server.shutdown();server.server_close();thread.join()

if __name__=='__main__':main()
