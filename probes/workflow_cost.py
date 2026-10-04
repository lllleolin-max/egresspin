"""Same whole HTTP-to-SQLite snapshot workflow using SDK or correct curl pinning."""
from contextlib import closing
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from threading import Thread
import argparse,hashlib,json,os,sqlite3,subprocess,time
from egresspin import Fetcher,ImportStore,Policy

p=argparse.ArgumentParser();p.add_argument('--output',required=True);a=p.parse_args();out=Path(a.output).resolve();out.mkdir()
raw=json.dumps({'orders':[{'id':str(i),'amount_cents':97*i+23} for i in range(1000)]},separators=(',',':')).encode();received=[];reports=[];started=time.perf_counter_ns()
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        received.append(dict(path=self.path,host=self.headers.get('Host')));self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    def log_message(self,*args):pass
s=ThreadingHTTPServer(('127.0.0.1',0),Handler);t=Thread(target=s.serve_forever,daemon=True);t.start();setup=time.perf_counter_ns()-started;origin=f'http://pin.test:{s.server_port}';url=origin+'/orders'
schema='CREATE TABLE imports(key TEXT PRIMARY KEY,url TEXT NOT NULL,request_sha256 TEXT NOT NULL,status INTEGER NOT NULL,content_type TEXT NOT NULL,body BLOB NOT NULL,sha256 TEXT NOT NULL,audit TEXT NOT NULL)'
try:
    for repetition in range(3):
        for mode in ['sdk','curl-native-sink']:
            directory=out/f'{mode}-{repetition}';directory.mkdir();database=directory/'imports.sqlite';before=len(received);begin=time.perf_counter_ns();dns=[]
            def resolver(host,port):dns.append((host,port));return ['127.0.0.1']
            if mode=='sdk':
                store=ImportStore(str(database));fetcher=Fetcher(Policy((origin,),testing_ips=('127.0.0.1',)),resolver=resolver)
                prepared=time.perf_counter_ns();prepare_ns=prepared-begin;prepare_disk_bytes=database.stat().st_size
                first=store.import_url('orders',url,fetcher);again=store.import_url('orders',url,fetcher);whole=store.export('orders');assert first['stored'] and not again['stored']
                network_and_commit_ns=time.perf_counter_ns()-prepared;method='Public SDK then unchanged saved-key reuse and full export'
            else:
                with closing(sqlite3.connect(database)) as db:db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA synchronous=EXTRA');db.execute(schema);db.commit()
                prepared=time.perf_counter_ns();prepare_ns=prepared-begin;prepare_disk_bytes=database.stat().st_size
                # Same one-hop fixture policy independently enforced, and curl
                # receives only the validated numeric address. No product checker.
                assert url==f'http://pin.test:{s.server_port}/orders';answers=resolver('pin.test',s.server_port);assert answers==['127.0.0.1']
                cmd=['curl.exe' if os.name=='nt' else 'curl','--disable','--silent','--show-error','--noproxy','*','--max-time','5','--resolve',f'pin.test:{s.server_port}:{answers[0]}','--output',str(directory/'received-body.bin'),'--write-out','%{json}',url]
                r=subprocess.run(cmd,capture_output=True,timeout=8);(directory/'curl.stdout').write_bytes(r.stdout);(directory/'curl.stderr').write_bytes(r.stderr);assert r.returncode==0
                stats=json.loads(r.stdout);assert stats['remote_ip']=='127.0.0.1' and stats['http_code']==200 and stats['proxy_used']==0;whole=(directory/'received-body.bin').read_bytes()
                witness=json.dumps({'origin':origin,'validated_answers':answers,'curl':stats,'argv':cmd},sort_keys=True);request=hashlib.sha256(json.dumps([url,{}],sort_keys=True,separators=(',',':')).encode()).hexdigest()
                with closing(sqlite3.connect(database)) as db:db.execute('BEGIN IMMEDIATE');db.execute('INSERT INTO imports VALUES(?,?,?,?,?,?,?,?)',('orders',url,request,200,'application/json',whole,hashlib.sha256(whole).hexdigest(),witness));db.commit()
                # Correct baseline saved-key branch reuses its SQL row too.
                with closing(sqlite3.connect(database)) as db:whole=bytes(db.execute('SELECT body FROM imports WHERE key=?',('orders',)).fetchone()[0])
                network_and_commit_ns=time.perf_counter_ns()-prepared;method='Correct curl RESOLVE + independent same-fixture policy + transactional native SQLite snapshot reuse; no automatic redirect or ambient proxy'
            elapsed=time.perf_counter_ns()-begin
            with closing(sqlite3.connect(database)) as db:
                rows=db.execute('SELECT key,body,sha256,audit FROM imports').fetchall();pages=db.execute('PRAGMA page_count').fetchone()[0];page_size=db.execute('PRAGMA page_size').fetchone()[0]
            assert len(rows)==1 and bytes(rows[0][1])==raw==whole and rows[0][2]==hashlib.sha256(whole).hexdigest();orders=json.loads(whole)['orders'];assert len(orders)==1000 and [v['id'] for v in orders]==[str(i) for i in range(1000)] and sum(v['amount_cents'] for v in orders)==48474500
            (directory/'complete-export.bin').write_bytes(whole);assert len(received)-before==1 and len(dns)==1
            report=dict(result='PASS',mode=mode,repetition=repetition,method=method,fixture_setup_ns=setup,prepare_ns=prepare_ns,prepare_disk_bytes=prepare_disk_bytes,network_commit_and_saved_reuse_ns=network_and_commit_ns,total_ns=elapsed,disk_bytes=database.stat().st_size,native_pages=pages,native_page_size=page_size,metadata_audit_bytes=len(rows[0][3].encode()),actual_requests=received[before:],dns_calls=dns,whole_bytes=len(whole),whole_sha256=rows[0][2],native_rows=1,fully_consumed_order_count=1000,amount_cents=48474500)
            reports.append(report);(directory/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    summary=dict(result='PASS',cases=reports,scope='Same whole real HTTP->transactional SQLite->saved snapshot reuse->native full JSON action. Single-hop correct curl policy fixture; network multi-hop/TLS pilot separately tests both. Actual curl process overhead differs from in-process SDK, not an algorithmic speedup claim. Raw metadata costs retained; no customer revenue or global novelty inference.')
    (out/'result.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8');print(json.dumps(summary))
finally:s.shutdown();s.server_close();t.join()
