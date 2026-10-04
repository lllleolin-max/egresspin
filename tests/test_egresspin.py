import contextlib,hashlib,json,os,sqlite3,subprocess,sys,tempfile,unittest
from pathlib import Path
from egresspin import Fetcher,ImportStore,PinError,Policy,normalize
from support import BODY,CERT,Listener

class Tests(unittest.TestCase):
    def policy(self,port,**kw):return Policy((f'http://pin.test:{port}',),testing_ips=('127.0.0.1',),**kw)
    def fetcher(self,port,**kw):return Fetcher(self.policy(port,**kw),resolver=lambda h,p:['127.0.0.1'])
    def test_normalize(self):
        self.assertEqual(normalize('HTTP://EXAMPLE.COM:80/a?x=1').url,'http://example.com/a?x=1')
        for url in ['file:///etc/a','http://user:pw@host/a','http://127.1/a','http://2130706433/','http://h/%GG','http://h/a#x','http://xn--abc/a','http://h\\a','http://[fe80::1%25lo]/','http://h/a\r\n','http://h:0/','https://h:0/']:
            with self.subTest(url=url),self.assertRaises(PinError):normalize(url)
    def test_policy_defaults(self):
        policy=Policy(('https://example.com',))
        for ip in ['127.0.0.1','10.0.0.1','169.254.169.254','::1','::ffff:127.0.0.1','224.0.0.1','0.0.0.0']:self.assertFalse(policy.permits(ip))
        self.assertTrue(policy.permits('8.8.8.8'))
    def test_actual_get(self):
        with Listener() as s:
            result=self.fetcher(s.port).fetch(f'http://pin.test:{s.port}/data')
            self.assertEqual(result.body,BODY);self.assertEqual(result.audit[0].peer,'127.0.0.1')
            self.assertEqual(s.requests[0]['headers']['Host'],f'pin.test:{s.port}')
    def test_dns_no_second_lookup(self):
        with Listener() as s:
            calls=[]
            def changing(h,p):calls.append(h);return ['127.0.0.1'] if len(calls)==1 else ['127.0.0.2']
            result=Fetcher(self.policy(s.port),resolver=changing).fetch(f'http://pin.test:{s.port}/data')
            self.assertEqual(result.body,BODY);self.assertEqual(len(calls),1);self.assertEqual(len(s.requests),1)
    def test_all_answers_must_pass(self):
        with Listener() as s:
            f=Fetcher(self.policy(s.port),resolver=lambda h,p:['127.0.0.1','127.0.0.2'])
            with self.assertRaisesRegex(PinError,'address_denied'):f.fetch(f'http://pin.test:{s.port}/data')
            self.assertEqual(s.requests,[])
    def test_mapped_address(self):
        with Listener() as s:
            f=Fetcher(self.policy(s.port),resolver=lambda h,p:['::ffff:127.0.0.1'])
            self.assertEqual(f.fetch(f'http://pin.test:{s.port}/data').audit[0].peer,'127.0.0.1')
    def test_connect_fallback(self):
        with Listener() as s:
            f=Fetcher(Policy((f'http://pin.test:{s.port}',),testing_ips=('127.0.0.1','127.0.0.2')),resolver=lambda h,p:['127.0.0.2','127.0.0.1'])
            r=f.fetch(f'http://pin.test:{s.port}/data');self.assertEqual(len(r.audit[0].attempts),2);self.assertEqual(r.body,BODY)
    def test_tls_hostname_and_sni(self):
        with Listener(tls=True) as s:
            p=Policy((f'https://pin.test:{s.port}',f'https://wrong.test:{s.port}'),testing_ips=('127.0.0.1',))
            f=Fetcher(p,resolver=lambda h,p:['127.0.0.1'],cafile=str(CERT))
            r=f.fetch(f'https://pin.test:{s.port}/data');self.assertEqual(r.body,BODY);self.assertEqual(s.sni,['pin.test'])
            with self.assertRaises(PinError):f.fetch(f'https://wrong.test:{s.port}/data')
            self.assertEqual(len(s.requests),1);self.assertEqual(s.sni[-1],'wrong.test')
    def test_redirect_relative(self):
        with Listener() as s:
            r=self.fetcher(s.port).fetch(f'http://pin.test:{s.port}/redirect');self.assertEqual(len(r.audit),2);self.assertEqual(r.body,BODY)
    def test_redirect_credential_strip(self):
        with Listener() as a,Listener() as b:
            a.redirect=f'http://other.test:{b.port}/data'
            p=Policy((f'http://pin.test:{a.port}',f'http://other.test:{b.port}'),testing_ips=('127.0.0.1',))
            Fetcher(p,resolver=lambda h,p:['127.0.0.1']).fetch(f'http://pin.test:{a.port}/redirect',headers={'Authorization':'PUBLIC_LAB_TOKEN','Cookie':'PUBLIC_COOKIE','X-Key':'PUBLIC_TEST','Accept':'application/json'})
            self.assertIn('authorization',a.requests[0]['headers']);self.assertNotIn('authorization',b.requests[0]['headers']);self.assertNotIn('cookie',b.requests[0]['headers']);self.assertNotIn('x-key',b.requests[0]['headers']);self.assertIn('accept',b.requests[0]['headers'])
    def test_redirect_denied_listener(self):
        with Listener() as a,Listener() as b:
            a.redirect=f'http://127.0.0.1:{b.port}/data'
            with self.assertRaisesRegex(PinError,'origin_denied'):self.fetcher(a.port).fetch(f'http://pin.test:{a.port}/redirect')
            self.assertEqual(len(a.requests),1);self.assertEqual(b.requests,[])
    def test_body_plus_one(self):
        with Listener() as s:
            self.assertEqual(self.fetcher(s.port,max_body=len(BODY)).fetch(f'http://pin.test:{s.port}/data').body,BODY)
            with self.assertRaisesRegex(PinError,'body_quota'):self.fetcher(s.port,max_body=len(BODY)-1).fetch(f'http://pin.test:{s.port}/data')
            self.assertEqual(self.fetcher(s.port,max_body=0).fetch(f'http://pin.test:{s.port}/empty').body,b'')
    def test_invalid_headers(self):
        with Listener() as s:
            for headers in [{'Host':'elsewhere'},{'Authorization':'a\r\nb'},{'X':'a','x':'b'}]:
                with self.assertRaises(PinError):self.fetcher(s.port).fetch(f'http://pin.test:{s.port}/data',headers=headers)
            self.assertEqual(s.requests,[])
    def test_proxy_environment_ignored(self):
        with Listener() as s,Listener() as proxy:
            old=os.environ.get('HTTP_PROXY');os.environ['HTTP_PROXY']=f'http://127.0.0.1:{proxy.port}'
            try:self.assertEqual(self.fetcher(s.port).fetch(f'http://pin.test:{s.port}/data').body,BODY)
            finally:
                if old is None:os.environ.pop('HTTP_PROXY',None)
                else:os.environ['HTTP_PROXY']=old
            self.assertEqual(proxy.requests,[])
    def test_import_native_sql(self):
        with tempfile.TemporaryDirectory() as t,Listener() as s:
            store=ImportStore(str(Path(t)/'imports.sqlite'));url=f'http://pin.test:{s.port}/data'
            self.assertTrue(store.import_url('orders',url,self.fetcher(s.port))['stored'])
            s.body=b'changed';self.assertFalse(store.import_url('orders',url,self.fetcher(s.port))['stored']);self.assertEqual(len(s.requests),1)
            self.assertEqual(store.export('orders'),BODY)
            with contextlib.closing(sqlite3.connect(store.path)) as db:
                row=db.execute('SELECT body,sha256,audit FROM imports').fetchone()
            self.assertEqual(row[0],BODY);self.assertEqual(row[1],hashlib.sha256(BODY).hexdigest());self.assertEqual(json.loads(row[2])[0]['peer'],'127.0.0.1')
            with self.assertRaisesRegex(PinError,'identity_conflict'):store.import_url('orders',url,self.fetcher(s.port),headers={'Authorization':'different'})
    def test_registered_cli(self):
        with tempfile.TemporaryDirectory() as t,Listener() as s:
            t=Path(t);policy=t/'policy.json';policy.write_text(json.dumps({'allowed_origins':[f'http://127.0.0.1:{s.port}'],'testing_ips':['127.0.0.1']}))
            import sysconfig
            exe=Path(sysconfig.get_path('scripts'))/('egresspin.exe' if os.name=='nt' else 'egresspin')
            r=subprocess.run([str(exe),'import',f'http://127.0.0.1:{s.port}/data','--database',str(t/'sink.sqlite'),'--key','orders','--policy',str(policy)],capture_output=True)
            self.assertEqual(r.returncode,0,r.stderr);self.assertTrue(json.loads(r.stdout)['stored'])
            output=subprocess.run([str(exe),'export','--database',str(t/'sink.sqlite'),'--key','orders'],capture_output=True)
            self.assertEqual(output.returncode,0,output.stderr);self.assertEqual(output.stdout,BODY)

if __name__=='__main__':unittest.main()
