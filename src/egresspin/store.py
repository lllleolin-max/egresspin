"""Concrete SQLite URL-import sink: full bytes plus connection witness atomically."""
from contextlib import closing
from dataclasses import asdict
import hashlib,json,re,sqlite3
from .model import PinError,integer,normalize
from .client import _headers

class ImportStore:
    def __init__(self,path,*,max_items=1000,max_bytes=16777216):
        self.path=path;self.max_items=integer(max_items,0,10000);self.max_bytes=integer(max_bytes,0,167772160)
        with closing(sqlite3.connect(path)) as db:
            db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA synchronous=EXTRA')
            db.execute('CREATE TABLE IF NOT EXISTS imports(key TEXT PRIMARY KEY,url TEXT NOT NULL,request_sha256 TEXT NOT NULL,status INTEGER NOT NULL,content_type TEXT NOT NULL,body BLOB NOT NULL,sha256 TEXT NOT NULL,audit TEXT NOT NULL)');db.commit()
    def import_url(self,key,url,fetcher,*,headers=None):
        if not isinstance(key,str) or not re.fullmatch('[A-Za-z0-9_-]{1,64}',key):raise PinError('invalid_key')
        canonical=fetcher.policy.target(url).url
        normalized_headers=_headers(headers)
        request_digest=hashlib.sha256(json.dumps([canonical,normalized_headers],sort_keys=True,separators=(',',':')).encode()).hexdigest()
        with closing(sqlite3.connect(self.path)) as db:
            old=db.execute('SELECT request_sha256,sha256 FROM imports WHERE key=?',(key,)).fetchone()
            number,total=db.execute('SELECT count(*),coalesce(sum(length(body)),0) FROM imports').fetchone()
        if old:
            if old[0]!=request_digest:raise PinError('identity_conflict')
            return {'key':key,'stored':False,'sha256':old[1]}
        if number>=self.max_items or total>=self.max_bytes and fetcher.policy.max_body>0:raise PinError('import_quota')
        result=fetcher.fetch(canonical,headers=normalized_headers)
        if result.status!=200:raise PinError('import_status',result.audit)
        digest=hashlib.sha256(result.body).hexdigest()
        witness=json.dumps([asdict(hop) for hop in result.audit],sort_keys=True,separators=(',',':'))
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('BEGIN IMMEDIATE')
            existing=db.execute('SELECT request_sha256,sha256 FROM imports WHERE key=?',(key,)).fetchone()
            if existing:
                if existing!=(request_digest,digest):raise PinError('identity_conflict')
                return {'key':key,'stored':False,'sha256':digest}
            number,total=db.execute('SELECT count(*),coalesce(sum(length(body)),0) FROM imports').fetchone()
            if number>=self.max_items or total+len(result.body)>self.max_bytes:raise PinError('import_quota')
            db.execute('INSERT INTO imports VALUES(?,?,?,?,?,?,?,?)',(key,canonical,request_digest,result.status,result.content_type,result.body,digest,witness));db.commit()
        return {'key':key,'stored':True,'sha256':digest,'bytes':len(result.body)}
    def export(self,key):
        with closing(sqlite3.connect(self.path)) as db:row=db.execute('SELECT body,sha256 FROM imports WHERE key=?',(key,)).fetchone()
        if not row:raise PinError('import_missing')
        body=bytes(row[0])
        if hashlib.sha256(body).hexdigest()!=row[1]:raise PinError('import_corrupt')
        return body
