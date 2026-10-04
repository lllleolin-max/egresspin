import argparse,json,sys
from dataclasses import asdict
from pathlib import Path
from . import Fetcher,ImportStore,PinError,Policy

def main():
    p=argparse.ArgumentParser(prog='egresspin',description='Pinned GET imports; policy is trusted application configuration')
    sub=p.add_subparsers(dest='command',required=True)
    run=sub.add_parser('import');run.add_argument('url');run.add_argument('--key',required=True);run.add_argument('--database',required=True)
    run.add_argument('--policy',required=True);run.add_argument('--cafile')
    export=sub.add_parser('export');export.add_argument('--database',required=True);export.add_argument('--key',required=True)
    a=p.parse_args()
    try:
        if a.command=='export':sys.stdout.buffer.write(ImportStore(a.database).export(a.key));return 0
        path=Path(a.policy)
        if path.stat().st_size>65536:raise PinError('policy_quota')
        data=json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data,dict):raise PinError('invalid_policy')
        policy=Policy(**data);result=ImportStore(a.database).import_url(a.key,a.url,Fetcher(policy,cafile=a.cafile))
        print(json.dumps(result,sort_keys=True));return 0
    except (PinError,OSError,ValueError,TypeError) as error:
        code=error.code if isinstance(error,PinError) else 'invalid_configuration'
        print(json.dumps({'error':code,'audit':[asdict(hop) for hop in error.audit] if isinstance(error,PinError) else []}),file=sys.stderr);return 3

if __name__=='__main__':raise SystemExit(main())
