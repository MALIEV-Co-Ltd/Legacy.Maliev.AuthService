"""Fixed PostgreSQL pre-create restriction over the unchanged private proxy."""
import json
import sys
import time
from pathlib import Path
from route import module

def plan(document,run,parent,inspect,original):
    if type(document) is not dict or document.get('Image')!='postgres:18-alpine':
        raise ValueError('Only existing Auth PostgreSQL fixture accepted')
    host=document.get('HostConfig',{})
    if document.get('Volumes') or host.get('Tmpfs') or document.get('Cmd') or document.get('Entrypoint'):
        raise ValueError('No caller data mount or executable override')
    image=inspect()
    import re
    if not re.fullmatch('sha256:[0-9a-f]{64}',image.get('Id','')):
        raise ValueError('Inspected immutable image required')
    volumes=image.get('Config',{}).get('Volumes')
    if type(volumes) is not dict or list(volumes) not in (['/var/lib/postgresql'],['/var/lib/postgresql/data']):
        raise ValueError('Reviewed PostgreSQL data declaration required')
    row=json.loads(json.dumps(document));row['Image']=image['Id']
    row.setdefault('HostConfig',{}).update(PidsLimit=64,Tmpfs={name:'rw,noexec,nosuid,size=805306368' for name in volumes})
    result=original(row,run,parent)
    if result['HostConfig']['Memory']!=768*1024**2 or result['HostConfig']['NanoCpus']!=1000000000:
        raise ValueError('Original fixed fixture caps required')
    return result

def main():
    # The original parser, peer/cgroup custody, forwarding and Ledger remain.
    source=Path(__file__).resolve().parents[1]/'financial-iam'
    backend=module(Path(__file__).resolve().parents[1]/'customer-refresh-no-sdk-adapter-v2-20261009/shared_backend.py','cs9_proxy_shared')
    captured=backend.capture(source)
    import types
    proxy=types.ModuleType('captured_cs9_proxy')
    exec(compile(captured['private_docker_proxy.py'],str(source/'private_docker_proxy.py'),'exec'),proxy.__dict__)
    original=proxy.create_plan
    daemon=sys.argv[sys.argv.index('--daemon')+1]
    def inspect():
        status,image=proxy.rpc(daemon,'GET','/images/postgres:18-alpine/json')
        if status!=200:raise ValueError('Actual private image inspection required')
        return image
    proxy.create_plan=lambda document,run,parent:plan(document,run,parent,inspect,original)
    proxy.main()

if __name__=='__main__':main()
