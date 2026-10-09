"""Validate Root's concrete one-run request before any native allocation."""
import base64
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid
from route import BASE,PACKET_SEAL

def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Duplicate request key')
        result[key]=value
    return result

def validate(raw,expected,env,now):
    if type(raw) is not bytes or not 0<len(raw)<=4096 or hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('Exact reviewed request bytes required')
    row=json.loads(raw,object_pairs_hook=unique)
    keys={'issuedBy','owner','phase','leaseId','issuedUtc','expiresUtc','sourceCommit','base','packetSeal'}
    fixed={'issuedBy':'019fc21e-50f0-7112-834f-9fb3b35b9dfe','owner':'01a1009c-c0ad-71b2-986b-136d13d5d51f','phase':'auth-cs9-validation','base':BASE,'packetSeal':PACKET_SEAL}
    if set(row)!=keys or any(type(v) is not str for v in row.values()) or any(row[k]!=v for k,v in fixed.items()):raise ValueError('Exact Auth request scope required')
    if str(uuid.UUID(row['leaseId']))!=row['leaseId']:raise ValueError('Canonical fresh lease required')
    issued=datetime.fromisoformat(row['issuedUtc']);expiry=datetime.fromisoformat(row['expiresUtc'])
    if issued.utcoffset() is None or expiry.utcoffset() is None or not issued<=now<expiry or not 0<(expiry-issued).total_seconds()<=900:raise ValueError('Fresh finite request required')
    if env.get('GITHUB_REPOSITORY')!='MALIEV-Co-Ltd/Legacy.Maliev.AuthService' or env.get('GITHUB_EVENT_NAME')!='workflow_dispatch' or env.get('GITHUB_REF')!='refs/heads/main' or env.get('GITHUB_RUN_ATTEMPT')!='1' or env.get('GITHUB_SHA')!=row['sourceCommit']:raise ValueError('Protected-main first attempt required')
    return row

def main():
    raw=base64.b64decode(os.environ['REQUEST_BASE64'],validate=True)
    row=validate(raw,os.environ['REQUEST_SHA256'],os.environ,datetime.now(timezone.utc))
    head=subprocess.check_output(['git','rev-parse','HEAD'],timeout=30).decode().strip()
    if head!=row['sourceCommit'] or subprocess.check_output(['git','status','--porcelain','--untracked-files=all'],timeout=30):raise ValueError('Clean exact workflow source required')
    here=Path(__file__).resolve().parent
    seal=json.loads((here/'seal.json').read_bytes(),object_pairs_hook=unique)
    names={'route.py','auth_owner.py','proxy.py','worker.py','caller.py','readback.py','admission.py','test_caller.py','test_route.py','workflow.yml'}
    rows=seal['files']
    if len(rows)!=10 or {r['path'] for r in rows}!=names:raise ValueError('Exact route seal inventory required')
    for item in rows:
        name,digest=item['path'],item['sha256']
        path=here/name
        if path.is_symlink() or path.stat().st_nlink!=1 or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise ValueError('Published route source changed')
        relative=path.relative_to(Path.cwd()).as_posix()
        if subprocess.check_output(['git','cat-file','blob',head+':'+relative],timeout=30)!=path.read_bytes():raise ValueError('Route Git object mismatch')
    workflow=Path('.github/workflows/customer-self-identity-validation.yml')
    if workflow.read_bytes()!=(here/'workflow.yml').read_bytes() or subprocess.check_output(['git','cat-file','blob',head+':'+workflow.as_posix()],timeout=30)!=workflow.read_bytes():raise ValueError('Exact workflow mirror required')
    from caller import admission
    admission(os.environ,Path('/proc/meminfo').read_text(),Path('/sys/fs/cgroup/cgroup.controllers').is_file())
    (Path(os.environ['RUNNER_TEMP'])/('auth-cs9-request-'+os.environ['GITHUB_RUN_ID']+'.json')).write_bytes(raw)
    print('Exact fresh Auth request and source admitted; no SDK workload launched')

def cached():
    path=Path(os.environ['RUNNER_TEMP'])/('auth-cs9-request-'+os.environ['GITHUB_RUN_ID']+'.json')
    if path.is_symlink() or path.stat().st_nlink!=1:raise ValueError('Regular request cache required')
    return validate(path.read_bytes(),os.environ['REQUEST_SHA256'],os.environ,datetime.now(timezone.utc))

if __name__=='__main__':main()
