"""Independent Auth policy model plus unchanged no-SDK lifecycle proof.

No real Testcontainers request or customer behavior is claimed by this route.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path
import shared_backend

def policy_module(path):
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path,*path.parents)) or not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError('Nonregular reviewed Auth policy')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != POLICY_SHA:
        raise ValueError('Reviewed Auth policy changed')
    import types
    module = types.ModuleType('auth_fixture_policy')
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module

# Exact sealed pure-policy source; real wire binding remains a separate gate.
POLICY_SHA = 'eacd143bb1ee22fdb00ab078d1672e9a7538808465beba60a5d1c5387026811f'

def model(proxy, policy):
    run = '11111111-1111-4111-8111-111111111111'
    parent = 'codex-auth-refresh-'+run+'.slice'
    contract = {'runId':run,'cgroupParent':parent,'imageId':'sha256:'+'a'*64,'imageVolumes':['/var/lib/postgresql'],'expiresAtUnix':1600,'memoryBytes':384*1024**2,'nanoCpus':1000000000,'pidsLimit':64}
    request = {'Image':'postgres:18-alpine','HostConfig':{'PortBindings':{'5432/tcp':[{'HostIp':'','HostPort':''}]}}}
    admitted = policy.admit_create(request,contract,1000)
    shared = proxy.create_plan(admitted,run,parent)
    host = shared['HostConfig']
    if any(host[key] != value for key,value in {'Memory':contract['memoryBytes'],'MemorySwap':contract['memoryBytes'],'NanoCpus':contract['nanoCpus'],'PidsLimit':64,'CgroupParent':parent}.items()):
        raise ValueError('Shared pre-birth API changed Auth policy bounds')
    if shared['Labels'][policy.LABEL] != run or host['PortBindings']['5432/tcp'][0]['HostIp'] != '127.0.0.1':
        raise ValueError('Shared pre-birth API changed Auth ownership/forwarding')
    return {'policyModelPassed':True,'realTestcontainersWireCaptured':False,'customerRuntimeAccepted':False,'fixtureProcessStarted':False}

def readback_with_model(loaded,evidence,policy_path):
    first = None
    probe = None
    errors = []
    try:
        probe = model(loaded['private_docker_proxy'],policy_module(policy_path))
        saved = json.loads((evidence/'resources/auth-policy-model.json').read_bytes())
        if saved != probe: raise ValueError('Auth model receipt changed')
    except BaseException as error:
        first = error
        errors.append('model:'+type(error).__name__)
    try:
        loaded['finite_stub_proof'].readback(evidence)
    except BaseException as error:
        if first is None: first = error
        errors.append('lifecycle:'+type(error).__name__)
    try:
        loaded['finite_stub_proof'].save(evidence/'auth-readback.json',{'errors':errors,'model':probe,'customerRuntimeAccepted':False})
    except BaseException as error:
        if first is None: first = error
    if first is not None: raise first
    return probe

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--role',choices=('workload','readback'),required=True)
    parser.add_argument('--context',type=Path)
    parser.add_argument('--receipt',type=Path)
    parser.add_argument('--evidence',type=Path)
    parser.add_argument('--backend',type=Path,required=True)
    parser.add_argument('--policy',type=Path,required=True)
    args = parser.parse_args()
    loaded = shared_backend.modules(args.backend)
    with shared_backend.bind_loaded(loaded):
        if args.role == 'workload':
            probe = model(loaded['private_docker_proxy'],policy_module(args.policy))
            loaded['finite_stub_proof'].save(args.receipt.with_name('auth-policy-model.json'),probe)
            # Generic empty-image lifecycle evidence is not PostgreSQL proof.
            loaded['finite_stub_proof'].workload(args.context,args.receipt)
        else:
            print(json.dumps(readback_with_model(loaded,args.evidence,args.policy),sort_keys=True))

if __name__ == '__main__': main()
