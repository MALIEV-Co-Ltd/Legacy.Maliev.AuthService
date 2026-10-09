"""One fixed Auth SDK route over captured retained resource functions."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import types

BASE='ee0e314ce37a127e6e3dd45d659b5d7ba95b3a9b'
PACKET_SEAL='df7660fd49acf98fabfd3986363f8c981956f91e50462b794435e0ff72d45d09'
HERE=Path(__file__).resolve().parent

def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result

def shared(source):
    backend=module(Path(source)/'eng/customer-refresh-no-sdk-adapter-v2-20261009/shared_backend.py','cs9_shared')
    loaded=backend.modules(Path(source)/'eng/financial-iam')
    loaded['pins']=backend.PINS
    return backend,loaded

def replace_once(text,before,after):
    if text.count(before)!=1:raise ValueError('Retained source hook changed')
    return text.replace(before,after,1)

def owner_text(raw):
    text=raw.decode()
    start=text.index('        sdk_command = ["/usr/bin/pwsh"')
    end=text.index('        if args.stage == "build":',start)
    text=text[:start]+'''        sdk_command = ["/usr/bin/python3", "-B", '''+repr(str(HERE/'worker.py'))+''',
            "--source", str(pathlib.Path(args.checkouts).resolve(strict=True)),
            "--destination", str(root / "cs9-materialized"), "--receipts", str(receipts),
            "--context", str(receipts / "native-context.json")]
'''+text[end:]
    marker='str(source / "private_docker_proxy.py")'
    if text.count(marker)!=2:raise ValueError('Exact proxy hooks required')
    text=text.replace(marker,repr(str(HERE/'proxy.py')))
    text=replace_once(text,'(source / "private_docker_proxy.py").read_bytes()',
                      'pathlib.Path('+repr(str(HERE/'proxy.py'))+').read_bytes()')
    # Retain the runtime directory generation for unchanged physical cleanup.
    text=replace_once(text,'    if args.stage == "proof":\n        birth = root.stat()',
                      '    if args.stage == "full":\n        birth = root.stat()')
    return text

def run_owner():
    source=Path(sys.argv[sys.argv.index('--source')+1])
    if sys.argv[sys.argv.index('--lane')+1]!='auth' or sys.argv[sys.argv.index('--stage')+1]!='full':
        raise ValueError('Only fixed Auth validation accepted')
    backend,loaded=shared(source.parents[1])
    captured=backend.capture(source)
    private=types.ModuleType('cs9_owned_coordinator')
    with backend.bind_loaded(loaded):
        exec(compile(owner_text(captured['hosted_owner.py']),str(HERE/'owner.py'),'exec'),private.__dict__)
        private.main()

def packet(source):
    root=Path(source)/'eng/customer-self-identity-intake'
    candidate=root/'customer-self-identity-setup-admission-source-v1-20261009'
    if hashlib.sha256((candidate/'seal.json').read_bytes()).hexdigest()!=PACKET_SEAL:
        raise ValueError('Fixed two-file packet required')
    return candidate

def materialize(source,destination):
    adapter=module(Path(source)/'eng/customer-self-identity-intake/controls/intake_adapter.py','cs9_intake')
    backend=adapter.load_backend(destination)
    backend.BASE=BASE
    backend.verify_packet=lambda p:adapter.verify_packet(p,backend)
    result=backend.materialize(Path(destination),packet(source))
    result['originalPacketBase']=adapter.BASE
    result['sdkExecuted']=False
    return result
