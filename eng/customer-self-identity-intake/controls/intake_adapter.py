"""Exact two-file cs9 source overlay using the unchanged frozen intake transaction."""
import argparse
import hashlib
import json
from pathlib import Path
import types

BASE='54a8358d4ba8c5d8c8dcf39d9cec9429cd951edf'
BACKEND='eng/customer-refresh-intake/controls/intake.py'
BACKEND_SHA='46968d644d26bbf11d800b47771c4ebf1ea71bb726bbe80de9b6168bc08afa97'
SEAL='df7660fd49acf98fabfd3986363f8c981956f91e50462b794435e0ff72d45d09'
MANIFEST='c4675a28c8dca1f3a46246dd067b0b3fdf90b6fc413858695ff43a239f1274c6'
PATHS=('Legacy.Maliev.AuthService.Infrastructure/CustomerSelfIdentityReader.cs',
       'Legacy.Maliev.AuthService.Tests/CustomerSelfIdentityTests.cs')
MEMBERS={'manifest.json','patch.diff',*('files/'+name for name in PATHS)}

def load_backend(root):
    path=Path(root)/BACKEND
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink!=1:
        raise ValueError('Regular unchanged intake backend required')
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=BACKEND_SHA:
        raise ValueError('Frozen intake backend changed')
    backend=types.ModuleType('private_cs9_intake_backend')
    exec(compile(raw,str(path),'exec'),backend.__dict__)
    if backend.git(root,'cat-file','blob',BASE+':'+BACKEND)!=raw:
        raise ValueError('Intake backend does not match exact base object')
    return backend

def verify_packet(packet,backend):
    packet=Path(packet)
    if packet.is_symlink():raise ValueError('Regular packet root required')
    sealRaw=backend.safe_path(packet,'seal.json').read_bytes()
    backend.require(backend.digest(sealRaw)==SEAL,'cs9 seal mismatch')
    seal=backend.load(sealRaw)
    pins=seal['files']
    backend.require(isinstance(pins,dict) and set(pins)==MEMBERS,'cs9 seal membership')
    actual={p.relative_to(packet).as_posix() for p in packet.rglob('*') if p.is_file() or p.is_symlink()}
    backend.require(actual==MEMBERS|{'seal.json'},'unexpected packet member')
    for name,expected in pins.items():
        raw=backend.safe_path(packet,name).read_bytes()
        backend.require(backend.digest(raw)==expected,'cs9 packet mismatch')
    raw=backend.safe_path(packet,'manifest.json').read_bytes()
    backend.require(backend.digest(raw)==MANIFEST,'cs9 manifest mismatch')
    manifest=backend.load(raw)
    backend.require(manifest['base']==BASE,'cs9 base mismatch')
    rows=manifest['files']
    backend.require(len(rows)==2 and {r['path'] for r in rows}==set(PATHS),'cs9 overlay membership')
    return rows

def materialize(root,packet):
    backend=load_backend(root)
    # Overrides exist only in this captured private namespace. Published backend
    # bytes and ambient modules remain unchanged; rollback/readback are original.
    backend.BASE=BASE
    backend.SEAL=SEAL
    backend.MANIFEST=MANIFEST
    backend.verify_packet=lambda p:verify_packet(p,backend)
    result=backend.materialize(Path(root),Path(packet))
    result.update(intakeBackendSha256=BACKEND_SHA,sdkExecuted=False)
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    parser.add_argument('--checkout',type=Path,required=True)
    parser.add_argument('--packet',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(materialize(args.checkout,args.packet),sort_keys=True))
