"""Copy only reviewed intake files from the exact workflow commit to a fresh directory."""
import json
import re
import sys
from pathlib import Path
import intake

CONTROL_NAMES = ('intake.py','test_intake.py','verify_trx.py','discovery.py','export_transport.py')
PREFIX = 'eng/customer-refresh-intake/'
OBSERVER_PINS = {
    'scripts/observe_postgres_cleanup.py':'48d73f0c1acd8b7f37cd1b2015437be49bcd77f11dbbf1f2d7b14a7cc98151e3',
    'scripts/test_observe_postgres_cleanup.py':'9280d52e0d1ccd7afb2265eb85d72990ceccf274abcb1ce5c0ba073923aabe10',
}

def export(root, commit, destination):
    if not re.fullmatch('[0-9a-f]{40}',commit) or destination.exists():
        raise ValueError('Exact transport commit and fresh directory required')
    if intake.git(root,'rev-parse','HEAD').decode().strip() != commit:
        raise ValueError('Workflow source mismatch')
    if intake.git(root,'status','--porcelain','--untracked-files=all'):
        raise ValueError('Dirty transport checkout')
    packet_prefix = PREFIX+'auth-customer-refresh-setup-fence-source-v1-20261009/'
    seal = intake.git(root,'show',commit+':'+packet_prefix+'seal.json')
    if intake.digest(seal) != intake.SEAL:
        raise ValueError('Transport source seal mismatch')
    rows = intake.load(seal)['files']
    expected = {PREFIX+'controls/'+name for name in CONTROL_NAMES} | {packet_prefix+'seal.json'} | {packet_prefix+r['path'] for r in rows}
    actual = set(intake.git(root,'ls-tree','-r','--name-only',commit,'--',PREFIX).decode().splitlines())
    if actual != expected: raise ValueError('Unexpected transport member')
    captured = {}
    for name in sorted(expected):
        mode = intake.git(root,'ls-tree',commit,'--',name).decode().split()[0]
        if mode != '100644': raise ValueError('Nonregular transport member')
        captured[name[len(PREFIX):]] = intake.git(root,'show',commit+':'+name)
    for name, expected_hash in OBSERVER_PINS.items():
        mode = intake.git(root,'ls-tree',commit,'--',name).decode().split()[0]
        raw = intake.git(root,'show',commit+':'+name)
        if mode != '100644' or intake.digest(raw) != expected_hash:
            raise ValueError('Unreviewed observer mode or source')
        captured['observer-controls/'+Path(name).name] = raw
    destination.mkdir()
    for name,raw in captured.items():
        path = destination/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw)
    intake.verify_packet(destination/'auth-customer-refresh-setup-fence-source-v1-20261009')
    return {'transportCommit':commit,'files':{name:intake.digest(raw) for name,raw in captured.items()}}

if __name__ == '__main__':
    print(json.dumps(export(Path(sys.argv[1]),sys.argv[2],Path(sys.argv[3])),sort_keys=True))
