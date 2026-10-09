"""Bind actual VSTest list output to the just-built focused test assembly."""
import hashlib
import json
import re
import sys
from pathlib import Path

PREFIX = 'Legacy.Maliev.AuthService.Tests.'
ASSEMBLY = 'Legacy.Maliev.AuthService.Tests.dll'
METHODS = {
    PREFIX+'CustomerRefreshAdmissionTests.Refresh_RechecksInitialPasswordStateBeforeIssuance': 'expectedSuccess',
    PREFIX+'LegacyIdentityReaderTests.FindActive_InitialPasswordState_DeniesOnlySetupRequiredCustomer': 'expectedActive',
    PREFIX+'RefreshSessionIdentityBoundaryHttpTests.CustomerRefresh_CurrentInitialPasswordState_ControlsFamilyAdmissionOnly': None,
}

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def association(name):
    method, sep, tail = name.partition('(')
    if method not in METHODS or not sep or not tail.endswith(')'):
        raise ValueError('Unknown discovered focused case')
    pairs = [part.strip().split(': ',1) for part in tail[:-1].split(',')]
    if any(len(p) != 2 for p in pairs) or len({p[0] for p in pairs}) != len(pairs):
        raise ValueError('Malformed or duplicate theory arguments')
    args = dict(pairs)
    outcome = METHODS[method]
    if outcome is None:
        if set(args) != {'setupRequired'} or args['setupRequired'] not in ('true','false'):
            raise ValueError('Wrong HTTP theory arguments')
    else:
        if set(args) != {'kind','setupRequired',outcome} or args['kind'] not in ('Customer','Employee') or args['setupRequired'] not in ('true','false'):
            raise ValueError('Wrong admission theory arguments')
        expected = 'false' if args['kind'] == 'Customer' and args['setupRequired'] == 'true' else 'true'
        if args[outcome] != expected: raise ValueError('Substituted expected outcome')
    return method, tuple(sorted(args.items()))

def validate_names(names):
    if len(names) != 10 or len(set(names)) != 10:
        raise ValueError('Discovery must contain ten distinct display names')
    joined = [association(name) for name in names]
    if len(set(joined)) != 10:
        raise ValueError('Repeated theory association')
    for method,outcome in METHODS.items():
        if sum(m == method for m,a in joined) != (2 if outcome is None else 4):
            raise ValueError('Wrong discovered method count')

def capture(assembly, listing):
    assembly = Path(assembly).resolve()
    if assembly.name != ASSEMBLY: raise ValueError('Wrong compiled assembly')
    raw = Path(listing).read_bytes()
    names = [line.strip() for line in raw.decode('utf-8-sig').splitlines() if any(line.strip().startswith(method+'(') for method in METHODS)]
    validate_names(names)
    return {'assemblyPath':str(assembly),'assemblySha256':sha(assembly),'listingSha256':hashlib.sha256(raw).hexdigest(),'cases':names}

if __name__ == '__main__':
    print(json.dumps(capture(sys.argv[1],sys.argv[2]),sort_keys=True))
