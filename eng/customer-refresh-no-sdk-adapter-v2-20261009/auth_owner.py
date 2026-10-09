"""Proof-only entrypoint inside the existing pre-registered capped owner unit."""
import argparse
import os
import sys
from pathlib import Path
import shared_backend

def arguments(argv):
    parser = argparse.ArgumentParser(add_help=False,allow_abbrev=False)
    parser.add_argument('--source',required=True)
    parser.add_argument('--lane',required=True)
    parser.add_argument('--stage',required=True)
    for name in ('checkouts','receipt','coordinator-unit'):
        parser.add_argument('--'+name,required=True)
    seen = set()
    for token in argv:
        if token.startswith('--'):
            key = token.split('=',1)[0]
            if key in seen: raise ValueError('Repeated owner option')
            seen.add(key)
    args = parser.parse_args(argv)
    if args.lane != 'auth' or args.stage != 'proof':
        raise ValueError('Only Auth no-SDK proof accepted')
    return args

def main():
    args = arguments(sys.argv[1:])
    if os.name != 'posix' or args.lane != 'auth' or args.stage != 'proof':
        raise ValueError('Only existing Linux no-SDK proof route accepted')
    # The original main still validates actual coordinator argv/birth/cgroup,
    # caps, expiry, private daemon/proxy and independent recovery unchanged.
    with shared_backend.bind_loaded(shared_backend.modules(args.source,Path(__file__).with_name('auth_proof.py'))) as loaded:
        loaded['hosted_owner'].main()

if __name__ == '__main__': main()
