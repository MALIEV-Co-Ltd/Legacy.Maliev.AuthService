"""Verify frozen Auth owner inputs and run pure controls; never allocate resources."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT/'eng/customer-refresh-no-sdk-adapter-v2-20261009'
POLICY = ROOT/'eng/customer-refresh-native-create-policy-v1-20261009'
SEALS = ((ADAPTER,'460a1c1255e9cdb4d0b9a4c912c894e9b198cdd6fab678508c2e2f219514092a'),
         (POLICY,'77e88ef0c59b19810d6c00c74a8c569a4d0a33c6251822b5b6a93a6b660fe48e'))

def verify():
    for directory,pin in SEALS:
        raw = (directory/'seal.json').read_bytes()
        if hashlib.sha256(raw).hexdigest() != pin: raise ValueError('Frozen seal changed')
        for row in json.loads(raw)['files']:
            path = directory/row['path']
            if path.parent != directory or path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
                raise ValueError('Invalid frozen source path')
            payload = path.read_bytes()
            if len(payload) != row['bytes'] or hashlib.sha256(payload).hexdigest() != row['sha256']:
                raise ValueError('Frozen source changed')
    for directory in (ADAPTER,POLICY):
        for path in directory.glob('*.py'): compile(path.read_bytes(),str(path),'exec')

def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--child',choices=('adapter','policy'))
    args = parser.parse_args()
    verify()
    if args.child:
        directory = ADAPTER if args.child == 'adapter' else POLICY
        sys.path.insert(0,str(directory))
        if args.child == 'adapter':
            import test_adapter as tests
            tests.BACKEND = ROOT/'eng/financial-iam'
            tests.POLICY = POLICY/'create_policy.py'
        else:
            import test_create_policy as tests
        suite = unittest.defaultTestLoader.loadTestsFromModule(tests)
        expected = 7 if args.child == 'adapter' else 5
        if suite.countTestCases() != expected: raise ValueError('Exact controls required')
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        if not result.wasSuccessful() or result.skipped: raise SystemExit(1)
    else:
        for optimized in (False,True):
            for kind in ('adapter','policy'):
                argv = [sys.executable,'-B']+(['-O'] if optimized else [])+[str(Path(__file__).resolve()),'--child',kind]
                result = subprocess.run(argv,timeout=30,check=False)
                if result.returncode: raise SystemExit(result.returncode)
        print('PASS: frozen inputs; compile first; 12 normal and 12 optimized source controls; native unrun')

if __name__ == '__main__': main()
