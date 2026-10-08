"""Offline transport checks only. No SDK, network, daemon or OS job is launched."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

SEAL_SHA256 = '7d14c32c96f973f4149b507d0a6bf4f1361bc33b695559c20e2df58ff7e441da'
PYTHON = ('private_docker_proxy.py', 'hosted_owner.py', 'recover_owner.py',
          'expiry_guard.py', 'verify_results.py', 'test_controls.py',
          'commerce_build_route.py', 'test_commerce_build_route.py',
          'finite_stub_proof.py', 'test_finite_stub_proof.py')

EXPECTED_COUNTS = {
    'pureControls': 69, 'transportControls': 5, 'commerceBuildRouteControls': 16,
    'stubProofControls': 34, 'totalControls': 124,
    'pythonSources': len(PYTHON), 'pythonSourcesCompiled': len(PYTHON) + 2,
    'psSources': 3,
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bounded_file(path, maximum):
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError('Linked transport source rejected')
    if not path.is_file() or path.stat().st_size > maximum:
        raise ValueError('Missing or oversized transport source')
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('Transport source exceeded read bound')
    return raw


def verify(root):
    directory = root / 'eng/financial-iam'
    raw = bounded_file(directory / 'source-transport-seal.json', 65536)
    if sha(raw) != SEAL_SHA256:
        raise ValueError('Immutable source transport seal changed')
    seal = json.loads(raw)
    if seal['schemaVersion'] != 1 or len(seal['files']) != 27 or seal['candidateNativeAccepted'] is not False:
        raise ValueError('Reviewed transport inventory differs')
    counts = seal.get('counts')
    if not isinstance(counts, dict) or counts != EXPECTED_COUNTS or any(type(value) is not int for value in counts.values()):
        raise ValueError('Reviewed transport count metadata differs')
    seen = set()
    for row in seal['files']:
        name = row['path']
        if name in seen or any(part in ('', '.', '..') for part in name.split('/')) or '\\' in name or ':' in name:
            raise ValueError('Invalid transport inventory path')
        seen.add(name)
        content = bounded_file(root / name, 1048576)
        if len(content) != row['bytes'] or sha(content) != row['sha256']:
            raise ValueError('Reviewed raw transport postimage changed')
    for row in seal['decodedRawInputs']:
        encoded = bounded_file(directory / 'inputs' / row['name'], 1048576).strip()
        data = base64.b64decode(encoded, validate=True)
        if base64.b64encode(data) != encoded or len(data) != row['decodedBytes'] or sha(data) != row['decodedSha256']:
            raise ValueError('Original raw encoded producer bytes changed')
    # Compile first; importing mocked controls does not compensate for syntax
    # failure and does not qualify any live Linux process/container behavior.
    for name in PYTHON:
        compile(bounded_file(directory / name, 131072).decode('utf-8'), str(directory / name), 'exec')
    compile(bounded_file(Path(__file__), 131072).decode('utf-8'), __file__, 'exec')
    compile(bounded_file(directory / 'test_source_transport.py', 131072).decode('utf-8'), str(directory / 'test_source_transport.py'), 'exec')
    return {'sealedFiles': 27, 'decodedRawInputs': len(seal['decodedRawInputs']),
            'pythonSourcesCompiled': 12, 'candidateNativeAccepted': False,
            'sdkStarted': False, 'nativeResourcesCreated': 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-pure-controls', action='store_true')
    parser.add_argument('--windows-import-shim', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    result = verify(root)
    if args.windows_import_shim:
        if os.name != 'nt':
            raise ValueError('Windows import shim cannot qualify Linux')
        import socketserver
        # Windows lacks this class. Pure mocks never construct/bind it; this
        # opt-in import alias is explicitly not platform/lifecycle acceptance.
        socketserver.UnixStreamServer = socketserver.TCPServer
        result['windowsImportShimOnly'] = True
    if args.run_pure_controls:
        suite = unittest.defaultTestLoader.loadTestsFromName('test_controls')
        checked = unittest.TextTestRunner(verbosity=2).run(suite)
        if checked.testsRun != EXPECTED_COUNTS['pureControls'] or checked.failures or checked.errors or checked.skipped:
            raise ValueError('Exact pure control suite did not pass')
        result.update(pureControlsPassed=EXPECTED_COUNTS['pureControls'], nativeLifecycleQualified=False)
        suite = unittest.defaultTestLoader.loadTestsFromName('test_source_transport')
        checked = unittest.TextTestRunner(verbosity=2).run(suite)
        if checked.testsRun != EXPECTED_COUNTS['transportControls'] or checked.failures or checked.errors or checked.skipped:
            raise ValueError('Exact transport regression suite did not pass')
        result['transportControlsPassed'] = EXPECTED_COUNTS['transportControls']
        suite = unittest.defaultTestLoader.loadTestsFromName('test_commerce_build_route')
        checked = unittest.TextTestRunner(verbosity=2).run(suite)
        if checked.testsRun != EXPECTED_COUNTS['commerceBuildRouteControls'] or checked.failures or checked.errors or checked.skipped:
            raise ValueError('Exact BUILD route rejection suite did not pass')
        result['commerceBuildRouteControlsPassed'] = EXPECTED_COUNTS['commerceBuildRouteControls']
        suite = unittest.defaultTestLoader.loadTestsFromName('test_finite_stub_proof')
        checked = unittest.TextTestRunner(verbosity=2).run(suite)
        if checked.testsRun != EXPECTED_COUNTS['stubProofControls'] or checked.failures or checked.errors or checked.skipped:
            raise ValueError('Exact stub proof failure-fence controls did not pass')
        result['stubProofControlsPassed'] = EXPECTED_COUNTS['stubProofControls']
    # Verify once more after tests. The tests cannot silently mutate a producer
    # input/source and still create successful transport evidence.
    verify(root)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
