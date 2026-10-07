"""BUILD-only consumer of sealed Commerce inputs inside the existing SDK unit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import time
import tempfile
import types

DRIVER_SHA = 'cb670db3b17795a88d9754c6064834c2de3f95fa1ade3de4ee25ecfed0c2e4a8'


def driver_module(path):
    path = Path(path).absolute()
    for part in (path, *path.parents):
        if part.is_symlink() or getattr(part.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('Linked BUILD driver refused')
    with path.open('rb') as stream:
        raw = stream.read(256 * 1024 + 1)
    if len(raw) > 256 * 1024 or hashlib.sha256(raw).hexdigest() != DRIVER_SHA:
        raise ValueError('Exact reviewed BUILD V3 driver required')
    module = types.ModuleType('reviewed_commerce_driver')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def git_blobs(shared, checkout, base, value, ledger):
    """Read actual committed blobs, preserving bytes rather than checkout conversions."""
    record = {'purpose': 'accepted-baseline-raw-blobs', 'pid': None, 'exited': False,
              'readerClosed': False, 'wholeUnitQuiescent': False}
    ledger.append(record)
    requests = tempfile.TemporaryFile()
    try:
        for row in value['baseFiles']:
            path = shared.canonical_path(row['path'])
            requests.write((base + ':' + path + '\n').encode('utf-8'))
        requests.seek(0)
        child = subprocess.Popen(['/usr/bin/git', '-C', str(checkout), 'cat-file', '--batch'],
                                 stdin=requests, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except BaseException:
        requests.close()
        raise
    original = None
    try:
        record['pid'] = child.pid
        record['startTicks'] = Path(f'/proc/{child.pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
        try:
            record['actualExecutable'] = os.readlink(f'/proc/{child.pid}/exe')
        except FileNotFoundError:
            if child.poll() is None:
                raise
            record['actualExecutable'] = None
            record['identityObservedAfterExit'] = True
        deadline = time.monotonic() + 30
        raw = bytearray()
        eof = False
        os.set_blocking(child.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout.fileno(), selectors.EVENT_READ)
            while child.poll() is None or not eof:
                if time.monotonic() >= deadline:
                    raise TimeoutError('Accepted Git blob batch deadline exceeded')
                for key, _ in selector.select(0.02):
                    try:
                        chunk = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        eof = True
                        selector.unregister(key.fd)
                    else:
                        if len(raw) + len(chunk) > 20 * 1024 * 1024:
                            raise ValueError('Accepted Git blob batch byte budget exceeded')
                        raw.extend(chunk)
        if child.returncode != 0:
            raise ValueError('Actual accepted Git blob batch failed')
        return bytes(raw)
    except BaseException as error:
        original = error
        raise
    finally:
        try:
            cancellation = shared.recover_fetch_owner(child)
        finally:
            requests.close()
        record.update(exited=child.poll() is not None, readerClosed=child.stdout.closed)
        if cancellation is not None and original is None:
            raise cancellation


def baseline_files(shared, archive, value):
    rows = value['baseFiles']
    result = {}
    offset = 0
    total = 0
    for row in rows:
        path = shared.canonical_path(row['path'])
        if path in result:
            raise ValueError('Duplicate accepted baseline path')
        end = archive.find(b'\n', offset)
        if end < 0 or end - offset > 100:
            raise ValueError('Incomplete actual Git blob response')
        fields = archive[offset:end].split(b' ')
        if len(fields) != 3 or fields[1] != b'blob' or not fields[2].isdigit():
            raise ValueError('Actual committed object is not a blob')
        size = int(fields[2])
        if size != row['bytes'] or size > shared.MAX_FILE_BYTES:
            raise ValueError('Accepted Git blob byte count differs')
        offset = end + 1
        raw = archive[offset:offset + size]
        total += size
        if total > 16 * 1024 * 1024:
            raise ValueError('Accepted baseline source budget exceeded')
        object_id = hashlib.sha1(b'blob ' + str(size).encode() + b'\0' + raw).hexdigest().encode()
        if fields[0] != object_id or shared.digest(raw) != row['sha256']:
            raise ValueError('Accepted Git blob seal differs')
        offset += size
        if archive[offset:offset + 1] != b'\n':
            raise ValueError('Incomplete actual Git blob response')
        offset += 1
        result[path] = raw
    if offset != len(archive):
        raise ValueError('Unexpected extra Git blob response')
    return result


def separate_paths(shared, args):
    for name in ('transport', 'driver', 'admission_verifier', 'context', 'checkouts', 'destination', 'receipts'):
        path = getattr(args, name)
        if not path.is_absolute():
            raise ValueError('Explicit absolute owner paths required')
        shared.reject_links(path)
    writes = (args.destination, args.receipts)
    reads = (args.transport, args.driver, args.admission_verifier, args.context, args.checkouts)
    # Context is already an owner receipt; its parent is intentionally receipts.
    for target in writes:
        for source in reads:
            if source == args.context and target == args.receipts:
                continue
            if target == source or target.is_relative_to(source) or source.is_relative_to(target):
                raise ValueError('BUILD outputs overlap immutable input roots')
    if args.destination == args.receipts or args.destination.is_relative_to(args.receipts) or args.receipts.is_relative_to(args.destination):
        raise ValueError('Separate candidate and result roots required')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('transport', 'driver', 'admission-verifier', 'context', 'checkouts', 'destination', 'receipts'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--lane', choices=('accounting', 'procurement', 'order'), required=True)
    args = parser.parse_args()
    driver = driver_module(args.driver)
    adapter = driver.verified_module(args.transport / 'commerce_source_adapter_v1.py', driver.ADAPTER_SHA)
    raw = (args.transport / 'policy.json').read_bytes()
    shared = adapter.load_shared(args.transport / 'sealed_source_capsule.py', adapter.SHARED_SHA256,
                                 raw, driver.POLICIES[args.lane], args.lane)
    value = adapter.policy(shared, raw, driver.POLICIES[args.lane], args.lane)
    separate_paths(shared, args)
    admission = driver.verified_module(args.admission_verifier, driver.ADMISSION_SHA)
    original = driver.gate(admission, args.context)
    checkout = args.checkouts / value['repository'].split('/')[1]
    shared.reject_links(checkout)
    shared.reject_links(args.receipts)
    logs = args.receipts / 'commerce-source-controls'
    logs.mkdir(exist_ok=False)
    ledger = []
    try:
        base = value['acceptedBase']
        for name, command in (
            ('commit', ['rev-parse', base + '^{commit}']),
            ('ancestry', ['merge-base', base, 'HEAD']),
        ):
            observed = driver.command(shared, ['/usr/bin/git', '-C', str(checkout), *command],
                                      checkout, logs / (name + '.log'), 30, ledger).strip()
            if observed != base:
                raise ValueError('Actual accepted baseline commit/ancestry differs')
        baseline = baseline_files(shared, git_blobs(shared, checkout, base, value, ledger), value)
        with (args.transport / 'capsule.zip').open('rb') as stream:
            capsule = stream.read(shared.MAX_ARCHIVE_BYTES + 1)
        blob = hashlib.sha1(b'blob ' + str(len(capsule)).encode() + b'\0' + capsule).hexdigest()
        if blob != value['capsuleGitBlob']:
            raise ValueError('Actual local capsule Git object differs')
        files = shared.validate_zip(capsule, value['bundleSha256'], value['bundleBytes'], value['entries'])
        source_receipt = adapter.materialize(shared, args.destination, baseline, files, value)
        (args.receipts / 'commerce-materialization.json').write_text(json.dumps(source_receipt, indent=2))
        driver.gate(admission, args.context, original_context=original)
        output = driver.command(shared, ['/usr/bin/python3', '-B', str(args.driver),
            '--lane', args.lane, '--transport', str(args.transport),
            '--admission-verifier', str(args.admission_verifier), '--context', str(args.context),
            '--source', str(args.destination / 'candidate'),
            '--dependencies', str(args.destination / 'dependencies'),
            '--results', str(args.receipts / 'commerce-build-results')],
            args.receipts, logs / 'build-driver.log', 1320, ledger)
        result = json.loads(output)
        if result.get('buildStageExited') is not True or result.get('nativeAccepted') is not False:
            raise ValueError('BUILD-only result shape differs')
        (args.receipts / 'commerce-build.json').write_text(json.dumps(result, indent=2))
    finally:
        (args.receipts / 'commerce-route-children.json').write_text(json.dumps(ledger, indent=2))


if __name__ == '__main__':
    main()
