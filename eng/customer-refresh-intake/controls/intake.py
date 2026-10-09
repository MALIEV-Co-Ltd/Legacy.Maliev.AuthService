"""Materialize only the frozen five-file customer refresh overlay; no SDK/dispatch."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path, PurePosixPath

BASE = '85a00d4bb54cf95199ee67dfd97d2b168233ff68'
SEAL = 'd70648e086959878866f28ccfcde2e13c790a1a54ba3b71ce670ddb8715ea7d9'
MANIFEST = '4a663e17df21579d26d8313ed30eacf833794e62e33e047e943811852e514cad'

def require(value, message):
    if not value:
        raise ValueError(message)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result

def load(raw):
    return json.loads(raw, object_pairs_hook=unique)

def safe_path(root, name):
    p = PurePosixPath(name)
    require(isinstance(name, str) and '\\' not in name and ':' not in name and
            not p.is_absolute() and all(x not in ('', '.', '..') for x in name.split('/')),
            'unsafe path')
    result = root / name
    for item in (result, *result.parents):
        require(not item.is_symlink(), 'symlink input')
        if item == root:
            break
    if result.exists():
        require(result.is_file() and result.stat().st_nlink == 1, 'nonregular or hard-linked input')
    return result

def verify_packet(packet):
    raw = safe_path(packet, 'seal.json').read_bytes()
    require(digest(raw) == SEAL, 'seal mismatch')
    rows = load(raw)['files']
    require(len(rows) == 13 and len({r['path'] for r in rows}) == 13, 'seal membership')
    for row in rows:
        data = safe_path(packet, row['path']).read_bytes()
        require(len(data) == row['bytes'] and digest(data) == row['sha256'], 'packet mismatch')
    raw = safe_path(packet, 'manifest.json').read_bytes()
    require(digest(raw) == MANIFEST, 'manifest mismatch')
    manifest = load(raw)
    require(manifest['base'] == BASE, 'base mismatch')
    rows = manifest['files']
    require(len(rows) == 5 and len({r['path'] for r in rows}) == 5, 'overlay membership')
    return rows

def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True,
                          capture_output=True, timeout=30).stdout

def validate_preimages(root, packet, rows):
    prepared = []
    for row in rows:
        target = safe_path(root, row['path'])
        old = target.read_bytes() if target.exists() else None
        require((old is None and row['parentSha256'] is None) or
                (old is not None and digest(old) == row['parentSha256']), 'parent mismatch')
        data = safe_path(packet, 'files/' + row['path']).read_bytes()
        require(len(data) == row['bytes'] and digest(data) == row['sha256'], 'postimage mismatch')
        prepared.append((target, old, data))
    return prepared

def tree_digest(root):
    names = git(root, 'ls-files', '-z').split(b'\0')
    names += git(root, 'ls-files', '--others', '--exclude-standard', '-z').split(b'\0')
    h = hashlib.sha256()
    for name in sorted(set(n for n in names if n)):
        text = name.decode('utf-8')
        h.update(name + b'\0' + bytes.fromhex(digest(safe_path(root, text).read_bytes())))
    return h.hexdigest()

def materialize(root, packet):
    require(not root.is_symlink() and not packet.is_symlink(), 'symlink root')
    root, packet = root.resolve(), packet.resolve()
    require(git(root, 'rev-parse', 'HEAD').decode().strip() == BASE, 'checkout mismatch')
    require(not git(root, 'status', '--porcelain', '--untracked-files=all'), 'dirty checkout')
    rows = verify_packet(packet)
    prepared = validate_preimages(root, packet, rows)
    try:
        for target, old, data in prepared:
            target.write_bytes(data)
        changed = set(git(root, 'diff', '--name-only', '-z').split(b'\0')) - {b''}
        changed |= set(git(root, 'ls-files', '--others', '--exclude-standard', '-z').split(b'\0')) - {b''}
        require(changed == {r['path'].encode() for r in rows}, 'unexpected tree change')
        for target, old, data in prepared:
            require(target.read_bytes() == data, 'post-write mismatch')
        return {'base': BASE, 'sealSha256': SEAL, 'manifestSha256': MANIFEST,
                'changedPaths': sorted(r['path'] for r in rows), 'treeSha256': tree_digest(root),
                'nativeExecuted': False}
    except BaseException as primary:
        failures = []
        for target, old, data in prepared:
            try:
                if old is None:
                    target.unlink(missing_ok=True)
                else:
                    target.write_bytes(old)
            except BaseException as failure:
                failures.append((str(target), failure))
        if failures:
            primary.rollback_failures = failures
            primary.add_note('Rollback failures retained: ' + ', '.join(path for path,_ in failures))
        raise

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, required=True)
    parser.add_argument('--packet', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(materialize(args.checkout, args.packet), sort_keys=True))
