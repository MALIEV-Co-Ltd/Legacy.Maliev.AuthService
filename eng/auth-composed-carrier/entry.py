"""Closed Auth43 publication guard; existing admission/caller remain authoritative."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

BASE = '2bd6a61bfce1d19310209c0d00b56d92f0abea91'
CARRIER = 'df834deb68488bc59f58ef2668bced3a61529c02a88d5bb0741ef1980058c4c5'
REPOSITORY = 'MALIEV-Co-Ltd/Legacy.Maliev.AuthService'
WORKFLOW = '.github/workflows/auth-composed-carrier-validation.yml'
ADDITIONS = {WORKFLOW, 'eng/auth-composed-carrier/entry.py',
             'eng/auth-composed-carrier/test_entry.py', 'eng/auth-composed-carrier/carrier-seal.json', '.gitattributes',
             'eng/customer-self-identity-validation/test_native_toolchain.py'}


def read(root, relative, maximum):
    target = root/relative
    for node in (target, *target.parents):
        if node == root.parent:
            break
        if node.is_symlink() or (hasattr(node, 'is_junction') and node.is_junction()):
            raise ValueError('Linked carrier path')
    row = target.lstat()
    if not stat.S_ISREG(row.st_mode) or row.st_nlink != 1 or row.st_size > maximum:
        raise ValueError('Regular bounded carrier file required')
    with target.open('rb') as stream:
        raw = stream.read(maximum+1)
    if len(raw) > maximum:
        raise ValueError('Carrier read exceeded bound')
    return raw


def context(environment):
    head = environment.get('GITHUB_SHA', '')
    if (len(head) != 40 or any(c not in '0123456789abcdef' for c in head)
            or environment.get('GITHUB_REPOSITORY') != REPOSITORY
            or environment.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
            or environment.get('GITHUB_REF') != 'refs/heads/main'
            or environment.get('GITHUB_RUN_ATTEMPT') != '1'
            or environment.get('GITHUB_WORKFLOW_SHA') != head
            or environment.get('GITHUB_WORKFLOW_REF') != REPOSITORY+'/'+WORKFLOW+'@refs/heads/main'):
        raise ValueError('Exact protected Auth carrier workflow first attempt required')
    return head


def verify(root, environment, git_object, changed_paths):
    root = Path(root).resolve(strict=True)
    head = context(environment)
    seal_path = 'eng/auth-composed-carrier/carrier-seal.json'
    raw = read(root, seal_path, 65536)
    if hashlib.sha256(raw).hexdigest() != CARRIER or git_object(head, seal_path) != raw:
        raise ValueError('Exact independently reviewed Auth43 outer seal required')
    # Exact raw hash binds schema, owner, base, ordered inventory and every pin.
    seal = json.loads(raw)
    rows = seal['packetFiles']
    if seal['base'] != BASE or len(rows) != 64:
        raise ValueError('Complete reviewed 64-file carrier required')
    allowed = {row['path'] for row in rows} | ADDITIONS
    if set(changed_paths) - allowed:
        raise ValueError('Publication changed unrelated Auth source')
    attributes = read(root, '.gitattributes', 65536)
    if attributes != git_object(BASE, '.gitattributes')+b'\neng/auth-composed-carrier/** -text\n':
        raise ValueError('Only the closed carrier raw-byte attributes addition is allowed')
    for row in rows:
        current = read(root, row['path'], row['bytes'])
        if (len(current) != row['bytes'] or hashlib.sha256(current).hexdigest() != row['sha256']
                or git_object(head, row['path']) != current):
            raise ValueError('Auth43 published raw carrier differs: '+row['path'])
    for path in ADDITIONS:
        current = read(root, path, 1048576)
        if git_object(head, path) != current:
            raise ValueError('Infrastructure entry differs from published Git object')
    return {'base': BASE, 'sourceCommit': head, 'carrierSealSha256': CARRIER,
            'carrierFiles': 64, 'applicationFiles': 43, 'nativeExecuted': False}


def main():
    root = Path.cwd()
    head = context(os.environ)
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], timeout=30)
    if git('rev-parse', 'HEAD').decode().strip() != head:
        raise ValueError('Actual workflow checkout differs')
    subprocess.run(['git', '-C', str(root), 'merge-base', '--is-ancestor', BASE, head],
                   check=True, timeout=30)
    if git('status', '--porcelain', '--untracked-files=all'):
        raise ValueError('Clean protected infrastructure checkout required')
    changed = list(filter(None, git('diff', '--name-only', '-z', BASE, head).decode().split('\0')))
    result = verify(root, os.environ, lambda revision, path: git('cat-file', 'blob', revision+':'+path), changed)
    print(json.dumps(result, sort_keys=True))
    # Retain the reviewed request, source seal, 4GiB and original caller gates.
    sys.path.insert(0, str(root/'eng/customer-self-identity-validation'))
    import admission
    admission.main()


if __name__ == '__main__':
    main()
