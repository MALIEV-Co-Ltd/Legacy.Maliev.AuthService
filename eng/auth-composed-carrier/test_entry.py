from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import entry

ROOT = Path(__file__).resolve().parents[2]
HEAD = 'a'*40
SOURCE = os.environ['AUTH_SOURCE_ROOT']
BASE_ATTRIBUTES = subprocess.check_output(['git', '-C', SOURCE, 'show', entry.BASE+':.gitattributes'], timeout=20)


def fixture_parent(platform=None, environment=None):
    platform = sys.platform if platform is None else platform
    environment = os.environ if environment is None else environment
    if platform == 'win32':
        candidate = Path('D:/codex-temp')
    elif platform == 'linux':
        value = environment.get('RUNNER_TEMP')
        candidate = Path(tempfile.gettempdir() if value is None else value)
    else:
        raise ValueError('Unsupported source-control platform')
    if (not candidate.is_absolute() or candidate.is_symlink()
            or (hasattr(candidate, 'is_junction') and candidate.is_junction())):
        raise ValueError('Physical absolute fixture parent required')
    parent = candidate.resolve(strict=True)
    if not parent.is_dir() or parent != candidate.absolute():
        raise ValueError('Existing physical fixture parent required')
    return parent


def copy_carrier(source, destination):
    raw = entry.read(source, 'eng/auth-composed-carrier/carrier-seal.json', 65536)
    if hashlib.sha256(raw).hexdigest() != entry.CARRIER:
        raise ValueError('Closed fixture carrier seal required')
    rows = json.loads(raw)['packetFiles']
    names = [row['path'] for row in rows]+sorted(entry.ADDITIONS)
    if len(rows) != 64 or len(set(names)) != 70:
        raise ValueError('Exactly 70 closed fixture inputs required')
    payloads = {}
    for name in names:
        path = PurePosixPath(name)
        if (path.is_absolute() or '\\' in name or ':' in name
                or path.as_posix() != name or any(part in ('', '.', '..', '.git') for part in name.split('/'))):
            raise ValueError('Canonical non-Git-control carrier path required')
        payloads[name] = entry.read(source, name, 1048576)
    for name, data in payloads.items():
        target = destination/name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


class PublicationGuards(unittest.TestCase):
    def environment(self):
        return {'GITHUB_SHA': HEAD, 'GITHUB_REPOSITORY': entry.REPOSITORY,
                'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
                'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_WORKFLOW_SHA': HEAD,
                'GITHUB_WORKFLOW_REF': entry.REPOSITORY+'/'+entry.WORKFLOW+'@refs/heads/main'}

    def verify(self, root=ROOT, environment=None, reader=None, changed=()):
        return entry.verify(root, environment or self.environment(),
                            reader or (lambda head, path: BASE_ATTRIBUTES if head == entry.BASE and path == '.gitattributes' else (ROOT/path).read_bytes()), changed)

    def test_actual_full_carrier(self):
        result = self.verify()
        self.assertEqual((result['carrierFiles'], result['applicationFiles']), (64, 43))
        self.assertFalse(result['nativeExecuted'])

    def test_wrong_ref_retry_and_workflow(self):
        for key, values in {'GITHUB_REF': ['refs/heads/release', 'refs/pull/1/merge', ''],
                            'GITHUB_RUN_ATTEMPT': ['2', '01', ''],
                            'GITHUB_WORKFLOW_SHA': ['b'*40],
                            'GITHUB_WORKFLOW_REF': [entry.REPOSITORY+'/old.yml@refs/heads/main']}.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    env = self.environment(); env[key] = value
                    with self.assertRaises(ValueError):
                        self.verify(environment=env)

    def test_git_object_mismatch(self):
        def reader(head, path):
            if head == entry.BASE and path == '.gitattributes':
                return BASE_ATTRIBUTES
            raw = (ROOT/path).read_bytes()
            return raw+b'changed' if path.endswith('/worker.py') else raw
        with self.assertRaisesRegex(ValueError, 'published raw'):
            self.verify(reader=reader)

    def test_unrelated_publication_change(self):
        with self.assertRaisesRegex(ValueError, 'unrelated'):
            self.verify(changed=['Legacy.Maliev.AuthService.Api/Program.cs'])

    def test_missing_mutated_and_predecessor_carrier(self):
        with tempfile.TemporaryDirectory(prefix='auth-carrier-source-') as directory:
            clone = Path(directory)/'source'
            clone.mkdir()
            copy_carrier(ROOT, clone)
            path = clone/'eng/customer-self-identity-validation/worker.py'
            original = path.read_bytes()
            path.write_bytes(original+b'changed')
            with self.assertRaises(ValueError):
                self.verify(root=clone)
            path.unlink()
            with self.assertRaises(FileNotFoundError):
                self.verify(root=clone)
            path.write_bytes(original)
            seal = clone/'eng/auth-composed-carrier/carrier-seal.json'
            seal.write_bytes(b'{"packetFiles":[{},{}]}')
            with self.assertRaisesRegex(ValueError, 'outer seal'):
                self.verify(root=clone)
        self.assertFalse(clone.exists())

    def test_actual_disposable_git_publication(self):
        parent = fixture_parent()
        fixture = Path(tempfile.mkdtemp(prefix='wf-auth-pub-', dir=parent)).resolve()
        self.assertEqual(fixture.parent, parent)
        root = fixture/'candidate'
        def git(*args):
            return subprocess.check_output(['git', '-C', str(root), *args], timeout=30)
        try:
            subprocess.run(['git', 'clone', '--shared', '--no-checkout', SOURCE, str(root)],
                           check=True, capture_output=True, timeout=30)
            git('-c', 'core.autocrlf=false', 'checkout', '--detach', entry.BASE)
            source = fixture/'full-checkout-source'
            source.mkdir()
            copy_carrier(ROOT, source)
            (source/'.git').mkdir()
            (source/'.git/foreign-control-sentinel').write_bytes(b'foreign-Git-control')
            (source/'unrelated-source-file.txt').write_bytes(b'foreign-source')
            git_head = (root/'.git/HEAD').read_bytes()
            git_config = (root/'.git/config').read_bytes()
            copy_carrier(source, root)
            self.assertFalse((root/'.git/foreign-control-sentinel').exists())
            self.assertFalse((root/'unrelated-source-file.txt').exists())
            self.assertEqual((root/'.git/HEAD').read_bytes(), git_head)
            self.assertEqual((root/'.git/config').read_bytes(), git_config)
            self.assertEqual(git('rev-parse', 'HEAD').decode().strip(), entry.BASE)
            git('-c', 'core.autocrlf=false', 'add', '--', '.gitattributes', '.github/workflows',
                'eng/auth-composed-carrier', 'eng/customer-self-identity-validation',
                'eng/customer-self-identity-intake/auth-composed-source-v1-20261010')
            git('-c', 'user.name=SourceControl', '-c', 'user.email=source-control@example.invalid',
                'commit', '-m', 'Synthetic infrastructure publication source control')
            head = git('rev-parse', 'HEAD').decode().strip()
            environment = self.environment()
            environment.update(GITHUB_SHA=head, GITHUB_WORKFLOW_SHA=head)
            changed = list(filter(None, git('diff', '--name-only', '-z', entry.BASE, head).decode().split('\0')))
            result = self.verify(root, environment, lambda revision, path: git('cat-file', 'blob', revision+':'+path), changed)
            self.assertEqual(result['carrierFiles'], 64)
            self.assertEqual(git('status', '--porcelain', '--untracked-files=all'), b'')
            git('merge-base', '--is-ancestor', entry.BASE, head)
        finally:
            if fixture.parent != parent or fixture.is_symlink():
                raise RuntimeError('Disposable publication cleanup ownership differs')
            def remove_readonly(function, filename, error):
                target = Path(filename)
                if (not isinstance(error, PermissionError) or target.is_symlink()
                        or not target.resolve().is_relative_to(fixture)
                        or target.stat().st_nlink != 1 or not target.is_file()):
                    raise error
                target.chmod(stat.S_IWRITE | stat.S_IREAD)
                function(filename)
            shutil.rmtree(fixture, onexc=remove_readonly)
            self.assertFalse(fixture.exists())

    def test_linux_fixture_selection_runner_and_fallback(self):
        with tempfile.TemporaryDirectory(prefix='fixture-selection-') as directory:
            parent = Path(directory).resolve()
            self.assertEqual(fixture_parent('linux', {'RUNNER_TEMP': str(parent)}), parent)
            with patch.object(tempfile, 'gettempdir', return_value=str(parent)):
                self.assertEqual(fixture_parent('linux', {}), parent)

    def test_linux_fixture_selection_refuses_invalid_parents(self):
        with tempfile.TemporaryDirectory(prefix='fixture-selection-') as directory:
            parent = Path(directory).resolve()
            ordinary = parent/'ordinary-file'
            ordinary.write_bytes(b'source-control')
            for value in ('', 'relative-parent', str(parent/'missing'), str(ordinary)):
                with self.subTest(value=value):
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        fixture_parent('linux', {'RUNNER_TEMP': value})


if __name__ == '__main__':
    unittest.main(verbosity=2)
