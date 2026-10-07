"""Offline rejection controls; no SDK, systemd or Docker is started."""
import hashlib
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock
from unittest.mock import patch

import commerce_build_route as route


class BaselineControls(unittest.TestCase):
    def setUp(self):
        self.shared = types.SimpleNamespace(MAX_FILE_BYTES=1024,
            digest=lambda raw: hashlib.sha256(raw).hexdigest(),
            canonical_path=self.canonical)
        self.raw = b'committed\r\nraw\x00bytes'
        self.policy = {'baseFiles': [{'path': 'source.cs', 'bytes': len(self.raw),
                                     'sha256': self.shared.digest(self.raw)}]}

    @staticmethod
    def canonical(path):
        if path.startswith('/') or '..' in path.split('/'):
            raise ValueError('Unsafe archive path')
        return path

    def blob(self, raw=None, kind=b'blob', size=None):
        raw = self.raw if raw is None else raw
        size = len(raw) if size is None else size
        oid = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest().encode()
        return oid + b' ' + kind + b' ' + str(size).encode() + b'\n' + raw + b'\n'

    def test_committed_binary_and_line_endings_are_preserved(self):
        self.assertEqual({'source.cs': self.raw}, route.baseline_files(self.shared, self.blob(), self.policy))

    def test_modified_same_length_blob_rejected(self):
        with self.assertRaisesRegex(ValueError, 'seal differs'):
            route.baseline_files(self.shared, self.blob(b'x' * len(self.raw)), self.policy)

    def test_missing_baseline_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            route.baseline_files(self.shared, b'', self.policy)

    def test_duplicate_baseline_policy_rejected(self):
        self.policy['baseFiles'] *= 2
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            route.baseline_files(self.shared, self.blob() * 2, self.policy)

    def test_nonblob_object_rejected(self):
        with self.assertRaisesRegex(ValueError, 'not a blob'):
            route.baseline_files(self.shared, self.blob(kind=b'tree'), self.policy)

    def test_extra_object_rejected(self):
        with self.assertRaisesRegex(ValueError, 'extra'):
            route.baseline_files(self.shared, self.blob() * 2, self.policy)

    def test_traversal_policy_rejected(self):
        self.policy['baseFiles'][0]['path'] = '../source.cs'
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            route.baseline_files(self.shared, self.blob(), self.policy)

    def test_byte_count_rejected(self):
        with self.assertRaisesRegex(ValueError, 'byte count'):
            route.baseline_files(self.shared, self.blob(size=0), self.policy)


class PathControls(unittest.TestCase):
    def args(self, root):
        return types.SimpleNamespace(transport=root / 'transport', driver=root / 'driver.py',
            admission_verifier=root / 'verify.py', context=root / 'receipts/context.json',
            checkouts=root / 'checkouts', destination=root / 'candidate', receipts=root / 'receipts')

    def test_owned_context_may_be_inside_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            route.separate_paths(types.SimpleNamespace(reject_links=Mock()), self.args(Path(temporary)))

    def test_results_cannot_modify_transport(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.args(Path(temporary)); args.receipts = args.transport / 'results'
            with self.assertRaisesRegex(ValueError, 'overlap'):
                route.separate_paths(types.SimpleNamespace(reject_links=Mock()), args)

    def test_candidate_cannot_modify_original_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = self.args(Path(temporary)); args.destination = args.checkouts / 'candidate'
            with self.assertRaisesRegex(ValueError, 'overlap'):
                route.separate_paths(types.SimpleNamespace(reject_links=Mock()), args)

    def test_driver_tampering_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'driver.py'; path.write_bytes(b'raise AssertionError("executed")')
            with self.assertRaisesRegex(ValueError, 'reviewed'):
                route.driver_module(path)


class OwnerAdmissionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import socketserver
        # Windows import model only; no server or owner resource is started.
        if not hasattr(socketserver, 'UnixStreamServer'):
            socketserver.UnixStreamServer = socketserver.TCPServer
        import hosted_owner
        cls.owner = hosted_owner

    def rejected(self, arguments, message):
        prefix = ['owner', '--source', '/source', '--checkouts', '/checkouts',
                  '--receipt', '/receipt', '--coordinator-unit', 'not-allocated']
        with patch('sys.argv', prefix + arguments), patch.object(self.owner, 'properties') as observe:
            with self.assertRaisesRegex(ValueError, message):
                self.owner.main()
            observe.assert_not_called()

    def test_procurement_cannot_enter_existing_full_route(self):
        self.rejected(['--lane', 'procurement'], 'Full route')

    def test_auth_cannot_enter_commerce_build_route(self):
        self.rejected(['--lane', 'auth', '--stage', 'build'], 'fixed Commerce')

    def test_build_without_explicit_producers_is_rejected_before_owner_observation(self):
        self.rejected(['--lane', 'order', '--stage', 'build'], 'absolute producer')

    def test_full_route_rejects_build_producer_override(self):
        self.rejected(['--lane', 'accounting', '--commerce-driver', '/driver'], 'Full route')


if __name__ == '__main__':
    unittest.main()
