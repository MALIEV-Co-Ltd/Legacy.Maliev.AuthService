"""Reject a stale native security toolchain without executing the SDK lane."""
import ast
from pathlib import Path
import unittest


def validate(raw):
    tree = ast.parse(raw)
    selections = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                        and target.value.id == 'env' and isinstance(target.slice, ast.Constant)
                        and target.slice.value == 'GOTOOLCHAIN'):
                    if not isinstance(node.value, ast.Constant):
                        raise ValueError('Literal native toolchain required')
                    selections.append(node.value.value)
    if selections != ['go1.26.9']:
        raise ValueError('Exact native security toolchain required')
    if raw.count(b'github.com/zricethezav/gitleaks/v8@6eaad039603a4de39fddd1cf5f727391efe9974e') != 1:
        raise ValueError('Original pinned Gitleaks source required')


class NativeToolchainControls(unittest.TestCase):
    def setUp(self):
        self.raw = Path(__file__).with_name('worker.py').read_bytes()

    def test_current_native_selector_passes(self):
        validate(self.raw)

    def test_old_native_selector_rejected(self):
        with self.assertRaises(ValueError):
            validate(self.raw.replace(b'go1.26.9', b'go1.26.8'))

    def test_changed_scanner_commit_rejected(self):
        with self.assertRaises(ValueError):
            validate(self.raw.replace(b'6eaad039603a4de39fddd1cf5f727391efe9974e', b'0' * 40))

    def test_dynamic_native_selector_rejected(self):
        with self.assertRaises(ValueError):
            validate(self.raw.replace(b"'go1.26.9'", b"os.environ['UNREVIEWED_GO']"))


if __name__ == '__main__':
    unittest.main()
