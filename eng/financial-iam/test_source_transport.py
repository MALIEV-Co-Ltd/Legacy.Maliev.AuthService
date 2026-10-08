"""Offline transport-envelope regressions; no candidate/native acceptance."""
from pathlib import Path
import unittest
from unittest.mock import patch

import verify_source_transport as transport


class TransportControls(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[2]
        self.original_read = transport.bounded_file

    def test_exact_reviewed_transport_and_raw_producers_are_preserved(self):
        result = transport.verify(self.root)
        self.assertEqual(24, result['sealedFiles'])
        self.assertEqual(7, result['decodedRawInputs'])
        self.assertFalse(result['candidateNativeAccepted'])
        self.assertEqual(0, result['nativeResourcesCreated'])

    def test_altered_policy_seal_is_rejected_before_source_loading(self):
        def read(path, maximum):
            content = self.original_read(path, maximum)
            return content + b' ' if path.name == 'source-transport-seal.json' else content
        with patch('verify_source_transport.bounded_file', side_effect=read), self.assertRaises(ValueError):
            transport.verify(self.root)

    def test_checkout_line_ending_repaint_is_rejected(self):
        def read(path, maximum):
            content = self.original_read(path, maximum)
            return content.replace(b'\n', b'\r\n') if path.name == 'Start-FinancialIamHostedOwner.ps1' else content
        with patch('verify_source_transport.bounded_file', side_effect=read), self.assertRaises(ValueError):
            transport.verify(self.root)

    def test_modified_raw_producer_encoding_is_rejected(self):
        def read(path, maximum):
            content = self.original_read(path, maximum)
            return b'AAAA' if path.name == 'accounting-catalogue.bytes.b64' else content
        with patch('verify_source_transport.bounded_file', side_effect=read), self.assertRaises(ValueError):
            transport.verify(self.root)

    def test_missing_source_never_claims_transport_success(self):
        with self.assertRaises(ValueError):
            transport.bounded_file(self.root / 'eng/financial-iam/absent-source-proof', 1024)


if __name__ == '__main__':
    unittest.main()
