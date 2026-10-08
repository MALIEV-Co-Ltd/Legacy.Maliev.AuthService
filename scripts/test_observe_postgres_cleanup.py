"""Pure privacy/boundary controls: no SDK, daemon, subprocess or socket allocation."""
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock
import observe_postgres_cleanup as observation

IDENTIFIER = 'a' * 64
PRIVATE = 'password SQL customer@example.invalid private-payload'


def document():
    return {'Id': IDENTIFIER, 'Config': {'Image': observation.IMAGE,
            'Env': [PRIVATE], 'Labels': {'private': PRIVATE}},
            'State': {'Pid': 123, 'ExitCode': 0, 'Running': False,
                      'Dead': False, 'OOMKilled': False, 'Error': PRIVATE},
            'HostConfig': {'Memory': 0, 'NanoCpus': 0, 'PidsLimit': None},
            'Mounts': [{'Type': 'volume', 'Name': 'b' * 64, 'Source': PRIVATE}]}


def event(identifier=IDENTIFIER, action='die'):
    return {'Type': 'container', 'Action': action, 'timeNano': 100,
            'Actor': {'ID': identifier, 'Attributes': {'image': observation.IMAGE,
                       'exitCode': '0', 'private': PRIVATE}}}


class Controls(unittest.TestCase):
    def test_container_omits_private_values_and_never_certifies_ownership(self):
        result = observation.container(document())
        self.assertNotIn(PRIVATE, json.dumps(result))
        self.assertFalse(result['authenticatedTaskOwnership'])
        self.assertTrue(result['persistentDataUnknown'])
        self.assertNotIn('PidsLimit', result['numeric'])

    def test_wrong_image_rejected(self):
        value = document()
        value['Config']['Image'] = 'foreign'
        with self.assertRaises(ValueError):
            observation.container(value)

    def test_boolean_numeric_rejected(self):
        value = document()
        value['State']['Pid'] = True
        with self.assertRaises(ValueError):
            observation.container(value)

    def test_private_volume_name_rejected(self):
        value = document()
        value['Mounts'][0]['Name'] = PRIVATE
        with self.assertRaises(ValueError):
            observation.container(value)

    def test_events_exclude_baseline_and_foreign_images(self):
        foreign = event('b' * 64)
        foreign['Actor']['Attributes']['image'] = 'foreign'
        self.assertEqual(([], set()), observation.events([event(), foreign], {IDENTIFIER}))

    def test_event_projection_omits_private_fields(self):
        rows, identifiers = observation.events([event()], set())
        self.assertEqual({IDENTIFIER}, identifiers)
        self.assertNotIn(PRIVATE, json.dumps(rows))

    def test_event_and_container_count_bounds(self):
        with self.assertRaises(ValueError):
            observation.events([event()] * 257, set())
        with self.assertRaises(ValueError):
            observation.events([event(f'{index:064x}') for index in range(17)], set())

    def test_private_signal_rejected(self):
        value = event()
        value['Actor']['Attributes']['signal'] = PRIVATE
        with self.assertRaises(ValueError):
            observation.events([value], set())

    def test_invalid_context_rejects_before_any_query(self):
        query = Mock()
        with self.assertRaises(ValueError):
            observation.observe('before', Path('unused'), {}, query)
        query.assert_not_called()

    def test_receipt_is_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            observation.write(path, 'before.json', {'a': 1})
            with self.assertRaises(FileExistsError):
                observation.write(path, 'before.json', {'a': 2})
            self.assertEqual({'a': 1}, json.loads((path / 'before.json').read_bytes()))

    def test_linked_destination_rejected(self):
        with patch.object(Path, 'is_symlink', return_value=True):
            with self.assertRaises(ValueError):
                observation.write(Path('unused'), 'before.json', {})

    def run_observation(self, directory, role, query, identity=None):
        original = Path.stat
        with patch.object(observation, 'context', return_value=identity or {'run': '1'}), \
                patch.object(Path, 'stat', autospec=True) as info, \
                patch.object(observation.time, 'time', return_value=100):
            # Only the socket stat is substituted; receipts use actual filesystem metadata.
            info.side_effect = lambda path, **kwargs: (SimpleNamespace(st_mode=stat.S_IFSOCK,
                st_dev=1, st_ino=2) if path.as_posix() == '/var/run/docker.sock' else
                original(path, **kwargs))
            return observation.observe(role, directory, {}, query)

    def test_baseline_and_absence_receipt_do_not_claim_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipts'
            before = self.run_observation(path, 'before', Mock(side_effect=[
                (200, {'ID': 'engine'}), (200, [])]))
            self.assertTrue(before['observationComplete'])
            after = self.run_observation(path, 'after', Mock(side_effect=[
                (200, {'ID': 'engine'}), (200, [event()]), (404, None)]))
            self.assertTrue(after['observationComplete'])
            self.assertTrue(after['containers'][0]['absenceVerified'])
            self.assertFalse(after['resourcesDeleted'])
            self.assertFalse(after['nativeAccepted'])
            self.assertEqual('unknown', after['cancelledOperation'])
            self.assertNotIn(PRIVATE, json.dumps(after))

    def test_generation_mismatch_rejects_before_events(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipts'
            self.run_observation(path, 'before', Mock(side_effect=[
                (200, {'ID': 'engine'}), (200, [])]))
            query = Mock(return_value=(200, {'ID': 'engine'}))
            result = self.run_observation(path, 'after', query, {'run': '2'})
            self.assertFalse(result['observationComplete'])
            self.assertEqual(1, query.call_count)

    def test_inspect_response_must_match_requested_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipts'
            self.run_observation(path, 'before', Mock(side_effect=[
                (200, {'ID': 'engine'}), (200, [])]))
            wrong = document()
            wrong['Id'] = 'c' * 64
            result = self.run_observation(path, 'after', Mock(side_effect=[
                (200, {'ID': 'engine'}), (200, [event()]), (200, wrong)]))
            self.assertFalse(result['observationComplete'])
            self.assertNotIn('containers', result)

    def test_process_deadline_covers_entire_observation_and_is_disarmed(self):
        with patch('sys.argv', ['observer', '--role', 'before', '--directory', 'unused']), \
                patch.object(observation.signal, 'SIGALRM', 14, create=True), \
                patch.object(observation.signal, 'ITIMER_REAL', 0, create=True), \
                patch.object(observation.signal, 'signal', return_value='previous') as handler, \
                patch.object(observation.signal, 'setitimer', create=True) as timer, \
                patch.object(observation, 'observe') as observe:
            def invoke(*_args):
                timer.assert_called_once_with(0, 20)
                callback = handler.call_args_list[0].args[1]
                with self.assertRaises(TimeoutError):
                    callback(14, None)
            observe.side_effect = invoke
            observation.main()
            self.assertEqual([(0, 20), (0, 0)], [call.args for call in timer.call_args_list])
            self.assertEqual((14, 'previous'), handler.call_args.args)

    def test_deadline_failure_writes_typed_unavailable_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_observation(Path(directory) / 'receipts', 'before',
                Mock(side_effect=TimeoutError(PRIVATE)))
            self.assertFalse(result['observationComplete'])
            self.assertEqual(['TimeoutError'], result['diagnosticErrors'])
            self.assertNotIn(PRIVATE, json.dumps(result))

    def test_failure_message_is_never_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_observation(Path(directory) / 'receipts', 'before',
                Mock(side_effect=ValueError(PRIVATE)))
            self.assertFalse(result['observationComplete'])
            self.assertEqual(['ValueError'], result['diagnosticErrors'])
            self.assertNotIn(PRIVATE, json.dumps(result))

    def test_rpc_rejects_mutating_route_before_connection(self):
        with patch.object(observation, 'UnixConnection') as connection:
            with self.assertRaises(ValueError):
                observation.rpc('/containers/id/kill', observation.time.monotonic() + 20)
            connection.assert_not_called()

    def test_rpc_byte_bound_and_finally_close(self):
        connection = Mock()
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.read1.return_value = b'x' * 11
        with patch.object(observation, 'UnixConnection', return_value=connection), \
                patch.object(observation, 'MAX_BYTES', 10):
            with self.assertRaises(ValueError):
                observation.rpc('/info', observation.time.monotonic() + 20)
        connection.close.assert_called_once()

    def test_rpc_deadline_rejects_before_connection(self):
        with patch.object(observation, 'UnixConnection') as connection:
            with self.assertRaises(TimeoutError):
                observation.rpc('/info', observation.time.monotonic() - 1)
            connection.assert_not_called()

    def test_rpc_404_absence_is_distinct(self):
        connection = Mock()
        connection.getresponse.return_value.status = 404
        connection.getresponse.return_value.read1.return_value = b''
        with patch.object(observation, 'UnixConnection', return_value=connection):
            self.assertEqual((404, None), observation.rpc('/containers/' + IDENTIFIER + '/json',
                             observation.time.monotonic() + 20))
        connection.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
