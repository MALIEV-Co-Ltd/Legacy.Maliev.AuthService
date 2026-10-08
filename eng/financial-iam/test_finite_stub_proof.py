"""Pure failure-fence controls; these never qualify a live Linux proof."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import finite_stub_proof as proof
import hosted_owner


class StubProofControls(unittest.TestCase):
    def fixture(self, path):
        run = 'auth-financial-123-1-012345abcdef'
        group = '/owned/' + run + '-sdk.service'
        caps = {'memory.max': str(128 * 1024 ** 2), 'memory.swap.max': '0',
                'cpu.max': '100000 100000', 'pids.max': '512'}
        current = dict(pid=100, startTicks='101', executable='/usr/bin/python3.12', bootId='boot', cgroup='0::' + group)
        cases = []
        for index, (case, failure, code) in enumerate(zip(proof.CASES, proof.EXPECTED_FAILURES, (0, -15, -15, -15, 7))):
            child = dict(current, pid=200 + index, startTicks=str(300 + index))
            cases.append(dict(case=case, firstFailure=failure, exitCode=code, identity=child, caps=caps,
                              exited=True, readersClosed=True, handleClosed=True, cleanupErrors=[], retainedPidfd=13))
        container = dict(id='a' * 64, imageId='sha256:' + 'b' * 64, created='time', memory=67108864,
                         nanoCpus=100000000, cgroupParent='owned.slice', mounts=[], running=False, absenceVerified=True)
        recorded = dict(container, labels={'codex.hosted-owner': proof.OWNER, 'codex.hosted-run': run})
        context = dict(schemaVersion=3, owner=run, sdkCgroup=group, dockerCgroupParent='owned.slice')
        units = {run + '-sdk.service': dict(mainProcess=dict(pid=100, startTicks='101', executable=current['executable'],
                                                            cgroup=group), exitCode='7', result='exit-code')}
        for index, suffix in enumerate(('daemon', 'proxy')):
            units[run + '-' + suffix + '.service'] = dict(mainProcess=dict(pid=400 + index, startTicks='501', cgroup='/endpoint/' + suffix))
            prefix = 'docker' + suffix.title()
            context.update({prefix + 'Pid': 400 + index, prefix + 'StartTicks': '501', prefix + 'Cgroup': '/endpoint/' + suffix})
        rows = {
            'launcher.json': dict(run=run, stage='proof', nativeAccepted=False, failures=['RuntimeException']),
            'resources/stub-proof.json': dict(owner=run, identity=current, caps=caps, sdkStarted=False, nativeAccepted=False,
                containerProcessStarted=False, cases=cases, expectedProxyRejections=3, createdContainer=container,
                workloadProofPassed=True, expectedOwnedWorkloadExit=7),
            'resources/external-cleanup.json': dict(remainingResources=0, sdkQuiescent=True, containersAbsent=True,
                originalQualificationFailuresRetained=['RuntimeError:Owned phase failed', 'PrivateDockerAdmissionFailureRetained']),
            'resources/containers.json': dict(failures=['ValueError'] * 4, containers={container['id']: recorded}, finalInventoryEmpty=True),
            'resources/stub-foreign-peer.json': dict(run=run, rejected=True, status=503),
            'resources/units.json': dict(run=run, units=units),
            'resources/native-context.json': context,
        }
        return rows

    def metadata_result(self, mutate=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'resources').mkdir()
            rows = self.fixture(path)
            if mutate:
                mutate(rows)
            for name, row in rows.items():
                (path / name).write_text(json.dumps(row))
            original = Path.read_text
            with patch.object(Path, 'read_text', lambda item: 'boot' if str(item).replace('\\', '/') == '/proc/sys/kernel/random/boot_id' else original(item)):
                return proof.validate_readback(path)

    def test_complete_metadata_fixture_preserves_no_sdk_and_no_native_acceptance(self):
        row = self.metadata_result()
        self.assertFalse(row['sdkStarted'])
        self.assertFalse(row['nativeAccepted'])
        self.assertEqual(5, row['cases'])

    def test_unexpected_proxy_failure_cannot_be_waived(self):
        with self.assertRaises(RuntimeError):
            self.metadata_result(lambda rows: rows['resources/containers.json']['failures'].append('TimeoutError'))

    def test_wrong_owned_phase_exit_cannot_qualify_cleanup(self):
        def alter(rows):
            for name, row in rows['resources/units.json']['units'].items():
                if name.endswith('-sdk.service'):
                    row['exitCode'] = '0'
        with self.assertRaises(RuntimeError):
            self.metadata_result(alter)

    def test_reused_child_generation_is_rejected(self):
        def alter(rows):
            cases = rows['resources/stub-proof.json']['cases']
            cases[1]['identity'] = dict(cases[0]['identity'])
        with self.assertRaises(RuntimeError):
            self.metadata_result(alter)

    def test_child_first_failure_must_survive_readback(self):
        with self.assertRaises(RuntimeError):
            self.metadata_result(lambda rows: rows['resources/stub-proof.json']['cases'][-1].update(firstFailure=None))

    def test_missing_independent_container_absence_is_rejected(self):
        def alter(rows):
            next(iter(rows['resources/containers.json']['containers'].values()))['absenceVerified'] = False
        with self.assertRaises(RuntimeError):
            self.metadata_result(alter)

    def test_foreign_proxy_generation_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.metadata_result(lambda rows: rows['resources/native-context.json'].update(dockerProxyStartTicks='999'))

    def test_foreign_container_labels_are_rejected(self):
        def alter(rows):
            next(iter(rows['resources/containers.json']['containers'].values()))['labels']['codex.hosted-run'] = 'foreign'
        with self.assertRaises(RuntimeError):
            self.metadata_result(alter)

    def test_cleanup_error_cannot_hide_in_apparent_child_success(self):
        with self.assertRaises(RuntimeError):
            self.metadata_result(lambda rows: rows['resources/stub-proof.json']['cases'][0]['cleanupErrors'].append({'phase': 'term', 'type': 'OSError'}))

    def child_failure(self, acquisition='birth', final_write_failure=False, close_failure=False, timeout_after_term=False, body_error=None):
        # Execute the real child_case control flow with retained synthetic handles.
        # No Linux process or descriptor is created by these fault injections.
        process = Mock(pid=777, returncode=None, stdout=io.BytesIO())
        process.poll.return_value = None
        waits = []
        def wait(timeout):
            waits.append(timeout)
            if timeout_after_term and len(waits) == 1:
                raise proof.subprocess.TimeoutExpired('retained child', timeout)
            process.returncode = -15
            return -15
        process.wait.side_effect = wait
        process.terminate.side_effect = RuntimeError('TERM failed')
        initial = body_error or (ValueError('birth failed') if acquisition == 'birth' else OSError('acquisition failed'))
        pidfd = Mock(side_effect=initial) if acquisition == 'pidfd' else Mock(return_value=123)
        birth = Mock(side_effect=initial) if acquisition == 'birth' else Mock(return_value={'cgroup': '0::/owned'})
        writes = []
        def persist(path, row):
            writes.append(dict(row))
            if acquisition == 'receipt' and len(writes) == 1:
                raise initial
            if final_write_failure:
                raise OSError('final write failed')
        def send(descriptor, sig):
            if sig == proof.signal.SIGTERM:
                raise RuntimeError('TERM failed')
        with patch.object(proof.subprocess, 'Popen', return_value=process) as spawn, \
                patch.object(proof.os, 'pidfd_open', pidfd, create=True), \
                patch.object(proof.signal, 'SIGKILL', 9, create=True), \
                patch.object(proof.signal, 'pidfd_send_signal', side_effect=send, create=True) as signals, \
                patch.object(proof.os, 'close', side_effect=OSError('close failed') if close_failure else None) as close, \
                patch.object(proof, 'identity', birth), patch.object(proof, 'check_caps', return_value={}), \
                patch.object(proof, 'save', side_effect=persist), self.assertRaises(type(initial)) as caught:
            proof.child_case('normal', '0::/owned', Path('unused'))
        self.assertIs(initial, caught.exception)
        spawn.assert_called_once()
        self.assertEqual(2 if timeout_after_term else 1, process.wait.call_count)
        if timeout_after_term:
            self.assertEqual((123, 9), signals.call_args.args)
        self.assertTrue(process.stdout.closed)
        if acquisition == 'pidfd':
            close.assert_not_called()
        else:
            close.assert_called_once_with(123)
        self.assertEqual(type(initial).__name__, writes[-1]['firstErrorType'])
        self.assertTrue(writes[-1]['exited'])
        return writes[-1]

    def test_birth_error_then_failed_term_still_waits_and_closes_same_handles(self):
        row = self.child_failure()
        self.assertTrue(row['readersClosed'])
        self.assertTrue(row['handleClosed'])
        self.assertEqual('term', row['cleanupErrors'][0]['phase'])

    def test_initial_receipt_error_then_failed_term_preserves_first_error(self):
        self.child_failure(acquisition='receipt')

    def test_pidfd_acquisition_error_still_settles_retained_popen_and_reader(self):
        row = self.child_failure(acquisition='pidfd')
        self.assertFalse(row['handleClosed'])

    def test_pidfd_close_failure_retains_birth_error_and_unclosed_handle_evidence(self):
        row = self.child_failure(close_failure=True)
        self.assertFalse(row['handleClosed'])
        self.assertEqual('pidfd-close', row['cleanupErrors'][-1]['phase'])

    def test_child_final_receipt_failure_does_not_mask_birth_error(self):
        self.child_failure(final_write_failure=True)

    def test_failed_term_then_wait_timeout_kills_same_pidfd_and_retains_birth_error(self):
        row = self.child_failure(timeout_after_term=True)
        self.assertEqual(['term', 'wait-after-term'], [item['phase'] for item in row['cleanupErrors']])

    def test_body_keyboard_interrupt_still_waits_and_closes_same_handles(self):
        self.child_failure(body_error=KeyboardInterrupt())

    def test_final_readback_write_failure_does_not_mask_validation_error(self):
        first = ValueError('validation failed')
        with patch.object(proof, 'validate_readback', side_effect=first), \
                patch.object(proof, 'physical_cleanup', return_value={'remainingResources': 0}) as cleanup, \
                patch.object(proof, 'save', side_effect=OSError('save failed')) as persist, self.assertRaises(RuntimeError) as caught:
            proof.readback(Path('unused'))
        self.assertIs(first, caught.exception.__cause__)
        cleanup.assert_called_once()
        self.assertEqual('ValueError', persist.call_args.args[1]['firstFailure'])

    def test_final_readback_write_failure_does_not_mask_cleanup_error(self):
        first = OSError('cleanup failed')
        with patch.object(proof, 'validate_readback', return_value={'lifecycleProofAccepted': True}), \
                patch.object(proof, 'physical_cleanup', side_effect=first), \
                patch.object(proof, 'save', side_effect=ValueError('save failed')), self.assertRaises(RuntimeError) as caught:
            proof.readback(Path('unused'))
        self.assertIs(first, caught.exception.__cause__)

    def test_final_receipt_failure_alone_invalidates_readback_success(self):
        first = OSError('save failed')
        with patch.object(proof, 'validate_readback', return_value={'lifecycleProofAccepted': True}), \
                patch.object(proof, 'physical_cleanup', return_value={'remainingResources': 0}), \
                patch.object(proof, 'save', side_effect=first) as persist, self.assertRaises(RuntimeError) as caught:
            proof.readback(Path('unused'))
        self.assertIs(first, caught.exception.__cause__)
        self.assertFalse(persist.call_args.args[1]['lifecycleProofAccepted'])

    def test_inactive_collected_unit_never_receives_reset_failed(self):
        def manager(argv):
            if argv[1] == 'show': return 'inactive\n'
            raise RuntimeError('Exact inactive unit already collected')
        with patch.object(hosted_owner, 'command', side_effect=manager) as call:
            proof.reset_failed_terminal_unit('owned.slice')
        call.assert_called_once_with(['/usr/bin/systemctl', 'show', 'owned.slice', '--property=ActiveState', '--value'])

    def test_retained_failed_unit_is_reset_by_exact_name(self):
        with patch.object(hosted_owner, 'command', side_effect=['failed\n', '']) as call:
            proof.reset_failed_terminal_unit('owned.service')
        self.assertEqual(['/usr/bin/systemctl', 'reset-failed', 'owned.service'], call.call_args.args[0])

    def test_failed_unit_reset_error_remains_fatal(self):
        first = RuntimeError('Manager reset failure')
        with patch.object(hosted_owner, 'command', side_effect=['failed\n', first]), self.assertRaises(RuntimeError) as caught:
            proof.reset_failed_terminal_unit('owned.service')
        self.assertIs(first, caught.exception)

    def test_nonterminal_or_unknown_manager_state_fences_cleanup(self):
        for state in ('active', 'activating', '', 'foreign'):
            with self.subTest(state=state), patch.object(hosted_owner, 'command', return_value=state) as call, self.assertRaises(RuntimeError):
                proof.reset_failed_terminal_unit('owned.service')
            self.assertEqual(1, call.call_count)

    def test_terminal_state_query_failure_remains_fatal(self):
        first = RuntimeError('Manager observation failure')
        with patch.object(hosted_owner, 'command', side_effect=first), self.assertRaises(RuntimeError) as caught:
            proof.reset_failed_terminal_unit('owned.service')
        self.assertIs(first, caught.exception)

    def test_unknown_child_case_cannot_spawn(self):
        with patch.object(proof.subprocess, 'Popen') as spawn, self.assertRaises(ValueError):
            proof.child_case('sdk', '0::/foreign', Path('unused'))
        spawn.assert_not_called()

    def test_caps_reject_swap_before_child_work(self):
        rows = {'memory.max': str(128 * 1024 ** 2), 'memory.swap.max': '1',
                'cpu.max': '100000 100000', 'pids.max': '512'}
        with patch.object(Path, 'read_text', lambda path: rows[path.name]), self.assertRaises(RuntimeError):
            proof.check_caps('0::/owned')

    def test_caps_reject_uncapped_tasks(self):
        rows = {'memory.max': str(128 * 1024 ** 2), 'memory.swap.max': '0',
                'cpu.max': '100000 100000', 'pids.max': 'max'}
        with patch.object(Path, 'read_text', lambda path: rows[path.name]), self.assertRaises(RuntimeError):
            proof.check_caps('0::/owned')

    def test_actual_cap_shape_is_frozen(self):
        rows = {'memory.max': str(128 * 1024 ** 2), 'memory.swap.max': '0',
                'cpu.max': '100000 100000', 'pids.max': '512'}
        with patch.object(Path, 'read_text', lambda path: rows[path.name]):
            self.assertEqual(rows, proof.check_caps('0::/owned'))

    def test_proof_rejects_commerce_input_before_manager_observation(self):
        argv = ['hosted_owner.py', '--source', '/unused', '--checkouts', '/unused', '--receipt', '/unused',
                '--coordinator-unit', 'unused', '--lane', 'auth', '--stage', 'proof', '--commerce-driver', '/driver']
        with patch('sys.argv', argv), patch.object(hosted_owner, 'properties') as manager, self.assertRaises(ValueError):
            hosted_owner.main()
        manager.assert_not_called()

    def test_proof_rejects_commerce_lane_before_manager_observation(self):
        argv = ['hosted_owner.py', '--source', '/unused', '--checkouts', '/unused', '--receipt', '/unused',
                '--coordinator-unit', 'unused', '--lane', 'order', '--stage', 'proof']
        with patch('sys.argv', argv), patch.object(hosted_owner, 'properties') as manager, self.assertRaises(ValueError):
            hosted_owner.main()
        manager.assert_not_called()

    def test_validation_failure_still_attempts_physical_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with patch.object(proof, 'validate_readback', side_effect=ValueError('synthetic')), \
                    patch.object(proof, 'physical_cleanup', return_value={'remainingResources': 0}) as cleanup, \
                    self.assertRaises(RuntimeError):
                proof.readback(path)
            cleanup.assert_called_once_with(path)
            row = json.loads((path / 'stub-lifecycle-readback.json').read_text())
            self.assertEqual('ValueError', row['firstFailure'])
            self.assertFalse(row['lifecycleProofAccepted'])
            self.assertFalse(row['sdkStarted'])

    def test_cleanup_failure_does_not_erase_first_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with patch.object(proof, 'validate_readback', side_effect=ValueError('first')), \
                    patch.object(proof, 'physical_cleanup', side_effect=OSError('second')), self.assertRaises(RuntimeError):
                proof.readback(path)
            row = json.loads((path / 'stub-lifecycle-readback.json').read_text())
            self.assertEqual('ValueError', row['firstFailure'])
            self.assertEqual('OSError', row['cleanupFailure'])

    def test_cleanup_failure_invalidates_apparent_proof_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with patch.object(proof, 'validate_readback', return_value={'lifecycleProofAccepted': True}), \
                    patch.object(proof, 'physical_cleanup', side_effect=OSError()), self.assertRaises(RuntimeError):
                proof.readback(path)
            self.assertFalse(json.loads((path / 'stub-lifecycle-readback.json').read_text())['lifecycleProofAccepted'])

    def test_foreign_run_cannot_inspect_or_remove_manager_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'resources').mkdir()
            for name, row in [('launcher.json', {'run': 'foreign', 'stage': 'proof', 'lane': 'auth'}),
                              ('resources/units.json', {'run': 'foreign'}),
                              ('resources/external-cleanup.json', {'remainingResources': 0})]:
                (path / name).write_text(json.dumps(row))
            with patch.object(hosted_owner, 'properties') as manager, self.assertRaises(RuntimeError):
                proof.physical_cleanup(path)
            manager.assert_not_called()


if __name__ == '__main__':
    unittest.main()
