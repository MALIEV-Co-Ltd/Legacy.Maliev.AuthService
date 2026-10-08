"""Pure controls ONLY; they do not qualify Docker, systemd, C# or native CI."""
import copy
import json
import pathlib
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import Mock, patch

from private_docker_proxy import create_plan, rpc
from hosted_owner import OwnedUnits, properties, stop_expiry_owners
from recover_owner import coordinator_barrier, recover
from verify_results import NS, ORDINARY, CASES, exact_cases, read_trx


class UnitTypePropertiesControls(unittest.TestCase):
    def observe(self, name, **extra):
        state = dict(Id=name, FragmentPath='/synthetic/' + name, InvocationID='generation',
                     ActiveState='inactive', SubState='dead')
        state.update(extra)
        with patch('hosted_owner.command', return_value='\n'.join(key + '=' + value for key, value in state.items())):
            return properties(name)

    def test_slice_omits_service_pid_but_retains_actual_cgroup(self):
        state = self.observe('owned.slice', ControlGroup='/actual-slice')
        self.assertEqual('0', state['MainPID'])
        self.assertEqual('/actual-slice', state['ControlGroup'])
        self.assertEqual('false', state['MainProcessApplicable'])

    def test_timer_omits_service_pid_and_cgroup(self):
        state = self.observe('owned.timer')
        self.assertEqual('0', state['MainPID'])
        self.assertEqual('', state['ControlGroup'])
        self.assertEqual('false', state['ControlGroupApplicable'])

    def test_service_missing_pid_remains_rejected(self):
        with self.assertRaises(KeyError):
            self.observe('owned.service', ControlGroup='/actual-service')

    def test_service_or_slice_missing_cgroup_remains_rejected(self):
        for name in ('owned.service', 'owned.slice'):
            with self.subTest(name=name), self.assertRaises(KeyError):
                self.observe(name, MainPID='0')

    def test_non_service_cannot_claim_a_main_process(self):
        for name in ('owned.slice', 'owned.timer'):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                self.observe(name, MainPID='123', ControlGroup='/foreign')

    def test_timer_cannot_claim_a_process_cgroup(self):
        with self.assertRaises(RuntimeError):
            self.observe('owned.timer', ControlGroup='/foreign')

    def lifecycle(self, name, extra):
        import hashlib
        with tempfile.TemporaryDirectory() as temporary:
            fragment = pathlib.Path(temporary) / name
            fragment.write_text('immutable fixture')
            owner = OwnedUnits('synthetic-control', pathlib.Path(temporary) / 'units.json')
            owner.units[name] = dict(fragment=str(fragment), sha256=hashlib.sha256(fragment.read_bytes()).hexdigest(),
                                     dispatchAttempted=False, invocationId=None, quiescenceVerified=False)
            state = dict(Id=name, FragmentPath=str(fragment), InvocationID='generation',
                         ActiveState='inactive', SubState='dead', **extra)
            commands = []
            def manager(argv, **kwargs):
                commands.append(argv)
                return '\n'.join(key + '=' + value for key, value in state.items()) if argv[1] == 'show' else ''
            with patch('hosted_owner.command', side_effect=manager), patch('hosted_owner.members', return_value=[]):
                owner.start(name)
                owner.stop(name)
            self.assertTrue(owner.units[name]['dispatchAttempted'])
            self.assertTrue(owner.units[name]['quiescenceVerified'])
            self.assertEqual('generation', owner.units[name]['invocationId'])
            self.assertNotIn('mainProcess', owner.units[name])
            self.assertEqual(1, sum(argv[1] == 'start' for argv in commands))
            self.assertEqual(1, sum(argv[1] == 'stop' for argv in commands))

    def test_actual_omission_shape_traverses_slice_start_and_stop(self):
        self.lifecycle('owned.slice', dict(ControlGroup='/actual-slice'))

    def test_actual_omission_shape_traverses_timer_start_and_stop(self):
        self.lifecycle('owned.timer', {})


class AdmissionControls(unittest.TestCase):
    def setUp(self):
        self.original = {"Image": "postgres:18-alpine", "Labels": {"codex.run": "fixture-generation"},
                         "HostConfig": {"PortBindings": {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": ""}]}}}

    def plan(self, value=None):
        return create_plan(self.original if value is None else value, "auth-financial-1-1-123456789abc", "authfinancial1.slice")

    def test_create_caps_before_callback_without_mutating_fixture(self):
        before = copy.deepcopy(self.original)
        result = self.plan()
        self.assertEqual(before, self.original)
        self.assertEqual(768 * 1024 * 1024, result["HostConfig"]["Memory"])
        self.assertEqual(1_000_000_000, result["HostConfig"]["NanoCpus"])
        self.assertEqual("fixture-generation", result["Labels"]["codex.run"])

    def test_loopback_is_applied_to_every_published_port(self):
        self.assertEqual("127.0.0.1", self.plan()["HostConfig"]["PortBindings"]["5432/tcp"][0]["HostIp"])

    def test_lower_fixture_cap_is_preserved(self):
        self.original["HostConfig"].update(Memory=512 * 1024 * 1024, NanoCpus=500_000_000)
        self.assertEqual(512 * 1024 * 1024, self.plan()["HostConfig"]["Memory"])

    def test_foreign_parent_rejected_before_birth(self):
        self.original["HostConfig"]["CgroupParent"] = "foreign.slice"
        with self.assertRaises(ValueError): self.plan()

    def test_host_mount_rejected(self):
        self.original["HostConfig"]["Binds"] = ["/var/run/docker.sock:/var/run/docker.sock"]
        with self.assertRaises(ValueError): self.plan()

    def test_persistent_named_mount_rejected(self):
        self.original["HostConfig"]["Mounts"] = [{"Type": "volume", "Source": "persistent"}]
        with self.assertRaises(ValueError): self.plan()

    def test_privilege_rejected(self):
        self.original["HostConfig"]["Privileged"] = True
        with self.assertRaises(ValueError): self.plan()

    def test_foreign_network_rejected(self):
        self.original["HostConfig"]["NetworkMode"] = "host"
        with self.assertRaises(ValueError): self.plan()

    def test_foreign_bind_rejected(self):
        self.original["HostConfig"]["PortBindings"]["5432/tcp"][0]["HostIp"] = "192.0.2.10"
        with self.assertRaises(ValueError): self.plan()

    def test_memory_excess_rejected(self):
        self.original["HostConfig"]["Memory"] = 1024 ** 3
        with self.assertRaises(ValueError): self.plan()

    def test_cpu_excess_rejected(self):
        self.original["HostConfig"]["NanoCpus"] = 2_000_000_000
        with self.assertRaises(ValueError): self.plan()

    def test_foreign_hosted_owner_label_rejected(self):
        self.original["Labels"]["codex.hosted-owner"] = "other-task"
        with self.assertRaises(ValueError): self.plan()

    def test_auto_remove_rejected_to_retain_evidence(self):
        self.original["HostConfig"]["AutoRemove"] = True
        with self.assertRaises(ValueError): self.plan()


class TrxControls(unittest.TestCase):
    def document(self):
        namespace = "{" + NS["t"] + "}"
        root = ET.Element(namespace + "TestRun")
        definitions = ET.SubElement(root, namespace + "TestDefinitions")
        test = ET.SubElement(definitions, namespace + "UnitTest", id="t", name="Example.Fact")
        ET.SubElement(test, namespace + "TestMethod", className="Example", name="Fact")
        ET.SubElement(test, namespace + "Execution", id="e")
        results = ET.SubElement(root, namespace + "Results")
        ET.SubElement(results, namespace + "UnitTestResult", testId="t", executionId="e", testName="Example.Fact", outcome="Passed")
        summary = ET.SubElement(root, namespace + "ResultSummary", outcome="Completed")
        counters = dict.fromkeys(("total", "executed", "passed"), "1")
        counters.update(dict.fromkeys(("failed", "error", "timeout", "aborted", "inconclusive", "passedButRunAborted", "notRunnable", "notExecuted", "disconnected", "warning", "completed", "inProgress", "pending"), "0"))
        ET.SubElement(summary, namespace + "Counters", **counters)
        return root

    def read(self, root):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "synthetic.trx"
            path.write_bytes(ET.tostring(root))
            return read_trx(path, 1)

    def test_exact_join_accepted_as_synthetic_only(self):
        self.assertEqual([("Example", "Fact", "Example.Fact")], self.read(self.document()))

    def test_failed_rejected(self):
        root = self.document()
        root.find("t:Results/t:UnitTestResult", NS).set("outcome", "Failed")
        with self.assertRaises(ValueError): self.read(root)

    def test_skipped_rejected(self):
        root = self.document()
        root.find("t:Results/t:UnitTestResult", NS).set("outcome", "NotExecuted")
        with self.assertRaises(ValueError): self.read(root)

    def test_duplicate_result_rejected(self):
        root = self.document()
        root.find("t:Results", NS).append(copy.deepcopy(root.find("t:Results/t:UnitTestResult", NS)))
        with self.assertRaises(ValueError): self.read(root)

    def test_orphan_result_rejected(self):
        root = self.document()
        root.find("t:Results/t:UnitTestResult", NS).set("testId", "orphan")
        with self.assertRaises(ValueError): self.read(root)

    def test_different_execution_rejected(self):
        root = self.document()
        root.find("t:Results/t:UnitTestResult", NS).set("executionId", "different")
        with self.assertRaises(ValueError): self.read(root)

    def test_counter_disagreement_rejected(self):
        root = self.document()
        root.find("t:ResultSummary/t:Counters", NS).set("passed", "0")
        with self.assertRaises(ValueError): self.read(root)

    def test_exact_coordinate_inventory_has_19_and_29(self):
        self.assertEqual(19, sum(len(cases) for (klass, _), cases in CASES.items() if klass != "Legacy.Maliev.AuthService.Tests.QuotationInvoiceLiveTransportHttpTests"))
        self.assertEqual(29, len(next(cases for (klass, _), cases in CASES.items() if klass == "Legacy.Maliev.AuthService.Tests.QuotationInvoiceLiveTransportHttpTests")))

    def test_missing_focused_case_rejected(self):
        with self.assertRaises(ValueError): exact_cases([], {ORDINARY})


class OwnerFaultControls(unittest.TestCase):
    def coordinator_receipt(self, directory):
        run = "auth-financial-1-1-123456789abc"
        script = pathlib.Path(directory) / "synthetic.py"
        script.write_text("synthetic source only")
        import hashlib
        owner = {"schemaVersion": 1, "run": run, "unit": run + "-control.service",
                 "description": "synthetic unpredictable fence", "cgroup": "/system.slice/" + run + "-control.service",
                 "dispatchAttempted": True, "invocationId": "retained-invocation", "script": str(script),
                 "scriptSha256": hashlib.sha256(script.read_bytes()).hexdigest(), "execStart": "exact retained command"}
        receipt = pathlib.Path(directory) / "coordinator.json"
        receipt.write_text(json.dumps(owner))
        state = {"Id": owner["unit"], "Transient": "yes", "Description": owner["description"],
                 "ControlGroup": owner["cgroup"], "InvocationID": owner["invocationId"],
                 "ExecStart": owner["execStart"], "MainPID": "0", "ActiveState": "inactive",
                 "ExecMainStartTimestampMonotonic": "1", "ExecMainExitTimestampMonotonic": "2"}
        return run, receipt, state

    def test_coordinator_barrier_failure_prevents_reading_resource_ledger(self):
        with patch("recover_owner.coordinator_barrier", side_effect=RuntimeError("synthetic live coordinator")), \
                patch("recover_owner.pathlib.Path.read_text") as read:
            with self.assertRaises(RuntimeError): recover("synthetic", "unused", "unused")
            read.assert_not_called()

    def test_changed_coordinator_invocation_never_authorizes_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            run, receipt, state = self.coordinator_receipt(directory)
            state["InvocationID"] = "replacement"
            with patch("recover_owner.properties", return_value=state), patch("recover_owner.command") as stop:
                with self.assertRaises(RuntimeError): coordinator_barrier(run, receipt)
                stop.assert_not_called()

    def test_live_coordinator_cgroup_after_stop_rejects_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            run, receipt, state = self.coordinator_receipt(directory)
            with patch("recover_owner.properties", return_value=state), patch("recover_owner.command"), \
                    patch("recover_owner.members", return_value=[123]):
                with self.assertRaises(RuntimeError): coordinator_barrier(run, receipt)
            self.assertFalse(json.loads(receipt.read_text()).get("quiescenceVerified", False))

    def test_exact_terminal_coordinator_with_empty_cgroup_records_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            run, receipt, state = self.coordinator_receipt(directory)
            with patch("recover_owner.properties", return_value=state), patch("recover_owner.command") as stop, \
                    patch("recover_owner.members", return_value=[]):
                self.assertTrue(coordinator_barrier(run, receipt)["quiescenceVerified"])
                stop.assert_called_once_with(["/usr/bin/systemctl", "stop", state["Id"]], timeout=50)

    def test_shared_next_collision_does_not_prevent_exact_coordinator_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            run, receipt, state = self.coordinator_receipt(directory)
            interrupted = receipt.with_suffix(".next")
            interrupted.write_text("foreign or interrupted writer: preserve exactly")
            with patch("recover_owner.properties", return_value=state), patch("recover_owner.command") as stop, \
                    patch("recover_owner.members", return_value=[]):
                self.assertTrue(coordinator_barrier(run, receipt)["quiescenceVerified"])
                stop.assert_called_once()
            self.assertEqual("foreign or interrupted writer: preserve exactly", interrupted.read_text())

    def test_receipt_write_failure_retries_only_after_coordinator_stop_and_retains_fault(self):
        with tempfile.TemporaryDirectory() as directory:
            run, receipt, state = self.coordinator_receipt(directory)
            import os
            replace = os.replace
            failures = [True]
            with patch("recover_owner.properties", return_value=state), patch("recover_owner.command") as stop, \
                    patch("recover_owner.members", return_value=[]):
                def replace_after_stop(source, target):
                    stop.assert_called_once()
                    if failures and failures.pop():
                        raise OSError("synthetic interrupted replace")
                    return replace(source, target)
                with patch("hosted_owner.os.replace", side_effect=replace_after_stop):
                    result = coordinator_barrier(run, receipt)
            self.assertTrue(result["quiescenceVerified"])
            self.assertEqual(1, len(result["receiptWriteFailures"]))
            self.assertEqual("recovery", result["receiptWriteFailures"][0]["writer"])
            self.assertEqual(result, json.loads(receipt.read_text()))

    def test_exhausted_receipt_write_still_stops_coordinator_but_never_reads_backend_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            run, receipt, state = self.coordinator_receipt(directory)
            with patch("recover_owner.properties", return_value=state), patch("recover_owner.command") as stop, \
                    patch("recover_owner.members", return_value=[]), patch("hosted_owner.os.replace", side_effect=OSError("synthetic unavailable persistence")) as replace, \
                    patch("recover_owner.OwnedUnits") as backend:
                with self.assertRaises(RuntimeError): recover(run, "unused-backend", receipt)
                stop.assert_called_once()
                self.assertEqual(3, replace.call_count)
                backend.assert_not_called()
            self.assertFalse(json.loads(receipt.read_text()).get("quiescenceVerified", False))

    def test_failed_expiry_stop_fences_backend_recovery(self):
        owner = Mock(units={"timer": {}, "guard": {}})
        owner.stop.side_effect = [TimeoutError("synthetic expiry still running"), None]
        failures = []
        self.assertFalse(stop_expiry_owners(owner, ("timer", "guard"), failures))
        self.assertEqual(["ExpiryOwnerQuiescence:TimeoutError"], failures)
        self.assertEqual(2, owner.stop.call_count)

    def test_absent_expiry_owners_are_quiescent_without_dispatch(self):
        owner = Mock(units={})
        self.assertTrue(stop_expiry_owners(owner, ("timer", "guard"), []))
        owner.stop.assert_not_called()

    def owner(self):
        owner = OwnedUnits("synthetic-control", pathlib.Path("unused-synthetic-receipt"))
        owner.units["synthetic.service"] = {"dispatchAttempted": False, "invocationId": None}
        owner.identity = Mock(return_value={"InvocationID": "actual-synthetic-invocation", "ControlGroup": "/synthetic"})
        owner.save = Mock()
        return owner

    def test_checkpoint_failure_never_dispatches_native_child(self):
        owner = self.owner()
        owner.save.side_effect = OSError("synthetic checkpoint")
        with patch("hosted_owner.command") as launch:
            with self.assertRaises(OSError): owner.start("synthetic.service")
            launch.assert_not_called()

    def test_ambiguous_start_failure_retains_exact_manager_owner(self):
        owner = self.owner()
        with patch("hosted_owner.command", side_effect=OSError("synthetic ambiguous return")):
            with self.assertRaises(OSError): owner.start("synthetic.service")
        self.assertTrue(owner.units["synthetic.service"]["dispatchAttempted"])
        self.assertEqual("actual-synthetic-invocation", owner.units["synthetic.service"]["invocationId"])

    def test_completed_phase_without_actual_invocation_not_accepted(self):
        owner = self.owner()
        owner.identity.return_value = {"ActiveState": "inactive", "ExecMainStartTimestampMonotonic": "0"}
        with self.assertRaises(RuntimeError): owner.settle("synthetic.service", 1)

    def test_live_descendant_denies_settlement_even_after_main_exit(self):
        owner = self.owner()
        owner.units["synthetic.service"]["invocationId"] = "actual-synthetic-invocation"
        owner.identity.return_value = {"ActiveState": "inactive", "ExecMainStartTimestampMonotonic": "1", "ExecMainExitTimestampMonotonic": "2", "ControlGroup": "/synthetic"}
        with patch("hosted_owner.members", return_value=[123]):
            with self.assertRaises(RuntimeError): owner.settle("synthetic.service", 1)

    def test_failed_stop_does_not_record_quiescence(self):
        owner = self.owner()
        with patch("hosted_owner.command", side_effect=TimeoutError("synthetic shutdown")):
            with self.assertRaises(TimeoutError): owner.stop("synthetic.service")
        self.assertFalse(owner.units["synthetic.service"].get("quiescenceVerified", False))

    def test_content_length_eof_does_not_touch_closed_socket(self):
        response = Mock(status=200, length=7)
        closed = [False]
        response.isclosed.side_effect = lambda: closed[0]
        def read(_):
            closed[0] = True
            return b'{"x":1}'
        response.read1.side_effect = read
        connection = Mock()
        connection.getresponse.return_value = response
        with patch("private_docker_proxy.UnixConnection", return_value=connection):
            self.assertEqual((200, {"x": 1}), rpc("synthetic.sock", "GET", "/info"))
        connection.owned_socket.settimeout.assert_called_once()
        response.close.assert_called_once()
        connection.close.assert_called_once()

    def test_rpc_deadline_closes_response_and_socket(self):
        response = Mock(status=200, length=None)
        response.isclosed.return_value = False
        connection = Mock()
        connection.getresponse.return_value = response
        with patch("private_docker_proxy.UnixConnection", return_value=connection), patch("private_docker_proxy.time.monotonic", side_effect=[0, 21]):
            with self.assertRaises(TimeoutError): rpc("synthetic.sock", "GET", "/info")
        response.close.assert_called_once()
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
