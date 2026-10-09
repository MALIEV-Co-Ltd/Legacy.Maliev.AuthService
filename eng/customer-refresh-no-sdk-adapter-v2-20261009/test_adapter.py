import pathlib
import types
import unittest
import tempfile
import ast
import json
import sys
import io
from contextlib import redirect_stdout
from unittest.mock import patch
import shared_backend
import auth_proof
import auth_owner

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
BACKEND = ROOT/'work/auth-customer-refresh-transport-20261009/eng/financial-iam'
POLICY = ROOT/'outputs/customer-refresh-native-create-policy-v1-20261009/create_policy.py'

class AdapterTests(unittest.TestCase):
    def test_owner_arguments_cannot_broaden_route(self):
        argv=['--source','/backend','--lane=auth','--stage=proof','--checkouts=/checkout','--receipt=/receipt','--coordinator-unit=auth-financial-1-1-aaaaaaaaaaaa-control.service']
        self.assertEqual(auth_owner.arguments(argv).stage,'proof')
        for extra in ('--commerce-transport=/packet','--commerce-driver=/driver','--admission-verifier=/gate','--unknown=x','--sta=proof'):
            with self.subTest(extra=extra), redirect_stdout(io.StringIO()), patch('sys.stderr',io.StringIO()), self.assertRaises(SystemExit):
                auth_owner.arguments(argv+[extra])
        with self.assertRaises(ValueError): auth_owner.arguments(argv+['--stage=full'])
        with self.assertRaises(ValueError): auth_owner.arguments([x.replace('--stage=proof','--stage=full') for x in argv])
    def test_actual_published_library_and_owner_only_one_hook(self):
        raw = shared_backend.capture(BACKEND)['hosted_owner.py']
        result = shared_backend.owner_source(raw,'/reviewed/auth_proof.py')
        marker = 'str(source / "finite_stub_proof.py")'
        proof = pathlib.Path('/reviewed/auth_proof.py')
        policy = proof.parent.parent/'customer-refresh-native-create-policy-v1-20261009/create_policy.py'
        replacement = repr(str(proof.absolute()))+', "--backend", str(source), "--policy", '+repr(str(policy.absolute()))
        self.assertEqual(raw.decode().replace(marker,replacement,1),result)
        compile(result,'parameterized-owner','exec')

    def test_shared_actual_create_api_preserves_auth_policy(self):
        proxy = shared_backend.pure_create_api(BACKEND)
        policy = types.ModuleType('policy')
        exec(compile(POLICY.read_bytes(),str(POLICY),'exec'),policy.__dict__)
        result = auth_proof.model(proxy,policy)
        self.assertTrue(result['policyModelPassed'])
        self.assertFalse(result['realTestcontainersWireCaptured'])
        self.assertFalse(result['customerRuntimeAccepted'])

    def test_tampered_backend_and_proof_path_rejected(self):
        with self.assertRaises(ValueError): shared_backend.owner_source(b'changed','/reviewed/proof.py')
        raw = shared_backend.capture(BACKEND)['hosted_owner.py']
        with self.assertRaises(ValueError): shared_backend.owner_source(raw,'/bad\npath')

    def test_launcher_only_redirects_coordinator_retains_recovery(self):
        raw = shared_backend.capture(BACKEND)['Start-FinancialIamHostedOwner.ps1']
        result = shared_backend.launcher_source(raw,'/reviewed/backend','/reviewed/auth_owner.py')
        self.assertIn("Start-Unit $control '"+str(pathlib.Path('/reviewed/auth_owner.py').absolute())+"'",result)
        self.assertIn("Join-Path '"+str(pathlib.Path('/reviewed/backend').absolute())+"' 'recover_owner.py'",result)
        self.assertIn('--property=MemoryMax=512M',result)
        self.assertIn('4096 MiB admission floor failed',result)

    def test_exact_policy_pin_and_changed_policy_rejected(self):
        auth_proof.policy_module(POLICY)
        with tempfile.TemporaryDirectory() as temporary:
            changed = pathlib.Path(temporary)/'policy.py'
            changed.write_bytes(POLICY.read_bytes()+b'\n# altered\n')
            with self.assertRaises(ValueError): auth_proof.policy_module(changed)

    def test_real_readback_finally_and_pinned_binding_survive_model_failures(self):
        raw = shared_backend.capture(BACKEND)['finite_stub_proof.py']
        node = next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name == 'readback')
        lifecycle = types.ModuleType('actual_readback_model')
        lifecycle.json = json
        exec(compile(ast.Module(body=[node],type_ignores=[]),'pinned-readback','exec'),lifecycle.__dict__)
        owner = types.ModuleType('pinned_owner_model')
        owner.command = object()
        previous = sys.modules.get('hosted_owner')
        ambient = types.ModuleType('untrusted_ambient_owner')
        sys.modules['hosted_owner'] = ambient
        try:
            for failure in (ValueError('policy'),FileNotFoundError('receipt'),KeyboardInterrupt()):
                with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as temporary:
                    events = []
                    lifecycle.validate_readback = lambda evidence: {'lifecycleProofAccepted':True}
                    def cleanup(evidence):
                        from hosted_owner import command
                        self.assertIs(command,owner.command)
                        events.append('physical-cleanup')
                        return {'remainingResources':0}
                    lifecycle.physical_cleanup = cleanup
                    lifecycle.save = lambda path,data: events.append(path.name)
                    loaded = {'private_docker_proxy':types.ModuleType('proxy_model'),'hosted_owner':owner,'finite_stub_proof':lifecycle}
                    with self.assertRaises(type(failure)) as raised:
                        with shared_backend.bind_loaded(loaded), patch.object(auth_proof,'policy_module',side_effect=failure), redirect_stdout(io.StringIO()):
                            auth_proof.readback_with_model(loaded,pathlib.Path(temporary),POLICY)
                    self.assertIs(raised.exception,failure)
                    self.assertEqual(events,['physical-cleanup','stub-lifecycle-readback.json','auth-readback.json'])
                    self.assertIs(sys.modules['hosted_owner'],ambient)
        finally:
            if previous is None: sys.modules.pop('hosted_owner',None)
            else: sys.modules['hosted_owner'] = previous

if __name__ == '__main__': unittest.main()
