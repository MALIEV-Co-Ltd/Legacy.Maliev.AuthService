import json
import hashlib
import ast
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import caller
BACKEND=Path(__file__).resolve().parents[2]/'work/ci9'

class Controls(unittest.TestCase):
    def test_real_systemd_suffix_identity_and_cleanup_inventory(self):
        unit='auth-identity-caller-1-1.service'
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp); runner=base/'runner.py';runner.write_bytes(b'pass\n')
            p=caller.plan(base,base/'evidence',runner,unit)
            Path(p['launcher']).write_bytes(b'launcher')
            p.update(callerSha256=hashlib.sha256(runner.read_bytes()).hexdigest(),launcherSha256=hashlib.sha256(b'launcher').hexdigest())
            state={'Id':unit,'Description':p['description'],'Transient':'yes','InvocationID':'actual',
                'MemoryMax':str(p['memory']),'MemorySwapMax':'0','RuntimeMaxUSec':'1h',
                'CPUQuotaPerSecUSec':'1s','ControlGroup':'/system.slice/'+unit}
            owner=types.SimpleNamespace(properties=lambda queried:state,quote=lambda value:value)
            extra={'ControlPID':'-1','TasksMax':'64','TimeoutStopUSec':'13min'}
            def configured(owner,queried,field):
                self.assertEqual(queried,unit)
                argv=p['cleanup' if field=='ExecStopPost' else 'workload']
                return {'path':argv[0],'arguments':argv,'ignoreErrors':False}
            with patch.object(caller,'extra_properties',return_value=extra),patch.object(caller,'configured_command',side_effect=configured):
                self.assertEqual(caller.verify_intent(p,owner)['cgroup'],'/system.slice/'+unit)
                for field,bad in (('Id',unit.removesuffix('.service')),('Id','foreign.service'),
                    ('ControlGroup','/system.slice/'+unit.removesuffix('.service'))):
                    original=state[field];state[field]=bad
                    with self.assertRaisesRegex(RuntimeError,'identity'):caller.verify_intent(p,owner)
                    state[field]=original
            queries=[]
            def inventory(names,**kwargs):
                queries.append(names);self.assertEqual(names,[unit]);return []
            proof=types.SimpleNamespace(registered_manager_units=inventory,save=lambda *a:None)
            caller.finish_caller(p,base/'evidence',{'hosted_owner':owner,'finite_stub_proof':proof})
            self.assertTrue(queries)
            self.assertIn('--unit='+unit,caller.manager_arguments(p,owner,[]))
        for bad in ('auth-identity-caller-1-1','auth-identity-caller-1-1.service.service','foreign.service'):
            with self.assertRaises(ValueError):caller.plan('/s','/e','/r',bad)
    def test_workflow_budget_covers_wait_finally_and_finite_checks(self):
        import re
        workflow=Path(__file__).with_name('workflow.yml').read_text()
        source=Path(caller.__file__).read_text()
        tree=ast.parse(source)
        methods={node.name:node for node in tree.body if isinstance(node,ast.FunctionDef)}
        def timeouts(name):
            return [kw.value.value for node in ast.walk(methods[name]) if isinstance(node,ast.Call)
                for kw in node.keywords if kw.arg=='timeout' and isinstance(kw.value,ast.Constant)]
        self.assertEqual(timeouts('run_dispatch'),[4380])
        self.assertEqual(timeouts('finish_caller'),[5,810])
        self.assertIn('deadline=time.monotonic()+10',source)
        bounds=[int(x) for x in re.findall(r'timeout-minutes:\s*([0-9]+)',workflow)]
        self.assertEqual(bounds,[110,3,5,90])
        step=bounds[-1]*60;job=bounds[0]*60
        checks=5+6*30
        self.assertGreaterEqual(step,4380+810+10+checks+15)
        self.assertGreaterEqual(job,step+bounds[1]*60+420)
    def test_tampered_recovery_source_prevents_birth_but_readback_runs(self):
        events=[]
        run='auth-financial-1-1-aaaaaaaaaaaa'
        proof=types.ModuleType('readback')
        proof.readback_with_model=lambda *a:events.append('readback')
        loaded={'hosted_owner':types.SimpleNamespace(command=lambda *a,**k:events.append('forbidden-manager-call')),
            'pins':{'recover_owner.py':'d6996140ddbb2896f00e357681b02f3478e50357c85d88f3981d63eee31de979'},
            'finite_stub_proof':types.SimpleNamespace(save=lambda *a:events.append('diagnostic'))}
        with tempfile.TemporaryDirectory() as tmp,patch.dict('sys.modules',{'readback':proof}):
            root=Path(tmp);source=root/'source';backend=source/'eng/financial-iam';backend.mkdir(parents=True)
            (backend/'recover_owner.py').write_bytes(b'raise RuntimeError("must never execute")\n')
            evidence=root/'evidence';evidence.mkdir()
            (evidence/'coordinator-owner.json').write_text(json.dumps({'run':run}))
            with self.assertRaisesRegex(ValueError,'source changed'):caller.cleanup(source,evidence,loaded)
        self.assertEqual(events,['readback','diagnostic'])
    def test_fresh_admission_failure_cannot_allocate_outer_unit(self):
        env={'GITHUB_REPOSITORY':'MALIEV-Co-Ltd/Legacy.Maliev.AuthService','GITHUB_EVENT_NAME':'workflow_dispatch',
            'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':'a'*40}
        cases=[(env,'MemAvailable: 4194303 kB\n',True),(env,'MemAvailable: 4194304 kB\n',False),
            ({**env,'GITHUB_EVENT_NAME':'push'},'MemAvailable: 9999999 kB\n',True),
            ({**env,'GITHUB_SHA':'wrong'},'MemAvailable: 9999999 kB\n',True)]
        with patch.object(caller,'persist_exclusive') as persist,patch.object(caller,'run_dispatch') as dispatch:
            for e,m,c in cases:
                with self.assertRaises(RuntimeError):caller.admitted_dispatch({},Path('/unused'),{},[],e,m,c)
            persist.assert_not_called();dispatch.assert_not_called()
        caller.admission(env,'MemAvailable: 4194304 kB\n',True)
    def test_hook_binding_rejects_caps_command_and_nonmanager_pid(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp); runner=base/'runner.py';runner.write_bytes(b'pass\n')
            p=caller.plan(base,base/'evidence',runner,'auth-identity-caller-1-1.service')
            Path(p['launcher']).write_bytes(b'launcher')
            p.update(callerSha256=hashlib.sha256(runner.read_bytes()).hexdigest(),launcherSha256=hashlib.sha256(b'launcher').hexdigest())
            state={'Id':p['unit'],'Description':p['description'],'Transient':'yes','InvocationID':'actual','MemoryMax':str(p['memory']),
                'MemorySwapMax':'0','RuntimeMaxUSec':'1h','CPUQuotaPerSecUSec':'1s','ControlGroup':'/system.slice/'+p['unit']}
            owner=types.SimpleNamespace(properties=lambda unit:state)
            extra={'ControlPID':'-1','TasksMax':'64','TimeoutStopUSec':'13min'}
            def configured(owner,unit,field):
                argv=p['cleanup' if field=='ExecStopPost' else 'workload']
                return {'path':argv[0],'arguments':argv,'ignoreErrors':False}
            with patch.object(caller,'extra_properties',return_value=extra),patch.object(caller,'configured_command',side_effect=configured):
                with self.assertRaisesRegex(RuntimeError,'control process'):caller.verify_intent(p,owner,hook=True)
                state['MemoryMax']='1'
                with self.assertRaisesRegex(RuntimeError,'caps'):caller.verify_intent(p,owner)
                state['MemoryMax']=str(p['memory'])
                state['Description']='foreign-nonce'
                with self.assertRaisesRegex(RuntimeError,'identity'):caller.verify_intent(p,owner)
                state['Description']=p['description']
            with patch.object(caller,'extra_properties',return_value=extra),patch.object(caller,'configured_command',return_value={}):
                with self.assertRaisesRegex(RuntimeError,'command'):caller.verify_intent(p,owner)
    def test_hook_cannot_enter_without_durable_intent(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuntimeError):caller.hook_admission('/source',Path(tmp)/'evidence',{'pins':{}})
    def test_typed_hook_rejects_wrong_wrapper_or_multiple_commands(self):
        raw=(BACKEND/'eng/financial-iam/recover_owner.py').read_bytes()
        node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='coordinator_command')
        for reply in ({'type':'a(sasbttttuii)','data':[]}, {'type':'wrong','data':[[]]}):
            answers=iter([json.dumps({'type':'o','data':['/org/freedesktop/systemd1/unit/test']}),json.dumps(reply)])
            owner=types.SimpleNamespace(command=lambda *a,**k:next(answers))
            reader=types.ModuleType('actual_pinned_reader');reader.json=json
            import re
            reader.re=re;reader.command=owner.command
            exec(compile(ast.Module(body=[node],type_ignores=[]),'actual-pinned-reader','exec'),reader.__dict__)
            owner._recovery_reader=reader
            with self.assertRaises(RuntimeError):caller.configured_command(owner,'own.service','ExecStopPost')
            self.assertIs(reader.command,owner.command)
    def test_collected_caller_records_actual_nonloading_absence(self):
        events=[]
        proof=types.SimpleNamespace(registered_manager_units=lambda *a,**k:[],save=lambda path,row:events.append(row))
        with tempfile.TemporaryDirectory() as tmp:
            evidence=Path(tmp)/'evidence'
            caller.finish_caller({'unit':'auth-identity-caller-1-1.service'},evidence,{'hosted_owner':object(),'finite_stub_proof':proof})
        self.assertTrue(events[0]['managerAbsent'])
    def test_completed_recovery_does_not_redispatch_collected_unit(self):
        run='auth-financial-1-1-aaaaaaaaaaaa'
        events=[]
        owner=types.SimpleNamespace(command=lambda *a,**k:events.append('unexpected-manager-call'))
        proof=types.ModuleType('readback')
        proof.readback_with_model=lambda *a:events.append('physical-readback')
        loaded={'hosted_owner':owner,'finite_stub_proof':types.SimpleNamespace(save=lambda *a:events.append('receipt'))}
        with tempfile.TemporaryDirectory() as tmp, patch.dict('sys.modules',{'readback':proof}):
            evidence=Path(tmp); (evidence/'resources').mkdir()
            (evidence/'coordinator-owner.json').write_text(json.dumps({'run':run}))
            (evidence/'resources/external-cleanup.json').write_text(json.dumps({'schemaVersion':1,'run':run,
                'remainingResources':0,'sdkQuiescent':True,'containersAbsent':True,'expiryQuiescent':True,'currentCleanupFailures':[]}))
            caller.cleanup('/source',evidence,loaded)
        self.assertEqual(events,['physical-readback','receipt'])
    def test_actual_dispatch_arguments_and_finally_on_timeout_and_cancel(self):
        for primary in (TimeoutError('modeled'),KeyboardInterrupt()):
            with self.subTest(kind=type(primary).__name__),tempfile.TemporaryDirectory() as tmp:
                evidence=Path(tmp); events=[]
                p=caller.plan('/source',evidence,'/runner','auth-identity-caller-1-1.service')
                def command(argv,**kw):
                    self.assertIn('--collect',argv)
                    self.assertIn('--property=RuntimeMaxSec=3600',argv)
                    self.assertIn('--property=TimeoutStopSec=780',argv)
                    self.assertIn('--property=LimitCORE=0',argv)
                    self.assertIn('--property=LimitFSIZE=268435456',argv)
                    self.assertIn('--description='+p['description'],argv)
                    self.assertTrue(any(x.startswith('--property=ExecStopPost=') and 'cleanup' in x for x in argv))
                    events.append('dispatch-with-atomic-hook')
                    raise primary
                loaded={'hosted_owner':types.SimpleNamespace(command=command,quote=lambda x:'"'+x+'"')}
                with patch.object(caller,'finish_caller',side_effect=lambda *a:events.append('exact-stop-and-absence')):
                    with self.assertRaises(type(primary)) as caught: caller.run_dispatch(p,evidence,loaded,[])
                self.assertIs(caught.exception,primary)
                self.assertEqual(events,['dispatch-with-atomic-hook','exact-stop-and-absence'])
    def test_cleanup_failure_does_not_replace_dispatch_primary(self):
        primary=ValueError('first')
        p=caller.plan('/s','/e','/r','auth-identity-caller-1-1.service')
        loaded={'hosted_owner':types.SimpleNamespace(command=lambda *a,**k:(_ for _ in ()).throw(primary),quote=str)}
        with tempfile.TemporaryDirectory() as tmp,patch.object(caller,'finish_caller',side_effect=OSError('cleanup')):
            with self.assertRaises(ValueError) as caught: caller.run_dispatch(p,Path(tmp),loaded,[])
        self.assertIs(caught.exception,primary)
        self.assertEqual(primary.caller_cleanup_failure,'OSError')
    def test_success_requires_full_physical_readback(self):
        p=caller.plan('/s','/e','/r','auth-identity-caller-1-1.service')
        loaded={'hosted_owner':types.SimpleNamespace(command=lambda *a,**k:'',quote=str),
            'finite_stub_proof':types.SimpleNamespace(save=lambda *a:None)}
        with tempfile.TemporaryDirectory() as tmp,patch.object(caller,'finish_caller'):
            evidence=Path(tmp)
            (evidence/'caller-cleanup.json').write_text('{"failures":[]}')
            (evidence/'auth-sdk-readback.json').write_text(json.dumps({'lifecycleProofAccepted':True,
                'runtimeRootAbsent':True,'registeredFragmentsAbsent':True,'registeredUnitsAbsent':True,'remainingResources':0}))
            caller.run_dispatch(p,evidence,loaded,[])
            (evidence/'auth-sdk-readback.json').write_text('{"lifecycleProofAccepted":true}')
            with self.assertRaises(RuntimeError):caller.run_dispatch(p,evidence,loaded,[])
    def test_existing_exact_settled_recovery_then_readback(self):
        root=BACKEND
        run='auth-financial-1-1-aaaaaaaaaaaa'
        events=[]
        owner=types.ModuleType('hosted_owner')
        def command(argv,**kwargs):
            events.append(argv[1])
            if argv[1]=='show': return '64' if '--property=TasksMax' in argv else 'loaded'
            if argv[1]=='stop': return ''
            if 'GetUnit' in argv: return json.dumps({'type':'o','data':['/org/freedesktop/systemd1/unit/recovery']})
            return json.dumps({'type':'a(sasbttttuii)','data':[['/usr/bin/python3',expected,False,0,0,0,0,0,0,0]]})
        with tempfile.TemporaryDirectory() as tmp:
            evidence=Path(tmp)
            (evidence/'coordinator-owner.json').write_text(json.dumps({'run':run}))
            expected=['/usr/bin/python3','-B',str(root/'eng/financial-iam/recover_owner.py'),
                '--run',run,'--receipt',str(evidence/'resources'),'--coordinator-receipt',str(evidence/'coordinator-owner.json')]
            owner.command=command
            owner.members=lambda group: []
            owner.properties=lambda unit: {'Id':unit,'Transient':'yes','MemoryMax':str(512*1024**2),
                'MemorySwapMax':'0','RuntimeMaxUSec':'600s','CPUQuotaPerSecUSec':'1s','InvocationID':'generation',
                'ActiveState':'active','SubState':'exited','MainPID':'0','ExecMainStartTimestampMonotonic':'1',
                'ExecMainExitTimestampMonotonic':'2','ControlGroup':'/system.slice/'+unit,'Result':'success','ExecMainStatus':'0'}
            for name in ('OwnedUnits','recover_containers','stop_expiry_owners','write_coordinator_receipt'):
                setattr(owner,name,object())
            proof=types.ModuleType('readback')
            proof.readback_with_model=lambda *a: events.append('readback')
            loaded={'hosted_owner':owner,'finite_stub_proof':types.SimpleNamespace(save=lambda *a:events.append('receipt')),
                'pins':{'recover_owner.py':'d6996140ddbb2896f00e357681b02f3478e50357c85d88f3981d63eee31de979'}}
            with patch.dict('sys.modules',{'readback':proof,'hosted_owner':owner}): caller.cleanup(root,evidence,loaded)
        self.assertEqual(events[-3:],['stop','readback','receipt'])
    def test_atomic_hook_and_unchanged_inner_launcher_arguments(self):
        p=caller.plan('/source','/evidence', '/runner.py','auth-identity-caller-1-1.service')
        self.assertEqual((p['runtime'],p['stop']),(3600,780))
        self.assertEqual(p['workload'][-4:],['-Lane','auth','-Stage','full'])
        self.assertIn('cleanup',p['cleanup'])
    def test_foreign_and_injected_identity_refused(self):
        for unit in ('foreign','auth-identity-caller-1-1\n'):
            with self.assertRaises(ValueError): caller.plan('/s','/e','/r',unit)
    def check_failure(self, primary):
        events=[]
        proof=types.ModuleType('readback')
        proof.readback_with_model=lambda *a: events.append('readback')
        owner=types.SimpleNamespace(command=lambda *a,**k: None)
        lifecycle=types.SimpleNamespace(save=lambda *a: events.append('receipt'))
        loaded={'hosted_owner':owner,'finite_stub_proof':lifecycle}
        with tempfile.TemporaryDirectory() as tmp, patch.dict('sys.modules',{'readback':proof}), \
             patch.object(Path,'read_bytes',side_effect=primary):
            with self.assertRaises(type(primary)) as caught: caller.cleanup('/source',Path(tmp),loaded)
            self.assertIs(caught.exception,primary)
        self.assertEqual(events,['readback','receipt'])
    def test_timeout_still_attempts_readback(self): self.check_failure(TimeoutError('modeled'))
    def test_cancellation_still_attempts_readback(self): self.check_failure(KeyboardInterrupt())
    def test_first_failure_still_attempts_readback(self): self.check_failure(ValueError('modeled'))

if __name__=='__main__': unittest.main()
