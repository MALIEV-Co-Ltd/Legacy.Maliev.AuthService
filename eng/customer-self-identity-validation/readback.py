"""Recover/read physical resources first; retain validation failure separately."""
import ast
import json
from pathlib import Path
import types

def readback(loaded,evidence,source):
    first=None;failures=[];physical=None
    try:
        raw=(Path(source)/'eng/financial-iam/finite_stub_proof.py').read_bytes()
        import hashlib
        if hashlib.sha256(raw).hexdigest()!=loaded['pins']['finite_stub_proof.py']:raise ValueError('Physical reader changed')
        tree=ast.parse(raw)
        function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='physical_cleanup')
        # Only the stage binding changes. All actual ownership, generation,
        # mounts, exact-unit inventory and deletion fences remain retained.
        count=0
        for node in ast.walk(function):
            if isinstance(node,ast.Constant) and node.value=='proof':node.value='full';count+=1
        if count!=1:raise ValueError('Exact physical stage hook required')
        private=types.ModuleType('cs9_physical_readback');private.__dict__.update(loaded['finite_stub_proof'].__dict__)
        exec(compile(ast.Module(body=[function],type_ignores=[]),'retained-physical-cleanup','exec'),private.__dict__)
        containers=json.loads((evidence/'resources/containers.json').read_bytes())
        admission_failed=bool(containers.get('failures'))
        for row in containers.get('containers',{}).values():
            if any(m.get('Type')!='tmpfs' for m in row['mounts']):raise ValueError('Persistent data prevents disposable-root removal')
        physical=private.physical_cleanup(evidence)
        if admission_failed:raise ValueError('Private admission failure retained after physical cleanup')
    except BaseException as error:first=error;failures.append('physical:'+type(error).__name__)
    try:
        result=json.loads((evidence/'resources/cs9-results/result.json').read_bytes())
        units=json.loads((evidence/'resources/units.json').read_bytes())
        row=units['units'][result['run']+'-sdk.service']
        identity=result['identity'];actual=row['mainProcess']
        if row.get('exitCode')!='0' or row.get('result')!='success' or any(identity[k]!=actual[k] for k in ('pid','startTicks','executable')) or identity['cgroup']!='0::'+actual['cgroup']:
            raise ValueError('Actual SDK generation/exit differs')
        if result['focused']!=3 or result['full']!=936 or result['coverage']!=936 or result['warnings'] or result['errors']:
            raise ValueError('Exact Auth validation evidence required')
    except BaseException as error:
        if first is None:first=error
        failures.append('validation:'+type(error).__name__)
    loaded['finite_stub_proof'].save(evidence/'auth-sdk-readback.json',{'lifecycleProofAccepted':not failures,'failures':failures,**(physical or {}),'nativeAccepted':False,'customerRuntimeAccepted':False})
    if first is not None:raise first

def readback_with_model(loaded,evidence,unused_policy):
    # Called by the retained caller cleanup after independent recovery.
    readback(loaded,evidence,Path(unused_policy).parents[2])
