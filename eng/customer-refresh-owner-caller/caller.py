"""Source-only caller; manager owns shutdown cleanup before launcher birth."""
import argparse
import json
import os
from pathlib import Path
import re
import hashlib
import signal
import uuid
import sys
import time


def admission(env,memory,cgroup_v2):
    if env.get('GITHUB_REPOSITORY')!='MALIEV-Co-Ltd/Legacy.Maliev.AuthService' or \
       env.get('GITHUB_EVENT_NAME')!='workflow_dispatch' or \
       any(not re.fullmatch(r'[0-9]+',env.get(key,'')) for key in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT')) or \
       not re.fullmatch(r'[a-f0-9]{40}',env.get('GITHUB_SHA','')):
        raise RuntimeError('Exact manual Auth source identity required')
    match=re.search(r'^MemAvailable:\s+([0-9]+)\s+kB$',memory,re.M)
    if not match or int(match[1])<4194304 or not cgroup_v2:
        raise RuntimeError('Fresh 4096 MiB/cgroup-v2 admission failed before allocation')


def plan(source, evidence, runner, unit, description=None):
    source, evidence, runner = map(lambda p: str(Path(p).resolve()), (source,evidence,runner))
    if not re.fullmatch(r'auth-proof-caller-[0-9]+-[0-9]+\.service',unit):
        raise ValueError('Exact caller unit required')
    for value in (source,evidence,runner):
        if any(c in value for c in '\n\r\0'): raise ValueError('Invalid path')
    description=description or 'AuthProofCaller:'+unit+':'+uuid.uuid4().hex
    if not re.fullmatch(r'AuthProofCaller:'+re.escape(unit)+r':[a-f0-9]{32}',description):
        raise ValueError('Exact caller nonce required')
    adapter = Path(source)/'eng/customer-refresh-no-sdk-adapter-v2-20261009'
    launcher = str(Path(evidence).with_suffix('.launcher.ps1'))
    # ExecStopPost is part of the same atomic manager registration as ExecStart.
    # Recovery remains separately manager-owned and capped by the original API.
    cleanup = ['/usr/bin/python3','-B',runner,'--role','cleanup','--source',source,'--evidence',evidence]
    workload = ['/usr/bin/pwsh','-NoProfile','-File',launcher,'-SourceCheckouts',source,
                '-EvidenceRoot',evidence,'-Lane','auth','-Stage','proof']
    return dict(unit=unit,description=description,launcher=launcher,adapter=str(adapter),cleanup=cleanup,workload=workload,
                runtime=3600,stop=780,memory=512*1024**2)


def completed_recovery(evidence,run):
    path = evidence/'resources/external-cleanup.json'
    if not path.exists(): return False
    row = json.loads(path.read_bytes())
    return row.get('schemaVersion') == 1 and row.get('run') == run and \
        type(row.get('remainingResources')) is int and row['remainingResources'] == 0 and \
        all(row.get(key) is True for key in ('sdkQuiescent','containersAbsent','expiryQuiescent')) and \
        row.get('currentCleanupFailures') == []


def persist_exclusive(path,row):
    with path.open('x',encoding='utf-8') as stream:
        json.dump(row,stream,sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


def intent_path(evidence):
    return Path(str(evidence)+'.caller-intent.json')


def configured_command(owner,unit,field):
    if field not in ('ExecStart','ExecStopPost'): raise ValueError('Unknown command field')
    reader=owner._recovery_reader
    original=reader.command
    def command(argv,**kwargs):
        if argv[:4]==['/usr/bin/busctl','--json=short','get-property','org.freedesktop.systemd1'] and argv[-1]=='ExecStart':
            argv=[*argv[:-1],field]
        return owner.command(argv,**kwargs)
    reader.command=command
    try:return reader.coordinator_command(unit)
    finally:reader.command=original


def extra_properties(owner,unit):
    fields=('ControlPID','TasksMax','TimeoutStopUSec')
    text=owner.command(['/usr/bin/systemctl','show',unit,'--property='+','.join(fields)])
    result={}
    for line in text.splitlines():
        key,value=line.split('=',1)
        if key not in fields or key in result: raise RuntimeError('Ambiguous caller property')
        result[key]=value
    if set(result)!=set(fields): raise RuntimeError('Incomplete caller properties')
    return result


def verify_intent(p,owner,hook=False):
    if hashlib.sha256(Path(p['cleanup'][2]).read_bytes()).hexdigest()!=p['callerSha256'] or \
       hashlib.sha256(Path(p['launcher']).read_bytes()).hexdigest()!=p['launcherSha256']:
        raise RuntimeError('Caller source changed')
    actual=owner.properties(p['unit'])
    extra=extra_properties(owner,p['unit'])
    if actual['Id']!=p['unit'] or actual['Description']!=p['description'] or actual['Transient']!='yes' or not actual['InvocationID'] or \
       actual['MemoryMax']!=str(p['memory']) or actual['MemorySwapMax']!='0' or \
       actual['RuntimeMaxUSec'] not in ('1h','3600s') or actual['CPUQuotaPerSecUSec']!='1s' or \
       extra['TasksMax']!='64' or extra['TimeoutStopUSec'] not in ('13min','780s') or \
       actual['ControlGroup']!='/system.slice/'+p['unit']:
        raise RuntimeError('Caller identity/caps changed')
    for field,key in (('ExecStart','workload'),('ExecStopPost','cleanup')):
        expected={'path':p[key][0],'arguments':p[key],'ignoreErrors':False}
        if configured_command(owner,p['unit'],field)!=expected: raise RuntimeError('Caller command changed')
    binding={'invocationId':actual['InvocationID'],'cgroup':actual['ControlGroup']}
    if hook:
        pid=os.getpid()
        if int(extra['ControlPID'])!=pid:
            raise RuntimeError('Cleanup PID is not the registered manager control process')
        stat=Path(f'/proc/{pid}/stat')
        before=stat.read_text().rsplit(')',1)[1].split()[19]
        executable=os.readlink(f'/proc/{pid}/exe')
        argv=Path(f'/proc/{pid}/cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
        group=Path(f'/proc/{pid}/cgroup').read_text().strip()
        after=stat.read_text().rsplit(')',1)[1].split()[19]
        if before!=after or group!='0::'+binding['cgroup'] or \
           executable!=os.path.realpath(p['cleanup'][0]) or argv[1:]!=p['cleanup'][1:]:
            raise RuntimeError('Cleanup must be actual manager-owned hook generation')
        binding.update(pid=pid,startTicks=before,executable=executable,arguments=argv[1:])
    return binding


def hook_admission(source,evidence,loaded):
    path=intent_path(evidence)
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink!=1 or path.stat().st_uid!=0:
        raise RuntimeError('Root-owned durable caller intent required')
    p=json.loads(path.read_bytes())
    expected=plan(source,evidence,Path(__file__),p['unit'],p.get('description'))
    if any(p.get(k)!=v for k,v in expected.items()) or p.get('backendPins')!=loaded['pins'] or \
       not re.fullmatch(r'[a-f0-9]{40}',p.get('executionCommit','')) or p['executionCommit']!=os.environ.get('GITHUB_SHA'):
        raise RuntimeError('Caller intent scope differs')
    binding=verify_intent(p,loaded['hosted_owner'],hook=True)
    evidence.mkdir(exist_ok=True)
    persist_exclusive(evidence/'caller-hook-owner.json',binding)
    return p


def manager_arguments(p,owner,environment):
    hook=' '.join(owner.quote(value) for value in p['cleanup'])
    return ['/usr/bin/systemd-run','--wait','--collect','--unit='+p['unit'],'--description='+p['description'],'--service-type=exec',
        '--property=MemoryMax=512M','--property=MemorySwapMax=0','--property=CPUQuota=100%',
        '--property=TasksMax=64','--property=RuntimeMaxSec=3600','--property=TimeoutStopSec=780',
        '--property=KillMode=control-group','--property=SendSIGKILL=yes',
        '--property=LimitCORE=0','--property=LimitFSIZE=268435456','--property=SuccessExitStatus=1',
        '--property=ExecStopPost='+hook,*environment,*p['workload']]


def finish_caller(p,evidence,loaded):
    owner=loaded['hosted_owner']
    proof=loaded['finite_stub_proof']
    rows=proof.registered_manager_units([p['unit']],timeout=5)
    if rows:
        binding=verify_intent(p,owner)
        hook=evidence/'caller-hook-owner.json'
        if hook.exists() and json.loads(hook.read_bytes())['invocationId']!=binding['invocationId']:
            raise RuntimeError('Caller invocation reused')
        owner.command(['/usr/bin/systemctl','stop',p['unit']],timeout=810)
    deadline=time.monotonic()+10
    while True:
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError('Caller manager absence unknown')
        rows=proof.registered_manager_units([p['unit']],timeout=remaining)
        if time.monotonic()>=deadline: raise TimeoutError('Caller absence observed late')
        if not rows: break
        time.sleep(.1)
    evidence.mkdir(exist_ok=True)
    proof.save(evidence/'caller-absence.json',{'unit':p['unit'],'managerAbsent':True,'nativeAccepted':False})


def run_dispatch(p,evidence,loaded,environment):
    first=None
    try:
        loaded['hosted_owner'].command(manager_arguments(p,loaded['hosted_owner'],environment),timeout=4380)
    except BaseException as error:
        first=error
    finally:
        try: finish_caller(p,evidence,loaded)
        except BaseException as error:
            if first is None: first=error
            else: first.caller_cleanup_failure=type(error).__name__
    # SuccessExitStatus=1 only tolerates the intentional launcher failure; require
    # actual hook/readback/physical-cleanup receipts independently before success.
    try:
        row=json.loads((evidence/'caller-cleanup.json').read_bytes())
        physical=json.loads((evidence/'stub-lifecycle-readback.json').read_bytes())
        if row['failures'] or physical.get('lifecycleProofAccepted') is not True or \
           any(physical.get(key) is not True for key in
               ('runtimeRootAbsent','registeredFragmentsAbsent','registeredUnitsAbsent')) or \
           type(physical.get('remainingResources')) is not int or physical['remainingResources']!=0:
            raise RuntimeError('Actual hook and physical readback not accepted')
    except BaseException as error:
        if first is None: first=error
    try:
        evidence.mkdir(exist_ok=True)
        loaded['finite_stub_proof'].save(evidence/'caller-final.json',
            {'firstFailure':type(first).__name__ if first is not None else None,
             'cleanupFailure':getattr(first,'caller_cleanup_failure',None),
             'nativeAccepted':False,'customerRuntimeAccepted':False})
    except BaseException as error:
        if first is None:first=error
        else:first.caller_receipt_failure=type(error).__name__
    if first is not None: raise first


def admitted_dispatch(p,evidence,loaded,environment,env,memory,cgroup_v2):
    admission(env,memory,cgroup_v2)
    persist_exclusive(intent_path(evidence),p)
    return run_dispatch(p,evidence,loaded,environment)


def recover_registered(source,evidence,loaded):
    owner = loaded['hosted_owner']
    receipt = json.loads((evidence/'coordinator-owner.json').read_bytes())
    run = receipt['run']
    if not re.fullmatch(r'auth-financial-[0-9]+-[0-9]+-[a-f0-9]{12}',run):
        raise ValueError('Exact retained run required')
    if completed_recovery(evidence,run): return
    unit = run+'-recovery.service'
    script = str(Path(source)/'eng/financial-iam/recover_owner.py')
    argv = ['/usr/bin/python3','-B',script,'--run',run,'--receipt',str(evidence/'resources'),
            '--coordinator-receipt',str(evidence/'coordinator-owner.json')]
    # Use the existing typed immutable command reader rather than display text.
    import types
    raw = (Path(source)/'eng/financial-iam/recover_owner.py').read_bytes()
    import hashlib
    if hashlib.sha256(raw).hexdigest() != loaded['pins']['recover_owner.py']:
        raise ValueError('Recovery source changed')
    recovery = types.ModuleType('pinned_recovery')
    exec(compile(raw,script,'exec'),recovery.__dict__)
    state = owner.command(['/usr/bin/systemctl','show',unit,'--property=LoadState','--value']).strip()
    if state == 'not-found':
        owner.command(['/usr/bin/systemd-run','--unit='+unit,'--service-type=exec','--remain-after-exit',
            '--property=MemoryMax=512M','--property=MemorySwapMax=0','--property=CPUQuota=100%',
            '--property=TasksMax=64','--property=RuntimeMaxSec=600','--property=TimeoutStopSec=30',
            '--property=KillMode=control-group','--property=SendSIGKILL=yes',
            '--property=LimitCORE=0','--property=LimitFSIZE=268435456',*argv])
    elif state != 'loaded':
        raise RuntimeError('Recovery manager identity unavailable')
    configured = recovery.coordinator_command(unit)
    if configured != {'path':argv[0],'arguments':argv,'ignoreErrors':False}:
        raise RuntimeError('Recovery command differs')
    deadline = time.monotonic()+630
    invocation = None
    while True:
        actual = owner.properties(unit)
        if actual['Id'] != unit or actual['Transient'] != 'yes' or \
           actual['MemoryMax'] != str(512*1024**2) or actual['MemorySwapMax'] != '0' or \
           actual['RuntimeMaxUSec'] not in ('10min','600s') or \
           actual['CPUQuotaPerSecUSec'] != '1s':
            raise RuntimeError('Recovery caps/identity differ')
        if owner.command(['/usr/bin/systemctl','show',unit,'--property=TasksMax','--value']).strip() != '64':
            raise RuntimeError('Recovery task cap differs')
        if not actual['InvocationID'] or invocation and actual['InvocationID'] != invocation:
            raise RuntimeError('Recovery generation differs')
        invocation = actual['InvocationID']
        if actual['ActiveState'] in ('inactive','failed') or actual['SubState'] == 'exited':
            if int(actual['MainPID']) or int(actual['ExecMainStartTimestampMonotonic']) <= 0 or \
               int(actual['ExecMainExitTimestampMonotonic']) < int(actual['ExecMainStartTimestampMonotonic']) or \
               actual['ControlGroup'] and owner.members(actual['ControlGroup']):
                raise RuntimeError('Recovery exit/empty cgroup unproved')
            if actual['Result'] != 'success' or actual['ExecMainStatus'] != '0':
                raise RuntimeError('Recovery failed')
            owner.command(['/usr/bin/systemctl','stop',unit],timeout=30)
            break
        if time.monotonic() >= deadline: raise TimeoutError('Recovery observation deadline')
        time.sleep(.25)


def cleanup(source,evidence,loaded):
    """Attempt independent recovery, then physical readback despite first failure."""
    owner = loaded['hosted_owner']
    evidence = Path(evidence)
    first = None
    failures = []
    try:
        recover_registered(source,evidence,loaded)
    except BaseException as error:
        first = error
        failures.append('recovery:'+type(error).__name__)
    try:
        import auth_proof
        auth_proof.readback_with_model(loaded,evidence,
            Path(source)/'eng/customer-refresh-native-create-policy-v1-20261009/create_policy.py')
    except BaseException as error:
        if first is None: first = error
        failures.append('readback:'+type(error).__name__)
    try:
        loaded['finite_stub_proof'].save(evidence/'caller-cleanup.json',
            {'failures':failures,'nativeAccepted':False,'customerRuntimeAccepted':False})
    except BaseException as error:
        if first is None: first = error
    if first is not None: raise first


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--role',choices=('dispatch','cleanup'),required=True)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--evidence',type=Path,required=True)
    args = parser.parse_args()
    if os.name != 'posix' or os.geteuid() != 0: raise RuntimeError('Linux root manager caller required')
    sys.path.insert(0,str(args.source/'eng/customer-refresh-no-sdk-adapter-v2-20261009'))
    import shared_backend
    loaded = shared_backend.modules(args.source/'eng/financial-iam')
    loaded['pins'] = shared_backend.PINS
    captured=shared_backend.capture(args.source/'eng/financial-iam')
    with shared_backend.bind_loaded(loaded):
        import types
        reader=types.ModuleType('captured_recovery_reader')
        exec(compile(captured['recover_owner.py'],str(args.source/'eng/financial-iam/recover_owner.py'),'exec'),reader.__dict__)
        loaded['hosted_owner']._recovery_reader=reader
        if args.role == 'cleanup':
            hook_admission(args.source,args.evidence,loaded)
            return cleanup(args.source,args.evidence,loaded)
        runid, attempt = os.environ['GITHUB_RUN_ID'],os.environ['GITHUB_RUN_ATTEMPT']
        p = plan(args.source,args.evidence,Path(__file__),f'auth-proof-caller-{runid}-{attempt}.service')
        if args.evidence.exists(): raise ValueError('Fresh evidence required')
        raw = shared_backend.capture(args.source/'eng/financial-iam')
        text = shared_backend.launcher_source(raw['Start-FinancialIamHostedOwner.ps1'],
            args.source/'eng/financial-iam',Path(p['adapter'])/'auth_owner.py')
        with Path(p['launcher']).open('x',encoding='utf-8') as stream: stream.write(text)
        owner = loaded['hosted_owner']
        if owner.command(['/usr/bin/systemctl','show',p['unit'],'--property=LoadState','--value']).strip() != 'not-found':
            raise RuntimeError('Existing caller refused')
        environment = ['--setenv='+key+'='+os.environ[key] for key in
            ('GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_REPOSITORY','GITHUB_EVENT_NAME')]
        p.update(callerSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 launcherSha256=hashlib.sha256(Path(p['launcher']).read_bytes()).hexdigest(),
                 backendPins=loaded['pins'],executionCommit=os.environ['GITHUB_SHA'])
        previous=signal.getsignal(signal.SIGTERM)
        def cancel(signum,frame):
            signal.signal(signal.SIGTERM,signal.SIG_IGN)
            raise KeyboardInterrupt('Caller cancelled')
        signal.signal(signal.SIGTERM,cancel)
        try: admitted_dispatch(p,args.evidence,loaded,environment,os.environ,
            Path('/proc/meminfo').read_text(),Path('/sys/fs/cgroup/cgroup.controllers').is_file())
        finally: signal.signal(signal.SIGTERM,previous)

if __name__ == '__main__': main()
