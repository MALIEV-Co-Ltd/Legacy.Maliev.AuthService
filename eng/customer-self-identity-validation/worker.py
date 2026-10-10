"""Exact Auth build-first/focused/full/static/coverage sequence, no deployment."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from route import BASE,materialize

GRAPH={
 'Legacy.Maliev.ServiceDefaults':'7edcd961024868513fd5f373cab3dcb261197f77',
 'Legacy.Maliev.CompatibilityContracts':'78e48ffc4ee000df0510cba5e7c7a3c4c4d539d7',
 'Legacy.Maliev.CustomerService':'4eedecd81d1d8dcb4f38d8f76e51e7e9cb2110be',
 'Maliev.IAMService':'4fe6642e5674013de9a3672505aec898fdcae0ed',
 'GenuineIamDefaults':'7b3099bf67d0f17e56cfdb3dcf36541304abaac2',
 'Maliev.Aspire':'01d506203763b914e237268a8746f1406423df86',
 'Maliev.MessagingContracts':'559a00db0c7920a5247fdff60d4476ad23a9a501',
}
NEW_CASE='Legacy.Maliev.AuthService.Tests.CustomerSelfIdentityTests.NormalWebIdentityUserPolicy_CurrentInitialPasswordState_RechecksPreviouslyIssuedTokenWithoutMutatingIdentity'

# Closed native display collision roster; exact current Auth source witness.
DUPLICATE_SOURCE_PATH='Legacy.Maliev.AuthService.Tests/QualificationIntrospectionHttpTests.cs'
DUPLICATE_SOURCE_SHA='7980b8fbed56e9bc6c9ff752e50a31591b949cf819d44d4f42caf84735f0f444'
DUPLICATE_ROSTER={'Legacy.Maliev.AuthService.Tests.QualificationIntrospectionHttpTests.InvalidInput_IsBoundedGeneric400(json: "{\\"employeeAccessToken\\":\\"a\\",\\"permission\\":\\"le"···)': {'className': 'Legacy.Maliev.AuthService.Tests.QualificationIntrospectionHttpTests', 'methodName': 'InvalidInput_IsBoundedGeneric400', 'count': 3}}

def duplicate_source(auth):
    if hashlib.sha256((auth/DUPLICATE_SOURCE_PATH).read_bytes()).hexdigest()!=DUPLICATE_SOURCE_SHA:
        raise ValueError('Closed duplicate roster source witness changed')

def trx(path,count,new_case=False,roster=None,check_assembly=True):
    root=ET.parse(path).getroot()
    ns='{http://microsoft.com/schemas/VisualStudio/TeamTest/2010}'
    def require(ok):
        if not ok:raise ValueError('Exact passing raw TRX inventory and joins required')
    def one(parent,name):
        rows=parent.findall(ns+name);require(len(rows)==1);return rows[0]
    require(root.tag==ns+'TestRun' and type(count) is int and count>0)
    summary=one(root,'ResultSummary');require(summary.get('outcome')=='Completed')
    counters=one(summary,'Counters')
    keys={'total','executed','passed','failed','error','timeout','aborted','inconclusive','passedButRunAborted','notRunnable','notExecuted','disconnected','warning','completed','inProgress','pending'}
    require(set(counters.attrib)==keys and all(re.fullmatch(r'0|[1-9][0-9]*',v) for v in counters.attrib.values()))
    c={k:int(v) for k,v in counters.attrib.items()}
    require(all(v==(count if k in {'total','executed','passed'} else 0) for k,v in c.items()))
    def inventory(box,tag):
        parent=one(root,box);rows=list(parent)
        require(len(rows)==count and all(n.tag==ns+tag for n in rows))
        require(len(list(root.iter(ns+tag)))==count)
        return rows
    results=inventory('Results','UnitTestResult');definitions=inventory('TestDefinitions','UnitTest');entries=inventory('TestEntries','TestEntry')
    require(len(list(root.iter(ns+'Counters')))==1)
    def identity(value):
        require(isinstance(value,str))
        try:require(str(uuid.UUID(value))==value.lower())
        except (ValueError,AttributeError):raise ValueError('Canonical TRX identity required') from None
        return value.lower()
    def index(rows,key):
        values=[identity(n.get(key)) for n in rows];require(len(set(values))==count)
        return dict(zip(values,rows))
    r=index(results,'testId');d=index(definitions,'id');e=index(entries,'testId')
    require(r.keys()==d.keys()==e.keys())
    executions=[];names=[];methods={}
    for key,row in r.items():
        definition=d[key];entry=e[key];execution=one(definition,'Execution');method=one(definition,'TestMethod')
        eid=identity(row.get('executionId'));executions.append(eid)
        require(eid==identity(execution.get('id'))==identity(entry.get('executionId')))
        name=row.get('testName');require(bool(name) and name==definition.get('name'));names.append(name)
        prefix=(method.get('className') or '')+'.'+(method.get('name') or '')
        require(bool(method.get('className')) and bool(method.get('name')) and (name==prefix or (name.startswith(prefix+'(') and name.endswith(')'))))
        methods.setdefault(name,set()).add((method.get('className'),method.get('name')))
        require(row.get('outcome')=='Passed' and bool(row.get('testListId')) and row.get('testListId')==entry.get('testListId'))
    require(len(set(executions))==count)
    for name in set(names):
        multiplicity=names.count(name)
        if multiplicity>1 or name in DUPLICATE_ROSTER:
            allowed=DUPLICATE_ROSTER.get(name)
            require(allowed is not None and multiplicity==allowed['count'] and methods[name]=={(allowed['className'],allowed['methodName'])})
    if new_case:require(names.count(NEW_CASE)==1)
    if roster is not None:
        validate_roster(roster)
        require(count==len(roster['cases']) and Counter(names)==Counter(roster['cases']))
        require(all(one(definition,'TestMethod').get('codeBase')==roster['assemblyPath'] for definition in definitions))
        if check_assembly:require(compiled_sha(Path(roster['assemblyPath']))==roster['assemblySha256'])
    return c

PREFIX='Legacy.Maliev.AuthService.Tests.'
ASSEMBLY='Legacy.Maliev.AuthService.Tests.dll'
DELETE_METHOD=PREFIX+'CustomerIdentityAdminTests.Delete_WaitsForCurrentOwnerAndPreservesExistingControllerOutcomes'
DELETE_ROUTE=PREFIX+'CustomerIdentityAdminTests.Delete_PreservesExistingPermissionEmployeePolicyAndRoute'
FOCUSED_CASES=(DELETE_METHOD+'(contender: "update")',DELETE_METHOD+'(contender: "delete")',DELETE_ROUTE)
FOCUSED_FILTER='FullyQualifiedName='+DELETE_METHOD+'|FullyQualifiedName='+DELETE_ROUTE

def compiled_sha(path):
    if path.name!=ASSEMBLY or path.is_symlink() or not path.is_file() or path.stat().st_nlink!=1 or path.stat().st_size>64*1024*1024:raise ValueError('Regular bounded compiled Auth assembly required')
    with path.open('rb') as stream:raw=stream.read(64*1024*1024+1)
    if not raw or len(raw)>64*1024*1024:raise ValueError('Compiled Auth assembly bound')
    return hashlib.sha256(raw).hexdigest()

def validate_roster(roster):
    keys={'schemaVersion','assemblyPath','assemblySha256','listingSha256','cases'}
    if type(roster) is not dict or set(roster)!=keys or type(roster['schemaVersion']) is not int or roster['schemaVersion']!=1 or type(roster['assemblyPath']) is not str or not Path(roster['assemblyPath']).is_absolute() or Path(roster['assemblyPath']).name!=ASSEMBLY:raise ValueError('Exact compiled discovery record required')
    for field in ('assemblySha256','listingSha256'):
        if type(roster[field]) is not str or not re.fullmatch('[a-f0-9]{64}',roster[field]):raise ValueError('Exact discovery digest required')
    cases=roster['cases']
    if type(cases) is not list or not 0<len(cases)<=4096 or any(type(n) is not str or not n.startswith(PREFIX) or len(n)>2048 for n in cases):raise ValueError('Bounded Auth discovery names required')
    for name,count in Counter(cases).items():
        if count>1:
            allowed=DUPLICATE_ROSTER.get(name)
            if allowed is None or count!=allowed['count']:raise ValueError('Unreviewed discovery collision')
    return roster

def capture_discovery(assembly,listing):
    path=Path(listing)
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink!=1 or path.stat().st_size>1024*1024:raise ValueError('Regular bounded discovery listing required')
    with path.open('rb') as stream:raw=stream.read(1024*1024+1)
    if len(raw)>1024*1024:raise ValueError('Discovery listing bound')
    lines=raw.decode('utf-8-sig').splitlines();marker='The following Tests are available:'
    if lines.count(marker)!=1:raise ValueError('One actual VSTest discovery section required')
    cases=[line.strip() for line in lines[lines.index(marker)+1:] if line.strip()]
    roster={'schemaVersion':1,'assemblyPath':str(Path(assembly).resolve(strict=True)),'assemblySha256':compiled_sha(Path(assembly)),'listingSha256':hashlib.sha256(raw).hexdigest(),'cases':cases}
    validate_roster(roster)
    if any(cases.count(name)!=1 for name in FOCUSED_CASES) or cases.count(NEW_CASE)!=1:raise ValueError('Current composed cases missing from compiled discovery')
    return roster

def focused_roster(roster):
    validate_roster(roster)
    if any(roster['cases'].count(name)!=1 for name in FOCUSED_CASES):raise ValueError('Exact three discovered delete cases required')
    return dict(roster,cases=list(FOCUSED_CASES))

def verify_retained_results(results,result):
    results=Path(results);raw=(results/'discovery.json').read_bytes()
    if len(raw)>1024*1024 or hashlib.sha256(raw).hexdigest()!=result['discoverySha256']:raise ValueError('Retained discovery identity changed')
    roster=json.loads(raw);validate_roster(roster);focused=focused_roster(roster)
    if roster['assemblySha256']!=result['assemblySha256'] or roster['listingSha256']!=result['listingSha256'] or hashlib.sha256((results/'discovery.log').read_bytes()).hexdigest()!=roster['listingSha256']:raise ValueError('Compiled/listing identity join changed')
    if type(result['focused']) is not int or type(result['full']) is not int or type(result['coverage']) is not int or result['focused']!=len(focused['cases']) or result['full']!=len(roster['cases']) or result['coverage']!=len(roster['cases']) or result['base']!=BASE:raise ValueError('Actual discovered counts required')
    trx(results/'focused/focused.trx',len(focused['cases']),False,focused,False)
    trx(results/'full/full.trx',len(roster['cases']),True,roster,False)
    trx(results/'coverage/coverage.trx',len(roster['cases']),True,roster,False)
    return {'focused':len(focused['cases']),'full':len(roster['cases']),'coverage':len(roster['cases']),'assemblySha256':roster['assemblySha256']}

def main():
    p=argparse.ArgumentParser(allow_abbrev=False)
    for key in ('source','destination','receipts','context'):p.add_argument('--'+key,type=Path,required=True)
    a=p.parse_args();deadline=time.monotonic()+1900
    context=json.loads(a.context.read_bytes())
    actual=Path('/proc/self/cgroup').read_text().strip()
    if context['schemaVersion']!=3 or actual!='0::'+context['sdkCgroup'] or os.environ.get('DOCKER_HOST')!=context['dockerHost']:
        raise ValueError('Actual owned SDK and private Docker custody required')
    caproot=Path('/sys/fs/cgroup')/context['sdkCgroup'].lstrip('/')
    expected={'memory.max':str(3*1024**3),'memory.swap.max':'0','cpu.max':'100000 100000','pids.max':'512'}
    if {n:(caproot/n).read_text().strip() for n in expected}!=expected:raise ValueError('Original actual SDK caps required')
    if a.destination.exists():raise ValueError('Fresh materialized root required')
    a.destination.mkdir();results=a.receipts/'cs9-results';results.mkdir()
    def run(argv,cwd,phase,limit):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('Owned validation deadline')
        with (results/(phase+'.log')).open('xb') as log:
            r=subprocess.run(argv,cwd=cwd,stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,timeout=min(remaining,limit),env=env)
        if r.returncode:raise RuntimeError('Validation phase failed: '+phase)
        return (results/(phase+'.log')).read_text(errors='strict')
    env=dict(os.environ,GITHUB_ACTIONS='false',UseLocalMalievDependencies='true',MalievWorkspaceRoot=str(a.destination/'.dependencies'),DOTNET_CLI_UI_LANGUAGE='en',DOTNET_SYSTEM_CONSOLE_ALLOW_ANSI_COLOR_REDIRECTION='0',NO_COLOR='1')
    snapshots=a.source/'.source-checkouts';auth=a.destination/'Legacy.Maliev.AuthService'
    for name,sha in {'Legacy.Maliev.AuthService':BASE,**GRAPH}.items():
        source=snapshots/name
        if subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],timeout=30).decode().strip()!=sha or subprocess.check_output(['git','-C',str(source),'status','--porcelain','--untracked-files=all'],timeout=30):raise ValueError('Exact clean dependency snapshot required')
        target=auth if name=='Legacy.Maliev.AuthService' else a.destination/'.dependencies'/name
        target.parent.mkdir(parents=True,exist_ok=True)
        run(['git','clone','--no-hardlinks','--no-checkout',str(source),str(target)],a.destination,'clone-'+name,30)
        run(['git','-c','core.autocrlf=false','checkout','--detach',sha],target,'checkout-'+name,30)
    intake=materialize(a.source,auth)
    duplicate_source(auth)
    (results/'intake.json').write_text(json.dumps(intake,sort_keys=True))
    adapter=__import__('route').module(a.source/'eng/customer-self-identity-intake/controls/intake_adapter.py','captured_cs9_tree')
    backend=adapter.load_backend(auth);tree=backend.tree_digest(auth)
    def stable():
        if backend.tree_digest(auth)!=tree:raise ValueError('Materialized source changed')
    run(['/usr/bin/pwsh','-NoProfile','-File','eng/Prepare-GenuineIamHttpSource.ps1','-CommittedSourceRoot',str(a.destination/'.dependencies')],auth,'prepare-genuine',60)
    tools=snapshots/'Legacy.Maliev.Workflows'
    if subprocess.check_output(['git','-C',str(tools),'rev-parse','HEAD'],timeout=30).decode().strip()!='e3a6093324a24968876782153286f52db8b29fd8':raise ValueError('Original trusted scanner source required')
    if subprocess.check_output(['git','-C',str(tools),'status','--porcelain','--untracked-files=all'],timeout=30):raise ValueError('Clean trusted scanner checkout required')
    for scanner in ('Invoke-JwtSigningResourceScan.ps1','Invoke-CurrentTreeCredentialScan.ps1'):
        run(['/usr/bin/pwsh','-NoProfile','-File',str(tools/'scripts'/scanner),'-RepositoryPath',str(auth)],auth,'scan-'+scanner,60)
    env['GOBIN']=str(a.destination/'owned-tools');env['GOTOOLCHAIN']='go1.26.9'
    Path(env['GOBIN']).mkdir()
    run(['go','install','github.com/zricethezav/gitleaks/v8@6eaad039603a4de39fddd1cf5f727391efe9974e'],auth,'install-scanner',180)
    for kind in ('git','dir'):
        run([str(Path(env['GOBIN'])/'gitleaks'),kind,'--redact','--exit-code','1',str(auth)],auth,'gitleaks-'+kind,60)
    common=['--configuration','Release','-p:UseLocalMalievDependencies=true','-p:MalievWorkspaceRoot='+env['MalievWorkspaceRoot']]
    build=run(['dotnet','build','Legacy.Maliev.AuthService.slnx','--warnaserror','--disable-build-servers','-m:1','-nodeReuse:false','-p:UseSharedCompilation=false',*common],auth,'build-first',600)
    for token in ('Warning','Error'):
        values=re.findall(r'(\d+) '+token+r'\(s\)',build)
        if not values or any(int(v) for v in values):raise ValueError('Zero build warnings/errors required')
    stable();project='Legacy.Maliev.AuthService.Tests/Legacy.Maliev.AuthService.Tests.csproj'
    assembly=auth/'Legacy.Maliev.AuthService.Tests/bin/Release/net10.0'/ASSEMBLY
    run(['dotnet','test',project,*common,'--no-build','--no-restore','--list-tests'],auth,'discovery',120)
    roster=capture_discovery(assembly,results/'discovery.log');focused=focused_roster(roster)
    discovery_raw=json.dumps(roster,sort_keys=True).encode();(results/'discovery.json').write_bytes(discovery_raw)
    stable()
    def discovery_stable():
        if compiled_sha(assembly)!=roster['assemblySha256'] or hashlib.sha256((results/'discovery.log').read_bytes()).hexdigest()!=roster['listingSha256'] or (results/'discovery.json').read_bytes()!=discovery_raw:raise ValueError('Compiled discovery custody changed')
    def test(name,selected,extras,new_case=False):
        discovery_stable()
        run(['dotnet','test',project,*common,'--no-build','--no-restore','--logger','trx;LogFileName='+name+'.trx','--results-directory',str(results/name),*extras],auth,name,700)
        trx(results/name/(name+'.trx'),len(selected['cases']),new_case,selected);stable();discovery_stable()
    test('focused',focused,['--filter',FOCUSED_FILTER])
    test('full',roster,[],True)
    run(['dotnet','format','Legacy.Maliev.AuthService.slnx','--verify-no-changes','--no-restore'],auth,'format',180);stable()
    audit=run(['dotnet','list','Legacy.Maliev.AuthService.slnx','package','--vulnerable','--include-transitive','--no-restore'],auth,'audit',60)
    if audit.count('has no vulnerable packages given the current sources.')!=5:raise ValueError('Five clean dependency audits required')
    test('coverage',roster,['--collect','XPlat Code Coverage','--settings','eng/coverage.runsettings'],True)
    run(['/usr/bin/pwsh','-NoProfile','-Command',"$ErrorActionPreference='Stop'; $reports=@(& ./eng/Get-OwnedCoverageReport.ps1 -ResultsDirectory '"+str(results/'coverage')+"'); if($reports.Count -ne 1){throw 'Exact coverage report required'}; & ./eng/Assert-OwnedCoverage.ps1 -CoveragePath $reports[0].FullName; & ./eng/Export-CoverageEvidence.ps1 -ResultsDirectory '"+str(results/'coverage')+"' -OutputDirectory '"+str(results/'coverage-evidence')+"'"],auth,'coverage-gate',60);stable()
    stat=Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]
    (results/'result.json').write_text(json.dumps({'base':BASE,'treeSha256':tree,'focused':len(focused['cases']),'full':len(roster['cases']),'coverage':len(roster['cases']),'assemblySha256':roster['assemblySha256'],'listingSha256':roster['listingSha256'],'discoverySha256':hashlib.sha256(discovery_raw).hexdigest(),'warnings':0,'errors':0,'identity':{'pid':os.getpid(),'startTicks':stat,'executable':os.readlink('/proc/self/exe'),'cgroup':actual,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip()},'caps':expected,'run':context['owner'],'sourceCommit':os.environ['GITHUB_SHA'],'nativeAccepted':False,'customerRuntimeAccepted':False},sort_keys=True))

if __name__=='__main__':main()
