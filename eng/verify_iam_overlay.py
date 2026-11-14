"""Candidate CI evidence checks for the genuine IAM HTTP package override."""
import hashlib
import json
from pathlib import Path
import sys
import os
import subprocess
import shutil
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
IAM = ROOT / '.genuine-iam-source/Maliev.IAMService/Maliev.IAMService.Application/Maliev.IAMService.Application.csproj'
HOST = ROOT / 'acceptance/GenuineIamHost/GenuineIamHost.csproj'
TESTS = ROOT / 'acceptance/GenuineIamHttp.Tests/GenuineIamHttp.Tests.csproj'
INFRA = ROOT / '.genuine-iam-source/Maliev.IAMService/Maliev.IAMService.Infrastructure/Maliev.IAMService.Infrastructure.csproj'
OVERLAY = ROOT / 'eng/iam-http-package-overlay.targets'
SOURCE_SHA = '213e27a03edf02477c105ac518a5118529a6b7f889b66dd9409eeadaacdbdbf5'
OVERLAY_SHA = 'a089913b5741a55b5641f2061c36ce498ea52794b178db98c82498ce0890934f'
COMMIT = '4fe6642e5674013de9a3672505aec898fdcae0ed'
TREE = 'f8549c11f5c5a8027f3c08e21b2585ce709010b5'
SOURCE_CHECKOUT = ROOT / '.dependencies/Maliev.IAMService'
SOURCE_ROOT = ROOT / '.genuine-iam-source/Maliev.IAMService'
NAME = 'Microsoft.AspNetCore.WebUtilities'
KEY = NAME + '/10.0.15'

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def json_object(path):
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out: raise ValueError('duplicate JSON key')
            out[k] = v
        return out
    return json.loads(path.read_bytes(), object_pairs_hook=pairs)

def source_inventory():
    env = {k:v for k,v in os.environ.items() if not k.upper().startswith('GIT_')}
    env.update(GIT_NO_LAZY_FETCH='1', GIT_NO_REPLACE_OBJECTS='1', GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
    def git(*args):
        return subprocess.run(['git','-C',str(SOURCE_CHECKOUT),*args], env=env, check=True,
                              capture_output=True, timeout=15).stdout
    if git('rev-parse',COMMIT+'^{tree}').decode().strip() != TREE: raise ValueError('IAM commit tree differs')
    result = {}
    for entry in git('ls-tree','-rz','--full-tree',COMMIT).split(b'\0'):
        if not entry: continue
        meta,path=entry.split(b'\t',1);mode,kind,oid=meta.decode('ascii').split(' ');name=path.decode('utf-8')
        parts=name.split('/')
        if mode not in ('100644','100755') or kind!='blob' or any(x in ('','.','..') for x in parts) or '\\' in name or name in result: raise ValueError('unsupported IAM tree entry')
        result[name]=oid
    if len(result) != 210: raise ValueError('IAM source inventory differs')
    return result

def verify_source(exclusive=False):
    if SOURCE_ROOT.is_symlink() or not SOURCE_ROOT.is_dir(): raise ValueError('IAM root differs')
    inventory=source_inventory()
    for name,oid in inventory.items():
        path=SOURCE_ROOT.joinpath(*name.split('/'))
        if path.is_symlink() or not path.is_file() or any(parent.is_symlink() for parent in path.parents if parent != SOURCE_ROOT.parent and SOURCE_ROOT in parent.parents): raise ValueError('IAM source path differs')
        data=path.read_bytes()
        if hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()!=oid: raise ValueError('IAM source blob differs')
    if exclusive:
        actual={p.relative_to(SOURCE_ROOT).as_posix() for p in SOURCE_ROOT.rglob('*') if p.is_file() or p.is_symlink()}
        if actual != set(inventory): raise ValueError('unexpected materialized IAM source path')
    return len(inventory)

def preflight():
    verify_source(exclusive=True)
    if sha(IAM) != SOURCE_SHA or sha(OVERLAY) != OVERLAY_SHA: raise ValueError('reviewed source or overlay differs')
    refs = [x for x in ET.fromstring(IAM.read_bytes()).iter('PackageReference') if x.get('Include') == NAME]
    if len(refs) != 1 or refs[0].get('Version') != '10.0.5': raise ValueError('original reference differs')
    for project in (IAM, INFRA, HOST, TESTS):
        if (project.parent / 'obj/project.assets.json').exists(): raise ValueError('stale assets present')

def package(mapping):
    found = [x for x in mapping if x.split('/', 1)[0].casefold() == NAME.casefold()]
    if found != [KEY]: raise ValueError('resolved package differs')

def assets(project, require_patched=True):
    doc = json_object(project.parent / 'obj/project.assets.json')
    if Path(doc['project']['restore']['projectPath']).resolve() != project.resolve(): raise ValueError('assets project differs')
    if not doc['targets']: raise ValueError('no restore targets')
    if require_patched:
        package(doc['libraries'])
        for target in doc['targets'].values(): package(target)
    return sorted(x for x in doc['libraries'] if x.split('/',1)[0].casefold()==NAME.casefold())

def verify():
    verify_source()
    if sha(IAM) != SOURCE_SHA or sha(OVERLAY) != OVERLAY_SHA: raise ValueError('source or overlay changed')
    evaluated = json_object(ROOT / 'artifacts/genuine-iam-evaluation.json')
    props = evaluated['Properties']
    expected = str(IAM.resolve())
    if props.get('MSBuildProjectFullPath') != expected or props.get('Auth201ExpectedIamApplicationProject') != expected or props.get('CustomAfterMicrosoftCommonTargets') != str(OVERLAY.resolve()): raise ValueError('evaluation properties differ')
    refs = [x for x in evaluated['Items']['PackageReference'] if x.get('Identity','').casefold() == NAME.casefold()]
    if len(refs) != 1 or refs[0].get('Version') != '10.0.15' or refs[0].get('VersionOverride'): raise ValueError('evaluation did not apply the expected update')
    baseline=json_object(ROOT/'artifacts/genuine-iam-baseline-evaluation.json')
    def refs_by_name(doc):
        result={}
        for item in doc['Items']['PackageReference']:
            name=item.get('Identity','').casefold()
            if not name or name in result: raise ValueError('duplicate reference')
            result[name]=dict(item)
        return result
    before,after=refs_by_name(baseline),refs_by_name(evaluated)
    if set(before)!=set(after): raise ValueError('reference roster changed')
    for name in before:
        a,b=before[name],after[name]
        if name==NAME.casefold():
            if a.get('Version')!='10.0.5' or b.get('Version')!='10.0.15' or a.get('VersionOverride') or b.get('VersionOverride'): raise ValueError('invalid reference change')
            a.pop('Version');b.pop('Version')
        if a!=b: raise ValueError('unrelated reference metadata changed')
    assets(IAM); assets(INFRA); assets(HOST)
    test_versions = assets(TESTS, require_patched=False)
    output = ROOT / 'acceptance/GenuineIamHost/bin/Release/net10.0'
    deps = json_object(output / 'GenuineIamHost.deps.json')
    package(deps['libraries'])
    target = deps['runtimeTarget']['name']
    package(deps['targets'][target])
    binary = output / 'GenuineIamHost.dll'
    packages = Path(os.environ.get('NUGET_PACKAGES', Path.home()/'.nuget/packages'))
    package_file = packages/'microsoft.aspnetcore.webutilities/10.0.15/lib/net10.0/Microsoft.AspNetCore.WebUtilities.dll'
    package_hash = sha(package_file) if package_file.is_file() else None
    return {'hostSha256':sha(binary),'depsSha256':sha(output/'GenuineIamHost.deps.json'),
            'packageSha256':package_hash,'testGraphWebUtilities':test_versions}

def main():
    mode = sys.argv[1]
    receipt = ROOT/'artifacts/genuine-iam-overlay-evidence.json'
    if mode == 'preflight': preflight()
    elif mode == 'record':
        result = verify()
        saved = ROOT/'artifacts/genuine-iam-overlay-graphs'
        saved.mkdir(exist_ok=False)
        for name,source in (('application-assets.json',IAM.parent/'obj/project.assets.json'),
                            ('infrastructure-assets.json',INFRA.parent/'obj/project.assets.json'),
                            ('host-assets.json',HOST.parent/'obj/project.assets.json'),
                            ('test-assets.json',TESTS.parent/'obj/project.assets.json'),
                            ('host-deps.json',HOST.parent/'bin/Release/net10.0/GenuineIamHost.deps.json')):
            shutil.copyfile(source,saved/name)
        with receipt.open('x', encoding='utf-8') as out: json.dump(result,out,sort_keys=True)
    elif mode == 'recheck':
        if json_object(receipt) != verify(): raise ValueError('host or dependency output changed')
    else: raise ValueError('unknown mode')
if __name__ == '__main__': main()
