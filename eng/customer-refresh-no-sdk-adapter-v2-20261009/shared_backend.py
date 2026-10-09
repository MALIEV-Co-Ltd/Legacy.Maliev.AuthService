"""Load unchanged published resource APIs; parameterize one proof entrypoint only."""
import hashlib
import ast
import json
from contextlib import contextmanager
import sys
import types
from pathlib import Path

PINS = {
 'hosted_owner.py':'c7c59062a89e5c7e66678eaf460426398a3089cb9d6a38302b78b2bdd8423372',
 'private_docker_proxy.py':'7f660f55e3a1420b44c4894a8ee50b4a9f6c89ae4b7c0f8349e4d41e93b3afda',
 'finite_stub_proof.py':'c89f3054cf3bd64d11112b02258973f78e304359fab7ab3bbf0777ea8edebcc8',
 'expiry_guard.py':'dcc6c1d639060a419bf5e034b02e83e4d9a1326fcac7977f427aec28e2907368',
 'recover_owner.py':'d6996140ddbb2896f00e357681b02f3478e50357c85d88f3981d63eee31de979',
 'Start-FinancialIamHostedOwner.ps1':'2ef1ef7685271b93c0ee28076393bede83f017e9b263380bb3b6ec47a5e7f3af',
}

def capture(root):
    root = Path(root).absolute()
    for part in (root,*root.parents):
        if part.is_symlink(): raise ValueError('Linked backend refused')
    result = {}
    for name,pin in PINS.items():
        path = root/name
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError('Nonregular backend source')
        raw = path.read_bytes()
        if len(raw) > 256*1024 or hashlib.sha256(raw).hexdigest() != pin:
            raise ValueError('Published backend pin mismatch')
        result[name] = raw
    return result

def owner_source(raw, proof_path, policy_path=None):
    if hashlib.sha256(raw).hexdigest() != PINS['hosted_owner.py']:
        raise ValueError('Owner source changed')
    marker = 'str(source / "finite_stub_proof.py")'
    text = raw.decode()
    if text.count(marker) != 1: raise ValueError('Exact proof hook required')
    proof = str(Path(proof_path).absolute())
    if any(c in proof for c in ('\n','\r','\0')): raise ValueError('Invalid proof path')
    policy = str(Path(policy_path or Path(proof_path).parent.parent/'customer-refresh-native-create-policy-v1-20261009/create_policy.py').absolute())
    if any(c in policy for c in ('\n','\r','\0')): raise ValueError('Invalid policy path')
    replacement = repr(proof)+', "--backend", str(source), "--policy", '+repr(policy)
    return text.replace(marker,replacement,1)

def pure_create_api(root):
    """Compile the pinned pure function only; no Unix socket implementation loaded."""
    raw = capture(root)['private_docker_proxy.py']
    tree = ast.parse(raw)
    selected = [node for node in tree.body if
                isinstance(node,ast.FunctionDef) and node.name == 'create_plan' or
                isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id == 'OWNER' for t in node.targets)]
    if len(selected) != 2: raise ValueError('Exact pure API required')
    module = types.ModuleType('auth_pure_create_model')
    module.json = json
    exec(compile(ast.Module(body=selected,type_ignores=[]),'pinned-pure-create-api','exec'),module.__dict__)
    return module

def modules(root, proof_path=None):
    captured = capture(root)
    proxy = types.ModuleType('private_docker_proxy')
    proxy.__file__ = str(Path(root)/'private_docker_proxy.py')
    exec(compile(captured['private_docker_proxy.py'],proxy.__file__,'exec'),proxy.__dict__)
    previous = sys.modules.get('private_docker_proxy')
    sys.modules['private_docker_proxy'] = proxy
    try:
        loaded = {'private_docker_proxy':proxy}
        for name in ('finite_stub_proof','hosted_owner'):
            module = types.ModuleType('auth_shared_'+name)
            module.__file__ = str(Path(root)/(name+'.py'))
            raw = captured[name+'.py']
            source = owner_source(raw,proof_path) if name == 'hosted_owner' and proof_path is not None else raw
            exec(compile(source,module.__file__,'exec'),module.__dict__)
            loaded[name] = module
        return loaded
    finally:
        if previous is None: sys.modules.pop('private_docker_proxy',None)
        else: sys.modules['private_docker_proxy'] = previous

def launcher_source(raw, backend, owner_path):
    if hashlib.sha256(raw).hexdigest() != PINS['Start-FinancialIamHostedOwner.ps1']:
        raise ValueError('Published launcher pin mismatch')
    marker = "(Join-Path $PSScriptRoot 'hosted_owner.py')"
    text = raw.decode()
    if text.count(marker) != 1: raise ValueError('Exact coordinator hook required')
    def literal(path):
        value = str(Path(path).absolute())
        if any(c in value for c in ('\n','\r','\0')): raise ValueError('Invalid source path')
        return "'"+value.replace("'","''")+"'"
    return text.replace(marker,literal(owner_path),1).replace('$PSScriptRoot',literal(backend))

@contextmanager
def bind_loaded(loaded):
    names = ('private_docker_proxy','hosted_owner')
    previous = {name:sys.modules.get(name) for name in names}
    try:
        for name in names: sys.modules[name] = loaded[name]
        yield loaded
    finally:
        for name,value in previous.items():
            if value is None: sys.modules.pop(name,None)
            else: sys.modules[name] = value
