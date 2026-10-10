"""One fixed Auth SDK route over captured retained resource functions."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import types

BASE='2bd6a61bfce1d19310209c0d00b56d92f0abea91'
PACKET_SEAL='4c0a696315089af2faaa844223f13619d48991962d047ac20fb48555f5e54f68'
HERE=Path(__file__).resolve().parent

def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result

def shared(source):
    backend=module(Path(source)/'eng/customer-refresh-no-sdk-adapter-v2-20261009/shared_backend.py','cs9_shared')
    loaded=backend.modules(Path(source)/'eng/financial-iam')
    loaded['pins']=backend.PINS
    return backend,loaded

def replace_once(text,before,after):
    if text.count(before)!=1:raise ValueError('Retained source hook changed')
    return text.replace(before,after,1)

def owner_text(raw):
    text=raw.decode()
    start=text.index('        sdk_command = ["/usr/bin/pwsh"')
    end=text.index('        if args.stage == "build":',start)
    text=text[:start]+'''        sdk_command = ["/usr/bin/python3", "-B", '''+repr(str(HERE/'worker.py'))+''',
            "--source", str(pathlib.Path(args.checkouts).resolve(strict=True)),
            "--destination", str(root / "cs9-materialized"), "--receipts", str(receipts),
            "--context", str(receipts / "native-context.json")]
'''+text[end:]
    marker='str(source / "private_docker_proxy.py")'
    if text.count(marker)!=2:raise ValueError('Exact proxy hooks required')
    text=text.replace(marker,repr(str(HERE/'proxy.py')))
    text=replace_once(text,'(source / "private_docker_proxy.py").read_bytes()',
                      'pathlib.Path('+repr(str(HERE/'proxy.py'))+').read_bytes()')
    # Retain the runtime directory generation for unchanged physical cleanup.
    text=replace_once(text,'    if args.stage == "proof":\n        birth = root.stat()',
                      '    if args.stage == "full":\n        birth = root.stat()')
    return text

def run_owner():
    source=Path(sys.argv[sys.argv.index('--source')+1])
    if sys.argv[sys.argv.index('--lane')+1]!='auth' or sys.argv[sys.argv.index('--stage')+1]!='full':
        raise ValueError('Only fixed Auth validation accepted')
    backend,loaded=shared(source.parents[1])
    captured=backend.capture(source)
    private=types.ModuleType('cs9_owned_coordinator')
    with backend.bind_loaded(loaded):
        exec(compile(owner_text(captured['hosted_owner.py']),str(HERE/'owner.py'),'exec'),private.__dict__)
        private.main()

# One closed composed packet; source proposal only, never an issued request.
BACKEND_PATH='eng/customer-refresh-intake/controls/intake.py'
BACKEND_SHA='46968d644d26bbf11d800b47771c4ebf1ea71bb726bbe80de9b6168bc08afa97'
MANIFEST_SHA='b872953f3b3bfea1e7d8f2830fff95d2a3dc6bbbf31e9fbbad4969e7024adefc'
DIRECTORIES=('acceptance/EmployeeLockoutSwitch','acceptance/EmployeeRememberedCookie')
PATHS=('Legacy.Maliev.AuthService.Api/Controllers/AuthenticationController.cs', 'Legacy.Maliev.AuthService.Api/Program.cs', 'Legacy.Maliev.AuthService.Application/AuthContracts.cs', 'Legacy.Maliev.AuthService.Application/AuthenticationAbstractions.cs', 'Legacy.Maliev.AuthService.Application/AuthenticationService.cs', 'Legacy.Maliev.AuthService.Infrastructure/CustomerIdentityAdminService.cs', 'Legacy.Maliev.AuthService.Infrastructure/CustomerPasswordSetupState.cs', 'Legacy.Maliev.AuthService.Infrastructure/CustomerSelfIdentityReader.cs', 'Legacy.Maliev.AuthService.Infrastructure/CustomerSelfService.cs', 'Legacy.Maliev.AuthService.Infrastructure/EmployeeDataProtectionXmlRepository.cs', 'Legacy.Maliev.AuthService.Infrastructure/EmployeePasswordTwoFactorPolicy.cs', 'Legacy.Maliev.AuthService.Infrastructure/EmployeeRememberedClientDataProtection.cs', 'Legacy.Maliev.AuthService.Infrastructure/InteractiveLegacyCredentialValidator.cs', 'Legacy.Maliev.AuthService.Infrastructure/LegacyIdentityAncillaryModel.cs', 'Legacy.Maliev.AuthService.Infrastructure/LegacyIdentityContexts.cs', 'Legacy.Maliev.AuthService.Infrastructure/LegacyIdentityReader.cs', 'Legacy.Maliev.AuthService.Infrastructure/Migrations/CustomerIdentityPostgres/202610100001_RestoreCustomerIdentityAncillaryStore.cs', 'Legacy.Maliev.AuthService.Infrastructure/Migrations/EmployeeIdentityPostgres/202610090001_RestoreEmployeeIdentityTokenStore.cs', 'Legacy.Maliev.AuthService.Infrastructure/Migrations/EmployeeIdentityPostgres/202610100001_RestoreEmployeeIdentityAncillaryStore.cs', 'Legacy.Maliev.AuthService.Infrastructure/Migrations/LegacyIdentityAncillarySchema.cs', 'Legacy.Maliev.AuthService.Infrastructure/ServiceCollectionExtensions.cs', 'Legacy.Maliev.AuthService.Tests/CustomerIdentityAdminTests.cs', 'Legacy.Maliev.AuthService.Tests/CustomerRefreshAdmissionTests.cs', 'Legacy.Maliev.AuthService.Tests/CustomerSelfIdentityTests.cs', 'Legacy.Maliev.AuthService.Tests/EmployeeDataProtectionCustodyTests.cs', 'Legacy.Maliev.AuthService.Tests/EmployeeDataProtectionPostgresTests.cs', 'Legacy.Maliev.AuthService.Tests/EmployeePasswordTwoFactorPolicyTests.cs', 'Legacy.Maliev.AuthService.Tests/EmployeeRememberedCustodyHttpTests.cs', 'Legacy.Maliev.AuthService.Tests/EmployeeRememberedKeyRingFixture.cs', 'Legacy.Maliev.AuthService.Tests/EmployeeSessionIssuanceHttpTests.cs', 'Legacy.Maliev.AuthService.Tests/InheritedIdentityStoreTests.cs', 'Legacy.Maliev.AuthService.Tests/InvoiceDelegationCurrentSessionHttpTests.cs', 'Legacy.Maliev.AuthService.Tests/Legacy.Maliev.AuthService.Tests.csproj', 'Legacy.Maliev.AuthService.Tests/LegacyIdentityReaderTests.cs', 'Legacy.Maliev.AuthService.Tests/OriginalUserConcurrencyTests.cs', 'Legacy.Maliev.AuthService.Tests/RefreshSessionIdentityBoundaryHttpTests.cs', 'acceptance/EmployeeLockoutSwitch/EmployeeLockoutSwitchAcceptanceTests.cs', 'acceptance/EmployeeLockoutSwitch/Legacy.Maliev.EmployeeLockoutSwitch.Acceptance.csproj', 'acceptance/EmployeeRememberedCookie/EmployeeRememberedCookieAcceptanceTests.cs', 'acceptance/EmployeeRememberedCookie/Legacy.Maliev.EmployeeRememberedCookie.Acceptance.csproj', 'docs/employee-data-protection-postgres-schema.sql', 'docs/employee-remembered-cookie-compatibility.md', 'docs/interactive-password-attempt-accounting.md')
MEMBERS={'complete.patch': (592390, '1f7d9a29930a59a579f255f12c8b529c2c5dfaf4381567c7cd855d90c04379f0'), 'custody.json': (9122, '179a85a5fddd49e1683f4d4f5248dbfba2eeb6ef2d6b67ec6787e1e7bcd15444'), 'files/acceptance/EmployeeLockoutSwitch/EmployeeLockoutSwitchAcceptanceTests.cs': (3683, 'cde59f1524f48ddba3c6c26738c85fc40b2efe5b1c8014fe866c94538d0e2fbf'), 'files/acceptance/EmployeeLockoutSwitch/Legacy.Maliev.EmployeeLockoutSwitch.Acceptance.csproj': (804, '7f263f6dda0bc465b70369cd68650d94866a7b17327610ba13c87679f39d6c25'), 'files/acceptance/EmployeeRememberedCookie/EmployeeRememberedCookieAcceptanceTests.cs': (11959, '3ade31aae46bd9bbd825a539c9552baa15a8262a9ce0204e3af9d83505c94eb2'), 'files/acceptance/EmployeeRememberedCookie/Legacy.Maliev.EmployeeRememberedCookie.Acceptance.csproj': (963, '37d57d9dd90030a78af6514b7949e136f6d5d6f081b817fc62e1c23d8a8c7e0b'), 'files/docs/employee-data-protection-postgres-schema.sql': (503, '7cac83166f2458bdf06ef12e638e9d2fc127946fef5468cbdf58d71ffb1a0921'), 'files/docs/employee-remembered-cookie-compatibility.md': (4495, '23a1fda266b6152557341de8685e064018d0c57f4af307eeb29af65b35d34929'), 'files/docs/interactive-password-attempt-accounting.md': (6122, '8cd2a2ee65b234929e7e430eb2b352cf8bd6f171ca1aa3e29003d218f85e6644'), 'files/Legacy.Maliev.AuthService.Api/Controllers/AuthenticationController.cs': (8829, 'a1df5b77174c0da51c4a3b14d58d4704387e2925ba5e1ca09eeef10d3c7a18af'), 'files/Legacy.Maliev.AuthService.Api/Program.cs': (5549, 'c7d6907909c2c4384cf299a7dceac99f6ca7739eef480dc95af5a53841f2d912'), 'files/Legacy.Maliev.AuthService.Application/AuthContracts.cs': (2317, '490ed862089c6a8ebfeedb44705016f920a411966c414098fb2ca5b3c8ee0bdf'), 'files/Legacy.Maliev.AuthService.Application/AuthenticationAbstractions.cs': (4892, '5cb4acedbb960dcca82f4cf6dc605f2585b0485fedfda208f661f1e0e4a2cad7'), 'files/Legacy.Maliev.AuthService.Application/AuthenticationService.cs': (6422, '60edb65d85483d506f8d03bdb7dbe91cf171b02c15167ee0f6780c707a0904e1'), 'files/Legacy.Maliev.AuthService.Infrastructure/CustomerIdentityAdminService.cs': (16700, '09a154929ab5422dba84b406ebd7938dc7007695ef8866008ecfacfc53b61640'), 'files/Legacy.Maliev.AuthService.Infrastructure/CustomerPasswordSetupState.cs': (1249, '1b813602ade333a0e52726469b212e3c23487d7de3d816adaf18f2ea461015d0'), 'files/Legacy.Maliev.AuthService.Infrastructure/CustomerSelfIdentityReader.cs': (1851, '92b409ec22fe59b4cd107564fd2513d99bacd84e9caa2de1d5ae8fd3f643465f'), 'files/Legacy.Maliev.AuthService.Infrastructure/CustomerSelfService.cs': (39445, '549db5847146fd35e0245058430db2a0c3e88f49b1c503e0be5ef2574abc90cc'), 'files/Legacy.Maliev.AuthService.Infrastructure/EmployeeDataProtectionXmlRepository.cs': (3050, '55f2aeb0554cd969dbf1137f76cb287f76ee763caec8ed439505847afef710b9'), 'files/Legacy.Maliev.AuthService.Infrastructure/EmployeePasswordTwoFactorPolicy.cs': (8881, '8fc165593091da40e0715f97715c5b7eb4161d8ee4277f855c9bf7ecb1f2f53e'), 'files/Legacy.Maliev.AuthService.Infrastructure/EmployeeRememberedClientDataProtection.cs': (5725, '524fa269d33c23f67160890919d05eaa4f70c2401826b73a4d6cd9fd333ee784'), 'files/Legacy.Maliev.AuthService.Infrastructure/InteractiveLegacyCredentialValidator.cs': (5467, 'aa1c58be31dad27305ef9b0ece68d6f1fa21663eae2f8c0a5a428ac6978ef3f6'), 'files/Legacy.Maliev.AuthService.Infrastructure/LegacyIdentityAncillaryModel.cs': (3063, '2adc7389c66aeb8ac7604f164bea08c3261e4e3a9694035cbf8b1da9bdc30176'), 'files/Legacy.Maliev.AuthService.Infrastructure/LegacyIdentityContexts.cs': (7757, '2f8b981a225c77f509fe695067e7efea79d265241ff9447145e408d45f0aad1c'), 'files/Legacy.Maliev.AuthService.Infrastructure/LegacyIdentityReader.cs': (5391, '0f051b5b33c5abd2a60c97c8159432ae14fd6a08da70d2ae3d8108bdba20b2cb'), 'files/Legacy.Maliev.AuthService.Infrastructure/Migrations/CustomerIdentityPostgres/202610100001_RestoreCustomerIdentityAncillaryStore.cs': (912, '985bdd1de1741f97f46b8378ff5a7ff607a3760e8f19eb1c1b6d378b3f23486d'), 'files/Legacy.Maliev.AuthService.Infrastructure/Migrations/EmployeeIdentityPostgres/202610090001_RestoreEmployeeIdentityTokenStore.cs': (1306, '5cf927a2ab047eeb3ad491735b4ad3ac170e7e6fe0dc7da532cb1f39da4ad128'), 'files/Legacy.Maliev.AuthService.Infrastructure/Migrations/EmployeeIdentityPostgres/202610100001_RestoreEmployeeIdentityAncillaryStore.cs': (1008, '11c6ac0fc954c766fe3fb7b01cfe1ef94308a1deae1bf826486a1e8f17360864'), 'files/Legacy.Maliev.AuthService.Infrastructure/Migrations/LegacyIdentityAncillarySchema.cs': (6245, '0a7574d225932c4736360ce2053260e0edc9ed733fd109469fb538e2d3a43099'), 'files/Legacy.Maliev.AuthService.Infrastructure/ServiceCollectionExtensions.cs': (6700, '65a1de3cbc46289704e8b93c16d1687a92e32483b8a457382401323ef1adcc17'), 'files/Legacy.Maliev.AuthService.Tests/CustomerIdentityAdminTests.cs': (18947, '9857b02ea25d103e388e314e1c31eb02a14af7567eb3ff11f0e7e7f720e8b48b'), 'files/Legacy.Maliev.AuthService.Tests/CustomerRefreshAdmissionTests.cs': (3791, '34842005117cdd4c4af45b6d9b7b6768d10910a265748b63fbcb3815c84f44c7'), 'files/Legacy.Maliev.AuthService.Tests/CustomerSelfIdentityTests.cs': (12171, 'ee677e59507e54272865364f3624080618be8c08bc645acfac43fd1e5a595b8d'), 'files/Legacy.Maliev.AuthService.Tests/EmployeeDataProtectionCustodyTests.cs': (829, 'b0dca37db1ea55091197906fb63a302ae1f70a84cfb98194655567d0104bd7ca'), 'files/Legacy.Maliev.AuthService.Tests/EmployeeDataProtectionPostgresTests.cs': (6175, '193ea4f3d0d8e2ef739e173cdf87d66392839ac1b36aa79999df87fae530ad78'), 'files/Legacy.Maliev.AuthService.Tests/EmployeePasswordTwoFactorPolicyTests.cs': (5807, '60bf6d5ab48d8c3e1ae79b3ba3be7775948931ff0da9c06332c49986e1259959'), 'files/Legacy.Maliev.AuthService.Tests/EmployeeRememberedCustodyHttpTests.cs': (4606, '289efe83d41e7b193ac63b5762cefdd4c3a69136348f00997c46d9187c21e4c2'), 'files/Legacy.Maliev.AuthService.Tests/EmployeeRememberedKeyRingFixture.cs': (6483, '5f82a24ebf09890da23cc22f1831cf86d049677c1409670ce2e6ace5c45bd8bb'), 'files/Legacy.Maliev.AuthService.Tests/EmployeeSessionIssuanceHttpTests.cs': (162772, '9b78da9c6b8f8b9d9400cf398bf0565a58e9d9c7bfc71fb3a7cda194b832f128'), 'files/Legacy.Maliev.AuthService.Tests/InheritedIdentityStoreTests.cs': (10251, 'd787fecc76a4dba357d25eaf2c889b834ee265fb88c5d350ca46bcfd55e6b717'), 'files/Legacy.Maliev.AuthService.Tests/InvoiceDelegationCurrentSessionHttpTests.cs': (25819, '18e847b5b82d1b2777df50e39c48edde63dd1d57a5d54d895235b72bdb226c47'), 'files/Legacy.Maliev.AuthService.Tests/Legacy.Maliev.AuthService.Tests.csproj': (2847, '4818e77830ce0fcaf1e968201a287b4e1c3305897110ee983c74fc9befd9c359'), 'files/Legacy.Maliev.AuthService.Tests/LegacyIdentityReaderTests.cs': (11560, '4869d60ebc06fd8eeb22aaa9baa38263ecfbbccd35eef4c8de75693bce133809'), 'files/Legacy.Maliev.AuthService.Tests/OriginalUserConcurrencyTests.cs': (16660, 'aaae201fe9fc039bdbf27d0a17c24223721e04eefdeeeb05655b72f5daecd6fd'), 'files/Legacy.Maliev.AuthService.Tests/RefreshSessionIdentityBoundaryHttpTests.cs': (42836, '3eb0378232e3a543d7b777bd682ed02fb96e4fcead952590f9bae33a1b9bf655'), 'manifest.json': (12555, 'b872953f3b3bfea1e7d8f2830fff95d2a3dc6bbbf31e9fbbad4969e7024adefc'), 'parent-seals/0.json': (11629, '4743b495f87eac7c8e20678b0c52bdbf9dc85989e0245f3f66641cad4f70faca'), 'parent-seals/1.json': (2251, '9a5e6b01b89ffba62d5966dfc5f2f225f97e8958b8cc6a81c8c60dda1a147d21'), 'parent-seals/2.json': (1572, 'e1db77891b35f9018659d96def42dde54e73b9ea428aabe2a558197a4ebf3d11'), 'parent-seals/3.json': (1079, '790b358c00a7bea155c84b8acb36609445227a876fa5822b25815e5cbdf0529e'), 'source-handoff.json': (24154, 'ec2dca070ed96cbed4cc6f6f800b6e867e4add4605d35b9ae6f3df54ba7aaeb8')}

def packet(source):
    candidate=Path(source)/'eng/customer-self-identity-intake/auth-composed-source-v1-20261010'
    if candidate.is_symlink():raise ValueError('Regular composed packet root required')
    return candidate

def pinned_read(backend,root,name,size,digest):
    path=backend.safe_path(root,name)
    backend.require(path.stat().st_size==size,'Exact composed input size required')
    with path.open('rb') as stream:raw=stream.read(size+1)
    backend.require(len(raw)==size and backend.digest(raw)==digest,'Exact composed input bytes required')
    return raw

def verify_packet(candidate,backend):
    seal_path=backend.safe_path(candidate,'seal.json')
    backend.require(seal_path.stat().st_size<=16384,'Bounded composed seal required')
    with seal_path.open('rb') as stream:raw=stream.read(16385)
    backend.require(len(raw)<=16384 and backend.digest(raw)==PACKET_SEAL,'Exact composed seal required')
    seal=backend.load(raw)
    backend.require(set(seal)=={'files'} and len(seal['files'])==len(MEMBERS),'Closed composed inventory required')
    backend.require({r['path']:(r['bytes'],r['sha256']) for r in seal['files']}==MEMBERS,'Composed inventory pins changed')
    actual={p.relative_to(candidate).as_posix() for p in candidate.rglob('*') if p.is_file() or p.is_symlink()}
    backend.require(actual==set(MEMBERS)|{'seal.json'},'Foreign composed packet member')
    loaded={name:pinned_read(backend,candidate,name,*pin) for name,pin in MEMBERS.items()}
    manifest=backend.load(loaded['manifest.json'])
    backend.require(backend.digest(loaded['manifest.json'])==MANIFEST_SHA and manifest['base']==BASE,'Exact composed base/manifest required')
    rows=manifest['files']
    backend.require(len(rows)==43 and tuple(r['path'] for r in rows)==PATHS,'Closed43 postimages required')
    backend.require(manifest['newDirectories']==list(DIRECTORIES),'Only two declared absent directories admitted')
    backend.require(backend.digest(loaded['source-handoff.json'])==manifest['handoffSha256'] and backend.digest(loaded['custody.json'])==manifest['custodySha256'],'Original composed provenance changed')
    for parent in manifest['parentSeals']:
        backend.require(backend.digest(loaded[parent['path']])==parent['sha256'],'Accepted parent seal changed')
    return rows

def load_intake(destination):
    path=Path(destination)/BACKEND_PATH
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink!=1:raise ValueError('Regular captured intake backend required')
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=BACKEND_SHA:raise ValueError('Captured intake backend bytes changed')
    backend=types.ModuleType('private_composed_intake')
    exec(compile(raw,str(path),'exec'),backend.__dict__)
    if backend.git(destination,'cat-file','blob',BASE+':'+BACKEND_PATH)!=raw:raise ValueError('Exact2bd backend Git parent required')
    backend.BASE=BASE;backend.SEAL=PACKET_SEAL;backend.MANIFEST=MANIFEST_SHA
    backend.verify_packet=lambda p:verify_packet(p,backend)
    return backend

def materialize(source,destination):
    destination=Path(destination)
    backend=load_intake(destination);candidate=packet(source)
    backend.require(backend.git(destination,'rev-parse','HEAD').decode().strip()==BASE,'Exact composed checkout required')
    backend.require(not backend.git(destination,'status','--porcelain','--untracked-files=all'),'Clean composed checkout required')
    rows=verify_packet(candidate,backend)
    backend.validate_preimages(destination,candidate,rows)
    created=[]
    try:
        for name in DIRECTORIES:
            path=backend.safe_path(destination,name)
            backend.require(not path.exists() and path.parent.is_dir() and not path.parent.is_symlink(),'Declared child directory must be absent under existing parent')
            created.append([path,None,None])
            path.mkdir(mode=0o700)
            value=path.lstat();created[-1][1:]=[value.st_dev,value.st_ino]
            backend.require(not path.is_symlink() and path.is_dir(),'Owned child directory creation refused')
        result=backend.materialize(destination,candidate)
        result['createdDirectories']=list(DIRECTORIES);result['sdkExecuted']=False
        return result
    except BaseException as primary:
        errors=[]
        for path,device,inode in reversed(created):
            try:
                backend.require(device is not None and inode is not None,'Child directory allocation identity unresolved')
                value=path.lstat()
                backend.require(not path.is_symlink() and path.is_dir() and (value.st_dev,value.st_ino)==(device,inode),'Owned child directory identity changed')
                path.rmdir()
            except BaseException as error:errors.append(error)
        if errors:
            primary.directory_cleanup_failures=errors
            primary.add_note('Declared child directory cleanup remains unresolved')
        raise
