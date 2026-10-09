import json
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch
import intake
import verify_trx
import discovery
import export_transport

PACKET = Path(__file__).resolve().parent.parent / 'auth-customer-refresh-setup-fence-source-v1-20261009'

class IntakeTests(unittest.TestCase):
    def test_frozen_packet(self):
        self.assertEqual(5, len(intake.verify_packet(PACKET)))

    def test_duplicate_json(self):
        with self.assertRaises(ValueError):
            intake.load('{"path":1,"path":2}')

    def test_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            for name in ('../x', '/x', 'C:/x', 'a\\x', 'a//x', './x'):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    intake.safe_path(Path(folder), name)

    def test_wrong_seal(self):
        with patch.object(intake, 'SEAL', '0' * 64), self.assertRaises(ValueError):
            intake.verify_packet(PACKET)

    def test_wrong_manifest(self):
        with patch.object(intake, 'MANIFEST', '0' * 64), self.assertRaises(ValueError):
            intake.verify_packet(PACKET)

    def test_parent_and_new_file_fences(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            rows = intake.verify_packet(PACKET)
            for row in rows:
                target = root / row['path']
                target.parent.mkdir(parents=True, exist_ok=True)
            with self.assertRaises(ValueError):
                intake.validate_preimages(root, PACKET, rows)
            new = next(r for r in rows if r['parentSha256'] is None)
            (root / new['path']).write_text('already exists')
            with self.assertRaises(ValueError):
                intake.validate_preimages(root, PACKET, [new])

    def test_wrong_checkout_and_dirty_checkout(self):
        for head, status in ((b'0'*40+b'\n', b''), (intake.BASE.encode()+b'\n', b' M unrelated')):
            with tempfile.TemporaryDirectory() as folder, patch.object(intake, 'git', side_effect=[head, status]), self.assertRaises(ValueError):
                intake.materialize(Path(folder), PACKET)

    def test_apply_and_rollback_extra_change(self):
        for extra in (False, True):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                (root / 'old.cs').write_bytes(b'old')
                prepared = [(root/'old.cs', b'old', b'new'), (root/'new.cs', None, b'added')]
                rows = [{'path':'old.cs'}, {'path':'new.cs'}]
                def fake_git(directory, *args):
                    if args[0] == 'rev-parse': return intake.BASE.encode()+b'\n'
                    if args[0] == 'status': return b''
                    if args[0] == 'diff': return b'old.cs\0'+(b'extra.cs\0' if extra else b'')
                    return b'new.cs\0'
                with patch.object(intake, 'git', side_effect=fake_git), patch.object(intake, 'verify_packet', return_value=rows), patch.object(intake, 'validate_preimages', return_value=prepared), patch.object(intake, 'tree_digest', return_value='a'*64):
                    if extra:
                        with self.assertRaises(ValueError): intake.materialize(root, PACKET)
                        self.assertEqual(b'old', (root/'old.cs').read_bytes())
                        self.assertFalse((root/'new.cs').exists())
                    else:
                        receipt = intake.materialize(root, PACKET)
                        self.assertEqual(['new.cs','old.cs'], receipt['changedPaths'])
                        self.assertEqual(b'new', (root/'old.cs').read_bytes())

    def test_postimage_tamper(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'files').mkdir()
            (root/'files/new.cs').write_bytes(b'altered')
            rows = [{'path':'new.cs','parentSha256':None,'bytes':4,'sha256':intake.digest(b'good')}]
            with self.assertRaises(ValueError): intake.validate_preimages(root, root, rows)

    def test_trx_execution_and_unique_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'focused.trx'
            assembly = Path(folder)/discovery.ASSEMBLY
            assembly.write_bytes(b'fixture assembly, not native evidence')
            listing = Path(folder)/'discovery.txt'
            roster_path = Path(folder)/'discovery.json'
            roster = [('CustomerRefreshAdmissionTests','Refresh_RechecksInitialPasswordStateBeforeIssuance')]*4 + [('LegacyIdentityReaderTests','FindActive_InitialPasswordState_DeniesOnlySetupRequiredCustomer')]*4 + [('RefreshSessionIdentityBoundaryHttpTests','CustomerRefresh_CurrentInitialPasswordState_ControlsFamilyAdmissionOnly')]*2
            names = []
            for i,(cls,method) in enumerate(roster):
                if i < 8:
                    kind,setup = ('Customer' if i%4 < 2 else 'Employee'), ('true' if i%2 == 0 else 'false')
                    outcome = 'expectedSuccess' if i < 4 else 'expectedActive'
                    expected = 'false' if kind == 'Customer' and setup == 'true' else 'true'
                    args = f'kind: {kind}, setupRequired: {setup}, {outcome}: {expected}'
                else: args = 'setupRequired: '+('true' if i == 8 else 'false')
                names.append(discovery.PREFIX+cls+'.'+method+'('+args+')')
            listing.write_text('\n'.join(names))
            roster_path.write_text(json.dumps(discovery.capture(assembly,listing)))
            def check(): verify_trx.verify(path,assembly,listing,roster_path)
            for mode in ('valid','missing','duplicate','wrong-method','aborted','bad-join','wrong-assembly','wrong-namespace','name-join','substituted-argument'):
                results, definitions, entries = [], [], []
                first = str(uuid.uuid4())
                for i,(cls,method) in enumerate(roster):
                    test_id = first if mode == 'duplicate' else str(uuid.uuid4())
                    execution = str(uuid.uuid4())
                    if mode != 'missing' or i != 9:
                        display = names[i] if mode != 'name-join' else 'unrelated'
                        if mode == 'substituted-argument' and i == 0: display = names[1]
                        results.append(f'<UnitTestResult testId="{test_id}" executionId="{execution}" outcome="Passed" testName="{display}"/>')
                    if mode == 'wrong-method': method = 'Unrelated'
                    namespace = discovery.PREFIX if mode != 'wrong-namespace' else 'Foreign.Tests.'
                    codebase = str(assembly.resolve()) if mode != 'wrong-assembly' else str(Path(folder)/'Other.dll')
                    definitions.append(f'<UnitTest id="{test_id}" name="{names[i]}"><Execution id="{execution}"/><TestMethod className="{namespace}{cls}" name="{method}" codeBase="{codebase}"/></UnitTest>')
                    joined = str(uuid.uuid4()) if mode == 'bad-join' else execution
                    entries.append(f'<TestEntry testId="{test_id}" executionId="{joined}"/>')
                outcome = 'Aborted' if mode == 'aborted' else 'Completed'
                zeros = ' '.join(f'{key}="0"' for key in ('error','timeout','aborted','inconclusive','passedButRunAborted','notRunnable','disconnected','warning','completed','inProgress','pending'))
                xml = f'<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><ResultSummary outcome="{outcome}"><Counters total="10" executed="10" passed="10" failed="0" notExecuted="0" {zeros}/></ResultSummary><Results>'+''.join(results)+'</Results><TestDefinitions>'+''.join(definitions)+'</TestDefinitions><TestEntries>'+''.join(entries)+'</TestEntries></TestRun>'
                path.write_text(xml)
                if mode == 'valid':
                    check()
                    for altered in (xml.replace('error="0"',''), xml.replace('</TestRun>','<Results/></TestRun>'),xml.replace('</TestRun>','<ResultSummary/></TestRun>')):
                        path.write_text(altered)
                        with self.assertRaises(ValueError): check()
                else:
                    with self.assertRaises(ValueError): check()

    def test_transport_exact_members_and_git_modes(self):
        seal = (PACKET/'seal.json').read_bytes()
        packet_prefix = export_transport.PREFIX+PACKET.name+'/'
        members = {packet_prefix+'seal.json':seal}
        for row in intake.load(seal)['files']:
            members[packet_prefix+row['path']] = (PACKET/row['path']).read_bytes()
        for name in export_transport.CONTROL_NAMES:
            members[export_transport.PREFIX+'controls/'+name] = (Path(__file__).parent/name).read_bytes()
        for name in export_transport.OBSERVER_PINS:
            retained = Path(__file__).resolve().parent.parent/'observer-controls'/Path(name).name
            source = retained if retained.exists() else Path(__file__).resolve().parents[3]/name
            members[name] = source.read_bytes()
        commit = 'a'*40
        for mode in ('valid','extra','symlink','dirty','wrong-head','wrong-observer-source','wrong-observer-mode'):
            def fake_git(root,*args):
                if args[0] == 'rev-parse': return (commit if mode != 'wrong-head' else 'b'*40).encode()+b'\n'
                if args[0] == 'status': return b'?? foreign' if mode == 'dirty' else b''
                if args[0] == 'show':
                    name = args[1].split(':',1)[1]
                    return b'altered observer' if mode == 'wrong-observer-source' and name in export_transport.OBSERVER_PINS else members[name]
                if '--name-only' in args: return ('\n'.join(sorted(name for name in members if name.startswith(export_transport.PREFIX)))+ ('\neng/customer-refresh-intake/extra' if mode == 'extra' else '')).encode()
                bad_mode = mode == 'symlink' or (mode == 'wrong-observer-mode' and args[-1] in export_transport.OBSERVER_PINS)
                return (('120000' if bad_mode else '100644')+' blob abc\tfile').encode()
            with tempfile.TemporaryDirectory() as folder, patch.object(intake,'git',side_effect=fake_git):
                destination = Path(folder)/'new'
                if mode == 'valid':
                    receipt = export_transport.export(Path(folder),commit,destination)
                    self.assertEqual(commit,receipt['transportCommit'])
                    self.assertEqual(5,len(intake.verify_packet(destination/PACKET.name)))
                else:
                    with self.assertRaises(ValueError): export_transport.export(Path(folder),commit,destination)
                    self.assertFalse(destination.exists())

if __name__ == '__main__':
    unittest.main()
