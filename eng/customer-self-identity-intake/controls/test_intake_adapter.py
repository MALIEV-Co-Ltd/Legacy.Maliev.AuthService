from pathlib import Path
import shutil
import tempfile
import unittest
import subprocess
import importlib.util
import os
import json
import hashlib
from unittest.mock import patch
import intake_adapter as adapter

ROOT=Path(__file__).resolve().parents[2]
BACKEND_ROOT=ROOT/'work/ac9'
PACKET=ROOT/'outputs/customer-self-identity-setup-admission-source-v1-20261009'

class Controls(unittest.TestCase):
    def bad_manifest(self,change,message):
        # Re-pin a synthetic invalid fixture to reach the semantic guard; the
        # reviewed production packet and constants are never written.
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'packet';shutil.copytree(PACKET,p)
            manifest=json.loads((p/'manifest.json').read_bytes());change(manifest)
            raw=json.dumps(manifest).encode();(p/'manifest.json').write_bytes(raw)
            seal=json.loads((p/'seal.json').read_bytes())
            seal['files']['manifest.json']=hashlib.sha256(raw).hexdigest()
            sealed=json.dumps(seal).encode();(p/'seal.json').write_bytes(sealed)
            with patch.object(adapter,'SEAL',hashlib.sha256(sealed).hexdigest()),patch.object(adapter,'MANIFEST',hashlib.sha256(raw).hexdigest()):
                with self.assertRaisesRegex(ValueError,message):adapter.verify_packet(p,adapter.load_backend(BACKEND_ROOT))
    def test_wrong_manifest_base_refused(self):
        self.bad_manifest(lambda m:m.update(base='0'*40),'base mismatch')
    def test_wrong_overlay_membership_refused(self):
        self.bad_manifest(lambda m:m['files'].pop(),'overlay membership')
    def test_manifest_hash_refused(self):
        with patch.object(adapter,'MANIFEST','0'*64):
            with self.assertRaisesRegex(ValueError,'manifest mismatch'):adapter.verify_packet(PACKET,adapter.load_backend(BACKEND_ROOT))
    def checkout(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root=Path(temp.name)/'checkout'
        subprocess.run(['git','clone','--no-hardlinks','--no-checkout',str(BACKEND_ROOT),str(root)],check=True,capture_output=True,timeout=30)
        subprocess.run(['git','-C',str(root),'checkout','--detach',adapter.BASE],check=True,capture_output=True,timeout=30)
        return root
    def originals(self,root):
        return {name:(root/name).read_bytes() for name in adapter.PATHS}
    def assert_originals(self,root,old):
        self.assertEqual(self.originals(root),old)
    def private_backend(self,root):
        backend=adapter.load_backend(root)
        backend.BASE=adapter.BASE
        backend.verify_packet=lambda p:adapter.verify_packet(p,backend)
        return backend
    def test_actual_materialize_and_ambient_bindings_unchanged(self):
        root=self.checkout()
        spec=importlib.util.spec_from_file_location('ambient_intake',BACKEND_ROOT/adapter.BACKEND)
        ambient=importlib.util.module_from_spec(spec);spec.loader.exec_module(ambient)
        before=(ambient.BASE,ambient.SEAL,ambient.MANIFEST,ambient.verify_packet)
        raw=(root/adapter.BACKEND).read_bytes()
        result=adapter.materialize(root,PACKET)
        self.assertEqual(set(result['changedPaths']),set(adapter.PATHS))
        for name in adapter.PATHS:self.assertEqual((root/name).read_bytes(),(PACKET/'files'/name).read_bytes())
        self.assertEqual(before,(ambient.BASE,ambient.SEAL,ambient.MANIFEST,ambient.verify_packet))
        self.assertEqual(raw,(root/adapter.BACKEND).read_bytes())
    def test_wrong_checkout_no_write(self):
        root=self.checkout();old=self.originals(root)
        subprocess.run(['git','-C',str(root),'checkout','--detach',adapter.BASE+'^'],check=True,capture_output=True,timeout=30)
        old=self.originals(root)
        with self.assertRaisesRegex(ValueError,'checkout mismatch'):adapter.materialize(root,PACKET)
        self.assert_originals(root,old)
    def test_dirty_checkout_no_write(self):
        root=self.checkout();(root/'untracked').write_text('dirty');old=self.originals(root)
        with self.assertRaisesRegex(ValueError,'dirty checkout'):adapter.materialize(root,PACKET)
        self.assert_originals(root,old)
    def test_mismatched_preimage_no_write(self):
        root=self.checkout();old=self.originals(root);backend=self.private_backend(root)
        rows=adapter.verify_packet(PACKET,backend)
        rows=[dict(row) for row in rows];rows[0]['parentSha256']='0'*64
        backend.verify_packet=lambda p:rows
        with self.assertRaisesRegex(ValueError,'parent mismatch'):backend.materialize(root,PACKET)
        self.assert_originals(root,old)
    def test_second_write_failure_restores_both(self):
        root=self.checkout();old=self.originals(root);write=Path.write_bytes;calls=[]
        def fail(path,data):
            calls.append(path)
            if len(calls)==2:raise OSError('second write fault')
            return write(path,data)
        with patch.object(Path,'write_bytes',fail):
            with self.assertRaisesRegex(OSError,'second write fault'):adapter.materialize(root,PACKET)
        self.assertEqual(calls[:2],[root/name for name in adapter.PATHS])
        self.assert_originals(root,old)
    def test_readback_failure_restores_both(self):
        root=self.checkout();old=self.originals(root);read=Path.read_bytes;write=Path.write_bytes;written=[]
        def record(path,data):written.append(path);return write(path,data)
        def fail(path):
            if len(written)==2 and path==root/adapter.PATHS[0]:return b'bad readback'
            return read(path)
        with patch.object(Path,'write_bytes',record),patch.object(Path,'read_bytes',fail):
            with self.assertRaisesRegex(ValueError,'post-write mismatch'):adapter.materialize(root,PACKET)
        self.assert_originals(root,old)
    def test_unexpected_changed_path_restores_both(self):
        root=self.checkout();old=self.originals(root);backend=self.private_backend(root);git=backend.git
        def injected(where,*args):
            if args[:2]==('diff','--name-only'):return git(where,*args)+b'extra\0'
            return git(where,*args)
        backend.git=injected
        with self.assertRaisesRegex(ValueError,'unexpected tree change'):backend.materialize(root,PACKET)
        self.assert_originals(root,old)
    def test_rollback_failure_retains_primary_and_diagnostic(self):
        root=self.checkout();backend=self.private_backend(root);write=Path.write_bytes;calls=[]
        def fail(path,data):
            calls.append(path)
            if len(calls)==2:raise OSError('primary second write')
            if len(calls)==3:raise OSError('rollback first fault')
            return write(path,data)
        old=self.originals(root)
        try:
            with patch.object(Path,'write_bytes',fail):
                with self.assertRaisesRegex(OSError,'primary second write') as caught:backend.materialize(root,PACKET)
            self.assertEqual(len(caught.exception.rollback_failures),1)
            self.assertEqual((root/adapter.PATHS[1]).read_bytes(),old[adapter.PATHS[1]])
        finally:
            for name,data in old.items():write(root/name,data)
    def test_duplicate_json_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicate JSON'):adapter.load_backend(BACKEND_ROOT).load(b'{"a":1,"a":2}')
    def test_unsafe_path_rejected(self):
        with self.assertRaisesRegex(ValueError,'unsafe path'):adapter.load_backend(BACKEND_ROOT).safe_path(PACKET,'../escape')
    def test_hardlinked_packet_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'packet';shutil.copytree(PACKET,p)
            os.link(p/'manifest.json',Path(tmp)/'link')
            with self.assertRaisesRegex(ValueError,'hard-linked'):adapter.verify_packet(p,adapter.load_backend(BACKEND_ROOT))
    def test_symlink_packet_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'packet';shutil.copytree(PACKET,p)
            target=p/'manifest.json';raw=target.read_bytes();target.unlink();outside=Path(tmp)/'manifest';outside.write_bytes(raw)
            target.symlink_to(outside)
            with self.assertRaisesRegex(ValueError,'symlink'):adapter.verify_packet(p,adapter.load_backend(BACKEND_ROOT))
    def test_git_object_mismatch_refused(self):
        # Correct frozen bytes, with actual Git returning a deliberately wrong blob.
        root=self.checkout()
        original=subprocess.run
        def fault(args,**kwargs):
            result=original(args,**kwargs)
            if 'cat-file' in args:result.stdout=b'wrong Git object'
            return result
        with patch.object(subprocess,'run',fault):
            with self.assertRaisesRegex(ValueError,'exact base object'):adapter.load_backend(root)
    def test_exact_packet_has_only_two_reviewed_postimages(self):
        backend=adapter.load_backend(BACKEND_ROOT)
        rows=adapter.verify_packet(PACKET,backend)
        self.assertEqual({row['path'] for row in rows},set(adapter.PATHS))
        self.assertEqual(backend.BASE,'85a00d4bb54cf95199ee67dfd97d2b168233ff68')
    def test_postimage_tamper_rejected_before_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'packet';shutil.copytree(PACKET,p)
            target=p/'files'/adapter.PATHS[0];target.write_bytes(target.read_bytes()+b'changed')
            with self.assertRaisesRegex(ValueError,'packet mismatch'):
                adapter.verify_packet(p,adapter.load_backend(BACKEND_ROOT))
    def test_unlisted_packet_member_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'packet';shutil.copytree(PACKET,p)
            (p/'extra.py').write_text('pass')
            with self.assertRaisesRegex(ValueError,'unexpected packet member'):
                adapter.verify_packet(p,adapter.load_backend(BACKEND_ROOT))
    def test_changed_backend_cannot_execute(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=root/adapter.BACKEND;p.parent.mkdir(parents=True)
            p.write_text('raise AssertionError("must never execute")')
            with self.assertRaisesRegex(ValueError,'backend changed'):adapter.load_backend(root)
    def test_changed_seal_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'packet';shutil.copytree(PACKET,p)
            (p/'seal.json').write_bytes((p/'seal.json').read_bytes()+b' ')
            with self.assertRaisesRegex(ValueError,'seal mismatch'):
                adapter.verify_packet(p,adapter.load_backend(BACKEND_ROOT))

if __name__=='__main__':unittest.main()
