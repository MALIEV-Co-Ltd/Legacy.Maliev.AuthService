import importlib.util,json,os,pathlib,tempfile,unittest,hashlib
from unittest import mock
spec=importlib.util.spec_from_file_location('candidate',pathlib.Path(__file__).with_name('verify_iam_overlay.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ORIGINAL_VERIFY_SOURCE=m.verify_source
SOURCE=b'<Project><ItemGroup><PackageReference Include="Microsoft.AspNetCore.WebUtilities" Version="10.0.5" /></ItemGroup></Project>'
OVERLAY=pathlib.Path(__file__).with_name('iam-http-package-overlay.targets')
class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  m.ROOT=pathlib.Path(self.tmp.name);m.IAM=m.ROOT/'iam/Application/Application.csproj';m.HOST=m.ROOT/'acceptance/GenuineIamHost/GenuineIamHost.csproj';m.TESTS=m.ROOT/'acceptance/GenuineIamHttp.Tests/GenuineIamHttp.Tests.csproj';m.INFRA=m.ROOT/'iam/Infrastructure/Infrastructure.csproj';m.OVERLAY=m.ROOT/'eng/overlay.targets'
  for f in (m.IAM,m.INFRA,m.HOST,m.TESTS,m.OVERLAY): f.parent.mkdir(parents=True,exist_ok=True)
  m.SOURCE_SHA=hashlib.sha256(SOURCE).hexdigest();m.IAM.write_bytes(SOURCE);m.INFRA.write_text('<Project/>');m.HOST.write_text('<Project/>');m.TESTS.write_text('<Project/>');m.OVERLAY.write_bytes(OVERLAY.read_bytes())
  (m.ROOT/'artifacts').mkdir(); patcher=mock.patch.object(m,'verify_source',return_value=210);patcher.start();self.addCleanup(patcher.stop)
 def write(self,p,obj): p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(obj))
 def prepare(self):
  props={'MSBuildProjectFullPath':str(m.IAM.resolve()),'Auth201ExpectedIamApplicationProject':str(m.IAM.resolve()),'CustomAfterMicrosoftCommonTargets':str(m.OVERLAY.resolve())}
  self.write(m.ROOT/'artifacts/genuine-iam-evaluation.json',{'Properties':props,'Items':{'PackageReference':[{'Identity':m.NAME,'Version':'10.0.15'}]}})
  self.write(m.ROOT/'artifacts/genuine-iam-baseline-evaluation.json',{'Items':{'PackageReference':[{'Identity':m.NAME,'Version':'10.0.5'}]}})
  for p in (m.IAM,m.INFRA,m.HOST,m.TESTS): self.write(p.parent/'obj/project.assets.json',{'project':{'restore':{'projectPath':str(p.resolve())}},'libraries':{m.KEY:{}},'targets':{'net10.0':{m.KEY:{}}}})
  out=m.HOST.parent/'bin/Release/net10.0';out.mkdir(parents=True);(out/'GenuineIamHost.dll').write_bytes(b'host')
  self.write(out/'GenuineIamHost.deps.json',{'libraries':{m.KEY:{}},'targets':{'net10.0':{m.KEY:{}}},'runtimeTarget':{'name':'net10.0'}})
 def test_inventory_rejects_changed_missing_and_extra(self):
  m.SOURCE_ROOT=m.ROOT/'actual';m.SOURCE_ROOT.mkdir();file=m.SOURCE_ROOT/'one.cs';file.write_bytes(b'abc')
  oid=hashlib.sha1(b'blob 3\0abc').hexdigest()
  # Bypass the default no-Git mock only to exercise the source-tree verifier.
  with mock.patch.object(m,'verify_source',m.verify_source.__wrapped__ if hasattr(m.verify_source,'__wrapped__') else ORIGINAL_VERIFY_SOURCE), mock.patch.object(m,'source_inventory',return_value={'one.cs':oid}):
   self.assertEqual(m.verify_source(exclusive=True),1)
   (m.SOURCE_ROOT/'extra').write_text('x')
   with self.assertRaises(ValueError):m.verify_source(exclusive=True)
   (m.SOURCE_ROOT/'extra').unlink();file.write_bytes(b'bad')
   with self.assertRaises(ValueError):m.verify_source()
   file.unlink()
   with self.assertRaises(ValueError):m.verify_source()
 def test_preflight_and_stale_failure(self):
  m.preflight(); p=m.IAM.parent/'obj/project.assets.json';p.parent.mkdir();p.write_text('{}')
  with self.assertRaises(ValueError):m.preflight()
 def test_restored_package_hash_is_recorded_when_present(self):
  self.prepare(); package=m.ROOT/'packages/microsoft.aspnetcore.webutilities/10.0.15/lib/net10.0/Microsoft.AspNetCore.WebUtilities.dll'
  package.parent.mkdir(parents=True);package.write_bytes(b'package')
  with mock.patch.dict(os.environ,{'NUGET_PACKAGES':str(m.ROOT/'packages')}):
   self.assertEqual(m.verify()['packageSha256'],hashlib.sha256(b'package').hexdigest())
   package.unlink();self.assertIsNone(m.verify()['packageSha256'])
 def test_test_graph_freshness_and_independent_version(self):
  p=m.TESTS.parent/'obj/project.assets.json';p.parent.mkdir();p.write_text('{}')
  with self.assertRaises(ValueError):m.preflight()
  p.unlink();p.parent.rmdir();self.prepare()
  d=json.loads(p.read_text());d['libraries']={m.NAME+'/10.0.12':{}};d['targets']={'net10.0':{m.NAME+'/10.0.12':{}}};self.write(p,d)
  self.assertEqual(m.verify()['testGraphWebUtilities'],[m.NAME+'/10.0.12'])
 def test_source_and_overlay_wrong(self):
  m.IAM.write_bytes(b'changed')
  with self.assertRaises(ValueError):m.preflight()
  m.IAM.write_bytes(SOURCE);m.OVERLAY.write_bytes(b'changed')
  with self.assertRaises(ValueError):m.preflight()
 def test_expected_evidence_and_host_change(self):
  self.prepare();a=m.verify();self.assertEqual(len(a['hostSha256']),64)
  (m.HOST.parent/'bin/Release/net10.0/GenuineIamHost.dll').write_bytes(b'other');self.assertNotEqual(a,m.verify())
 def test_reject_wrong_eval_and_old_graph(self):
  self.prepare();path=m.ROOT/'artifacts/genuine-iam-evaluation.json';d=json.loads(path.read_text());d['Items']['PackageReference'][0]['Version']='10.0.5';self.write(path,d)
  with self.assertRaises(ValueError):m.verify()
  d['Items']['PackageReference'][0]['Version']='10.0.15';self.write(path,d);p=m.HOST.parent/'obj/project.assets.json';a=json.loads(p.read_text());a['targets']['net10.0']={m.NAME+'/10.0.5':{}};self.write(p,a)
  with self.assertRaises(ValueError):m.verify()
 def test_reject_missing_property_and_override(self):
  self.prepare();p=m.ROOT/'artifacts/genuine-iam-evaluation.json';d=json.loads(p.read_text());d['Properties'].pop('CustomAfterMicrosoftCommonTargets');self.write(p,d)
  with self.assertRaises(ValueError):m.verify()
  d['Properties']['CustomAfterMicrosoftCommonTargets']=str(m.OVERLAY.resolve());d['Items']['PackageReference'][0]['VersionOverride']='10.0.5';self.write(p,d)
  with self.assertRaises(ValueError):m.verify()
if __name__=='__main__': print('pid='+str(os.getpid()),flush=True);unittest.main(verbosity=2)
