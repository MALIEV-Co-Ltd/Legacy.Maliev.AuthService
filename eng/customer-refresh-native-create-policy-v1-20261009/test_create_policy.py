import copy
import unittest
import create_policy as policy

class CreatePolicyTests(unittest.TestCase):
    def setUp(self):
        run = '11111111-1111-4111-8111-111111111111'
        self.owner = {'runId':run,'cgroupParent':'codex-auth-refresh-'+run+'.slice','imageId':'sha256:'+'a'*64,'imageVolumes':['/var/lib/postgresql'],'expiresAtUnix':1600,'memoryBytes':384*1024**2,'nanoCpus':1000000000,'pidsLimit':64}
        self.payload = {'Image':'postgres:18-alpine','Env':['FIXTURE=private'],'Labels':{'org.testcontainers':'true'},'HostConfig':{'PortBindings':{'5432/tcp':[{'HostIp':'','HostPort':''}]}}}

    def test_injects_prebirth_caps_exact_owner_and_disposable_storage(self):
        before = copy.deepcopy(self.payload)
        result = policy.admit_create(self.payload,self.owner,1000)
        self.assertEqual(before,self.payload)
        self.assertEqual(self.owner['imageId'],result['Image'])
        self.assertEqual(self.owner['runId'],result['Labels'][policy.LABEL])
        self.assertEqual(self.owner['memoryBytes'],result['HostConfig']['Memory'])
        self.assertEqual(self.owner['memoryBytes'],result['HostConfig']['MemorySwap'])
        self.assertEqual({'/var/lib/postgresql':'rw,noexec,nosuid,size=402653184'},result['HostConfig']['Tmpfs'])
        self.assertEqual('127.0.0.1',result['HostConfig']['PortBindings']['5432/tcp'][0]['HostIp'])

    def test_rejects_persistence_privilege_and_foreign_network(self):
        for name,value in (('Binds',['/foreign:/data']),('Mounts',[{'Type':'volume'}]),('Privileged',True),('NetworkMode','host'),('PublishAllPorts',True),('AutoRemove',True),('Tmpfs',{'/unreviewed':'rw'})):
            row = copy.deepcopy(self.payload); row['HostConfig'][name] = value
            with self.subTest(name=name), self.assertRaises(ValueError): policy.admit_create(row,self.owner,1000)

    def test_rejects_fake_owner_or_expired_uncapped_lease(self):
        for name,value in (('runId','other'),('cgroupParent','foreign.slice'),('expiresAtUnix',900),('memoryBytes',True),('memoryBytes',9999999999),('nanoCpus',0),('pidsLimit',65),('imageId','mutable:tag'),('imageVolumes',['/foreign'])):
            row = dict(self.owner); row[name]=value
            with self.subTest(name=name), self.assertRaises(ValueError): policy.admit_create(self.payload,row,1000)

    def test_rejects_wrong_image_label_and_public_fixed_port(self):
        rows = []
        row = copy.deepcopy(self.payload); row['Image']='postgres:latest'; rows.append(row)
        row = copy.deepcopy(self.payload); row['Labels'][policy.LABEL]=self.owner['runId']; rows.append(row)
        row = copy.deepcopy(self.payload); row['HostConfig']['PortBindings']['5432/tcp'][0]={'HostIp':'0.0.0.0','HostPort':'5432'}; rows.append(row)
        row = copy.deepcopy(self.payload); row['HostConfig']['Devices']=['/dev/foreign']; rows.append(row)
        for row in rows:
            with self.assertRaises(ValueError): policy.admit_create(row,self.owner,1000)

    def test_rejects_workload_and_health_command_overrides(self):
        for name,value in (('Entrypoint',['sh']),('Cmd',['sleep','3600']),('Healthcheck',{'Test':['CMD','sh','-c','other']})):
            row = copy.deepcopy(self.payload); row[name]=value
            with self.subTest(name=name), self.assertRaises(ValueError): policy.admit_create(row,self.owner,1000)

if __name__ == '__main__': unittest.main()
