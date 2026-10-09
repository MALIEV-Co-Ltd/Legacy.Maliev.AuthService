"""Pure pre-birth Auth fixture policy for an existing private-daemon owner hook.

This allocates no resource and grants no authority. A qualified owner must call
it before Docker create, enforce the lease, observe real custody and clean up.
"""
import copy
import math
import re
import uuid

LABEL = 'maliev.validation.auth-refresh'
MAX_MEMORY = 384 * 1024**2

def require(value, message):
    if not value: raise ValueError(message)

def contract(value, now):
    expected = {'runId','cgroupParent','imageId','imageVolumes','expiresAtUnix','memoryBytes','nanoCpus','pidsLimit'}
    require(type(value) is dict and set(value) == expected, 'Closed owner contract required')
    require(str(uuid.UUID(value['runId'])) == value['runId'], 'Canonical owner run required')
    require(type(now) in (int,float) and math.isfinite(now), 'Finite actual time required')
    expiry = value['expiresAtUnix']
    require(type(expiry) in (int,float) and math.isfinite(expiry) and 30 <= expiry-now <= 3600, 'Finite owner lease required')
    require(value['cgroupParent'] == 'codex-auth-refresh-'+value['runId']+'.slice', 'Exact Auth owner cgroup required')
    require(type(value['imageId']) is str and re.fullmatch('sha256:[0-9a-f]{64}',value['imageId']), 'Pinned inspected image required')
    volumes = value['imageVolumes']
    require(type(volumes) is list and len(volumes) == 1 and volumes[0] in ('/var/lib/postgresql','/var/lib/postgresql/data'), 'Reviewed image data-volume declaration required')
    for key, ceiling in (('memoryBytes',MAX_MEMORY),('nanoCpus',1000000000),('pidsLimit',64)):
        require(type(value[key]) is int and 0 < value[key] <= ceiling, 'Pre-birth resource cap required')

def admit_create(payload, owner, now):
    contract(owner,now)
    require(type(payload) is dict and payload.get('Image') == 'postgres:18-alpine', 'Only Auth PostgreSQL fixture accepted')
    allowed = {'Image','Env','HostConfig','Labels','ExposedPorts','Cmd','Entrypoint','Hostname','Healthcheck','AttachStdout','AttachStderr','Tty','OpenStdin','StdinOnce'}
    require(set(payload) <= allowed, 'Unsupported create field')
    for key in ('Entrypoint','Cmd'):
        value = payload.get(key)
        require(value is None or (type(value) is list and not value), 'Workload override rejected')
    require(payload.get('Healthcheck') is None, 'Health-check command override rejected')
    host = payload.get('HostConfig',{})
    require(type(host) is dict, 'Invalid HostConfig')
    require(set(host) <= {'PortBindings','PublishAllPorts','AutoRemove','NetworkMode','Binds','Mounts','Tmpfs','Memory','NanoCpus','PidsLimit','CgroupParent','Privileged'}, 'Unsupported host capability')
    require(not host.get('Binds') and not host.get('Mounts') and not host.get('Privileged') and not host.get('PublishAllPorts') and not host.get('AutoRemove'), 'Persistent, privileged or unobserved fixture rejected')
    require(host.get('NetworkMode','default') in ('default','bridge'), 'Host or foreign network rejected')
    require(not host.get('Tmpfs'), 'Caller-owned mount override rejected')
    labels = payload.get('Labels',{})
    require(type(labels) is dict and all(type(k) is str and type(v) is str for k,v in labels.items()), 'Invalid fixture labels')
    require(LABEL not in labels, 'Caller cannot assert owner label')
    bindings = host.get('PortBindings',{})
    require(type(bindings) is dict and set(bindings) <= {'5432/tcp'}, 'Only PostgreSQL port admitted')
    for rows in bindings.values():
        require(type(rows) is list and len(rows) == 1, 'One disposable PostgreSQL binding required')
        for row in rows:
            require(type(row) is dict and set(row) <= {'HostIp','HostPort'} and row.get('HostIp','') in ('','127.0.0.1') and row.get('HostPort','') in ('','0'), 'Only dynamic loopback forwarding admitted')
    result = copy.deepcopy(payload)
    result['Image'] = owner['imageId']
    result['Labels'] = dict(labels, **{LABEL:owner['runId'],'maliev.validation.expires':str(owner['expiresAtUnix'])})
    capped = copy.deepcopy(host)
    capped.update({'Memory':owner['memoryBytes'],'MemorySwap':owner['memoryBytes'],'NanoCpus':owner['nanoCpus'],'PidsLimit':owner['pidsLimit'],'CgroupParent':owner['cgroupParent'],'AutoRemove':False,'Privileged':False,'PublishAllPorts':False,'NetworkMode':'bridge', 'Tmpfs':{path:'rw,noexec,nosuid,size='+str(owner['memoryBytes']) for path in owner['imageVolumes']}})
    capped['PortBindings'] = {port:[{'HostIp':'127.0.0.1','HostPort':''}] for port in bindings}
    result['HostConfig'] = capped
    return result
