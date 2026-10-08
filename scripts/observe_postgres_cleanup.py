"""Bounded GET-only ordinary CI observation; never cleanup or native admission."""
import argparse
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import time
from urllib.parse import urlencode

MAX_BYTES = 2 * 1024 * 1024
MAX_CONTAINERS = 16
MAX_EVENTS = 256
ID = re.compile(r'[a-f0-9]{64}')
SESSION = re.compile(r'[a-f0-9]{32}|[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
ACTIONS = {'create', 'start', 'kill', 'die', 'stop', 'destroy'}
IMAGE = 'postgres:18-alpine'


class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect('/var/run/docker.sock')


def rpc(path, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('Observation deadline')
    if not (path == '/info' or path == '/containers/json?all=1' or
            re.fullmatch(r'/containers/[a-f0-9]{64}/json', path) or path.startswith('/events?')):
        raise ValueError('Observation GET route rejected')
    connection = UnixConnection('localhost', timeout=min(3, remaining))
    try:
        connection.request('GET', path)
        endpoint_socket = connection.sock
        response = connection.getresponse()
        chunks, size = [], 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Observation deadline')
            endpoint_socket.settimeout(min(3, remaining))
            chunk = response.read1(min(16384, MAX_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_BYTES:
                raise ValueError('Observation response bound')
        raw = b''.join(chunks)
        if len(raw) > MAX_BYTES or time.monotonic() > deadline:
            raise ValueError('Observation response bound')
        if response.status == 404:
            return 404, None
        if response.status != 200:
            raise ValueError('Observation status rejected')
        if path.startswith('/events?'):
            lines = raw.splitlines()
            if len(lines) > MAX_EVENTS:
                raise ValueError('Observation event bound')
            return 200, [json.loads(line) for line in lines]
        return 200, json.loads(raw)
    finally:
        connection.close()


def container(document):
    identifier = document['Id']
    if not ID.fullmatch(identifier) or document['Config']['Image'] != IMAGE:
        raise ValueError('Unexpected PostgreSQL identity')
    labels = document['Config'].get('Labels') or {}
    session = labels.get('org.testcontainers.sessionId')
    if session is not None and not SESSION.fullmatch(session):
        raise ValueError('Unexpected session identity')
    state = document['State']
    host = document['HostConfig']
    numeric = {key: state[key] for key in ('Pid', 'ExitCode')}
    numeric.update({key: host[key] for key in ('Memory', 'NanoCpus')})
    if host.get('PidsLimit') is not None:
        numeric['PidsLimit'] = host['PidsLimit']
    if any(type(value) is not int or value < -1 for value in numeric.values()):
        raise ValueError('Unexpected numeric state')
    flags = {key: state[key] for key in ('Running', 'Dead', 'OOMKilled')}
    if any(type(value) is not bool for value in flags.values()):
        raise ValueError('Unexpected state flags')
    mounts = document.get('Mounts', [])
    if not isinstance(mounts, list) or len(mounts) > 16:
        raise ValueError('Unexpected mount inventory')
    volumes = []
    for mount in mounts:
        if mount.get('Type') == 'volume':
            name = mount.get('Name', '')
            if not ID.fullmatch(name):
                raise ValueError('Unexpected volume identity')
            volumes.append(name)
    return dict(id=identifier, testcontainersSession=session, numeric=numeric, state=flags,
                anonymousVolumeIds=volumes, mountCount=len(mounts),
                persistentDataUnknown=bool(mounts), authenticatedTaskOwnership=False)


def events(rows, baseline_ids):
    if not isinstance(rows, list) or len(rows) > MAX_EVENTS:
        raise ValueError('Event inventory bound')
    result, identifiers = [], set()
    for row in rows:
        actor = row.get('Actor', {})
        attributes = actor.get('Attributes', {})
        if row.get('Type') != 'container' or attributes.get('image') != IMAGE:
            continue
        identifier = actor.get('ID', '')
        if not ID.fullmatch(identifier) or identifier in baseline_ids:
            continue
        action = row.get('Action')
        if action not in ACTIONS:
            continue
        timestamp = row.get('timeNano')
        if type(timestamp) is not int or timestamp < 0:
            raise ValueError('Event timestamp rejected')
        item = dict(id=identifier, action=action, timeNano=timestamp)
        for key in ('signal', 'exitCode'):
            value = attributes.get(key)
            if value is not None:
                if not isinstance(value, str) or not re.fullmatch(r'-?[0-9]{1,10}', value):
                    raise ValueError('Event numeric metadata rejected')
                item[key] = int(value)
        result.append(item)
        identifiers.add(identifier)
        if len(identifiers) > MAX_CONTAINERS:
            raise ValueError('Container inventory bound')
    return result, identifiers


def context(environment):
    if (environment.get('GITHUB_REPOSITORY') != 'MALIEV-Co-Ltd/Legacy.Maliev.AuthService' or
            environment.get('RUNNER_ENVIRONMENT') != 'github-hosted' or
            environment.get('GITHUB_ACTIONS') != 'true' or
            environment.get('DOCKER_HOST', 'unix:///var/run/docker.sock') != 'unix:///var/run/docker.sock'):
        raise ValueError('Ordinary hosted observation only')
    for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        if not re.fullmatch(r'[0-9]{1,20}', environment.get(key, '')):
            raise ValueError('Run identity rejected')
    if not re.fullmatch(r'[a-f0-9]{40}', environment.get('GITHUB_SHA', '')):
        raise ValueError('Source identity rejected')
    return dict(run=environment['GITHUB_RUN_ID'], attempt=environment['GITHUB_RUN_ATTEMPT'],
                sha=environment['GITHUB_SHA'], bootId=Path('/proc/sys/kernel/random/boot_id').read_text().strip())


def write(directory, name, value):
    for part in (directory, *directory.parents):
        if part.is_symlink():
            raise ValueError('Linked receipt destination rejected')
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / name
    raw = (json.dumps(value, sort_keys=True) + '\n').encode()
    if len(raw) > 256 * 1024:
        raise ValueError('Receipt size bound')
    with target.open('xb') as stream:
        stream.write(raw)


def observe(role, directory, environment, query=rpc):
    identity = context(environment)
    result = dict(schemaVersion=1, context=identity, observationComplete=False,
                  nativeAccepted=False, resourcesDeleted=False, cancelledOperation='unknown',
                  eventWindowCompletenessCertified=False, diagnosticErrors=[])
    deadline = time.monotonic() + 20
    try:
        endpoint = Path('/var/run/docker.sock').stat()
        if not stat.S_ISSOCK(endpoint.st_mode):
            raise ValueError('Docker endpoint is not a socket')
        result['socket'] = dict(device=endpoint.st_dev, inode=endpoint.st_ino, sharedDaemon=True)
        _, info = query('/info', deadline)
        engine = info['ID']
        if not isinstance(engine, str) or not re.fullmatch(r'[A-Za-z0-9:-]{1,96}', engine):
            raise ValueError('Engine identity rejected')
        result['engineId'] = engine
        if role == 'before':
            _, rows = query('/containers/json?all=1', deadline)
            if not isinstance(rows, list) or len(rows) > MAX_CONTAINERS:
                raise ValueError('Baseline inventory bound')
            ids = [row['Id'] for row in rows]
            if not all(isinstance(value, str) and ID.fullmatch(value) for value in ids):
                raise ValueError('Baseline identity rejected')
            result.update(baselineIds=ids, sinceUnix=int(time.time()), observationComplete=True)
        else:
            source = directory / 'before.json'
            if source.is_symlink() or source.stat().st_size > 256 * 1024:
                raise ValueError('Baseline receipt rejected')
            before = json.loads(source.read_bytes())
            if (not before['observationComplete'] or before['context'] != identity or
                    before['engineId'] != engine or before['socket'] != result['socket']):
                raise ValueError('Baseline generation differs')
            until = int(time.time())
            if not 0 <= until - before['sinceUnix'] <= 5400:
                raise ValueError('Observation window rejected')
            _, rows = query('/events?' + urlencode(dict(since=before['sinceUnix'], until=until,
                                                      filters=json.dumps({'type': ['container']}))), deadline)
            safe_events, identifiers = events(rows, set(before['baselineIds']))
            inventory = []
            for identifier in sorted(identifiers):
                status, document = query('/containers/' + identifier + '/json', deadline)
                if status != 404 and (status != 200 or document.get('Id') != identifier):
                    raise ValueError('Inspect response identity differs')
                inventory.append(dict(id=identifier, absenceVerified=True) if status == 404 else container(document))
            result.update(events=safe_events, containers=inventory, observationComplete=True,
                          observedBoundary='PostgreSQL lifecycle; operation not inferred')
    except Exception as error:
        # Keep only a built-in error type; no HTTP body, SQL or exception message.
        result['diagnosticErrors'].append(type(error).__name__ if type(error) in
            (ValueError, TypeError, KeyError, FileNotFoundError, TimeoutError,
             OSError, json.JSONDecodeError) else 'ObservationError')
    write(directory, role + '.json', result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', choices=('before', 'after'), required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    # A socket inactivity timeout cannot bound trickled HTTP headers. A Linux
    # process timer bounds the complete observation without another worker.
    def expired(_number, _frame):
        raise TimeoutError('Observation deadline')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 20)
    try:
        observe(args.role, args.directory, os.environ)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


if __name__ == '__main__':
    main()
