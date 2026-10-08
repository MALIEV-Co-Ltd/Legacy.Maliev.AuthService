"""Actual Linux stub lifecycle proof. Never invokes an SDK or starts a container."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import tarfile
import time

from private_docker_proxy import OWNER, UnixConnection, rpc

CASES = ('normal', 'cancellation', 'output_limit', 'output_timeout', 'first_failure')
EXPECTED_FAILURES = (None, 'Cancelled', 'OutputLimit', 'OutputTimeout', 'Exit:7')


def save(path, value):
    temporary = path.with_suffix('.proof-next')
    with temporary.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def identity(pid):
    stat = Path(f'/proc/{pid}/stat')
    before = stat.read_text().rsplit(')', 1)[1].split()[19]
    result = dict(pid=pid, startTicks=before, executable=os.readlink(f'/proc/{pid}/exe'),
                  cgroup=Path(f'/proc/{pid}/cgroup').read_text().strip(),
                  bootId=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    if stat.read_text().rsplit(')', 1)[1].split()[19] != before:
        raise RuntimeError('Child generation changed during observation')
    return result


def check_caps(cgroup):
    root = Path('/sys/fs/cgroup') / cgroup.removeprefix('0::').lstrip('/')
    expected = {'memory.max': str(128 * 1024 ** 2), 'memory.swap.max': '0',
                'cpu.max': '100000 100000', 'pids.max': '512'}
    actual = {name: (root / name).read_text().strip() for name in expected}
    if actual != expected:
        raise RuntimeError('Actual stub workload caps differ')
    return actual


def child_case(case, cgroup, receipt):
    if case not in CASES:
        raise ValueError('Unknown stub case')
    code = "import os,time; time.sleep(.25); " + {
        'normal': "os.write(1,b'ready'); time.sleep(.05)",
        'cancellation': 'time.sleep(30)',
        'output_limit': "os.write(1,b'x'*2048); time.sleep(30)",
        'output_timeout': "os.write(1,b'ready'); time.sleep(30)",
        'first_failure': "os.write(1,b'ready'); raise SystemExit(7)",
    }[case]
    row = dict(case=case, firstFailure=None, outputBytes=0, readersClosed=False,
               exited=False, handleClosed=False)
    process = subprocess.Popen(['/usr/bin/python3', '-I', '-c', code], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    pidfd = None
    first_error = None
    row['cleanupErrors'] = []

    def retain(error, phase):
        nonlocal first_error
        row['cleanupErrors'].append({'phase': phase, 'type': type(error).__name__})
        if first_error is None:
            first_error = error
            row['firstErrorType'] = type(error).__name__

    def send(sig):
        if pidfd is not None:
            signal.pidfd_send_signal(pidfd, sig)
        elif sig == signal.SIGTERM:
            process.terminate()  # The unreaped Popen child retains its identity.
        else:
            process.kill()

    try:
        pidfd = os.pidfd_open(process.pid)
        row['retainedPidfd'] = pidfd
        row['identity'] = identity(process.pid)
        if row['identity']['cgroup'] != cgroup:
            raise RuntimeError('Stub escaped its pre-registered unit')
        row['caps'] = check_caps(cgroup)
        save(receipt, row)  # Exact retained handle/birth evidence before signals or reads.
        deadline = time.monotonic() + 2
        with selectors.DefaultSelector() as reader:
            reader.register(process.stdout, selectors.EVENT_READ)
            while True:
                if case == 'cancellation':
                    row['firstFailure'] = 'Cancelled'
                    signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                    break
                if time.monotonic() >= deadline:
                    row['firstFailure'] = 'OutputTimeout'
                    break
                if not reader.select(min(.05, max(0, deadline - time.monotonic()))):
                    continue
                chunk = os.read(process.stdout.fileno(), 1025)
                if not chunk:
                    break
                row['outputBytes'] += len(chunk)
                if row['outputBytes'] > 1024:
                    row['firstFailure'] = 'OutputLimit'
                    break
        if row['firstFailure'] and process.poll() is None:
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        row['exitCode'] = process.wait(timeout=3)
        if row['firstFailure'] is None and row['exitCode']:
            row['firstFailure'] = 'Exit:' + str(row['exitCode'])
    except BaseException as error:
        first_error = error
        row['firstErrorType'] = type(error).__name__
    finally:
        # A retained pidfd targets the original generation even if its PID is reused.
        alive = True
        try:
            alive = process.poll() is None
        except BaseException as error:
            retain(error, 'poll')
        if alive:
            try:
                send(signal.SIGTERM)
            except BaseException as error:
                retain(error, 'term')
            try:
                process.wait(timeout=3)
            except BaseException as error:
                retain(error, 'wait-after-term')
                try:
                    send(signal.SIGKILL)
                except BaseException as error:
                    retain(error, 'kill')
                try:
                    process.wait(timeout=3)
                except BaseException as error:
                    retain(error, 'wait-after-kill')
        row['exited'] = process.returncode is not None
        try:
            process.stdout.close()
            row['readersClosed'] = process.stdout.closed
        except BaseException as error:
            retain(error, 'reader-close')
        if pidfd is not None:
            try:
                os.close(pidfd)
                row['handleClosed'] = True
            except BaseException as error:
                retain(error, 'pidfd-close')
        try:
            save(receipt, row)
        except BaseException as error:
            retain(error, 'final-receipt')
    if first_error is not None:
        raise first_error
    expected = {'normal': None, 'cancellation': 'Cancelled', 'output_limit': 'OutputLimit',
                'output_timeout': 'OutputTimeout', 'first_failure': 'Exit:7'}[case]
    if row['firstFailure'] != expected or not all(row[key] for key in ('exited', 'readersClosed', 'handleClosed')):
        raise RuntimeError('Actual stub outcome/cleanup differs')
    return row


def import_empty_image(socket, run):
    # A local empty tar creates a disposable image with no files, volumes or executable.
    # No registry download or container process is needed to inspect create-time caps.
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w'):
        pass
    connection = UnixConnection(socket, timeout=5)
    response = None
    try:
        connection.request('POST', '/images/create?fromSrc=-&repo=' + run, archive.getvalue(),
                           {'Content-Type': 'application/x-tar'})
        response = connection.getresponse()
        raw = bytearray()
        deadline = time.monotonic() + 15
        while not response.isclosed() and response.length != 0:
            if time.monotonic() >= deadline:
                raise TimeoutError('Empty image import deadline')
            chunk = response.read1(min(65536, 1048577 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > 1048576:
                raise RuntimeError('Import response exceeds bound')
        messages = [json.loads(line) for line in raw.splitlines() if line]
        identifiers = [item['status'] for item in messages if item.get('status', '').startswith('sha256:')]
        if response.status != 200 or len(identifiers) != 1 or any('error' in item for item in messages):
            raise RuntimeError('Disposable empty image import failed')
        return identifiers[0]
    finally:
        if response:
            response.close()
        connection.close()


def workload(context_path, receipt):
    context = json.loads(context_path.read_text())
    run, socket = context['owner'], context['dockerHost'].removeprefix('unix://')
    current = identity(os.getpid())
    if current['cgroup'] != '0::' + context['sdkCgroup'] or os.geteuid() != 0:
        raise RuntimeError('Exact capped stub unit required')
    result = dict(schemaVersion=1, owner=run, identity=current, caps=check_caps(current['cgroup']),
                  sdkStarted=False, nativeAccepted=False, containerProcessStarted=False,
                  cases=[], expectedProxyRejections=0)
    save(receipt, result)
    status, info = rpc(socket, 'GET', '/info')
    if status != 200 or info['DockerRootDir'] != '/var/tmp/' + run + '/docker-data':
        raise RuntimeError('Admitted private-daemon info differs')
    image = import_empty_image(socket, run)
    for host in ({'CgroupParent': 'foreign.slice'}, {'Privileged': True}, {'Binds': ['/tmp:/tmp']}):
        status, body = rpc(socket, 'POST', '/containers/create', {'Image': image, 'HostConfig': host})
        if status != 503 or body != {'message': 'Owned Docker admission failed'}:
            raise RuntimeError('Unsafe allocation was not rejected')
        result['expectedProxyRejections'] += 1
        save(receipt, result)
    status, created = rpc(socket, 'POST', '/containers/create',
                          {'Image': image, 'Cmd': ['/absent'], 'HostConfig': {'Memory': 67108864, 'NanoCpus': 100000000}})
    if status != 201:
        raise RuntimeError('Disposable create failed')
    identifier = created['Id']
    status, document = rpc(socket, 'GET', '/containers/' + identifier + '/json')
    host = document['HostConfig']
    if status != 200 or document['State']['Running'] or document['State']['Pid'] != 0 or document['Mounts'] or \
            host['Memory'] != 67108864 or host['MemorySwap'] != 67108864 or host['NanoCpus'] != 100000000 or \
            host['CgroupParent'] != context['dockerCgroupParent'] or \
            document['Config']['Labels'] != {'codex.hosted-owner': OWNER, 'codex.hosted-run': run}:
        raise RuntimeError('Actual pre-start container caps/ownership differ')
    result['createdContainer'] = dict(id=identifier, imageId=document['Image'], created=document['Created'],
                                    memory=host['Memory'], nanoCpus=host['NanoCpus'],
                                    cgroupParent=host['CgroupParent'], mounts=[], running=False)
    save(receipt, result)
    status, _ = rpc(socket, 'DELETE', '/containers/' + identifier + '?force=false&v=false')
    absent, _ = rpc(socket, 'GET', '/containers/' + identifier + '/json')
    if status != 204 or absent != 404:
        raise RuntimeError('Exact disposable container absence not proved')
    result['createdContainer']['absenceVerified'] = True
    for case in CASES:
        result['cases'].append(child_case(case, current['cgroup'], receipt.with_name('stub-' + case + '.json')))
        save(receipt, result)
    result['workloadProofPassed'] = True
    result['expectedOwnedWorkloadExit'] = 7
    save(receipt, result)
    # Exercise the existing owner's actual failed phase and independent recovery.
    # A successful cleanup must preserve this original exit, never accept the lane.
    raise SystemExit(7)


def validate_readback(evidence):
    directory = evidence / 'resources'
    launch = json.loads((evidence / 'launcher.json').read_text())
    proof = json.loads((directory / 'stub-proof.json').read_text())
    cleanup = json.loads((directory / 'external-cleanup.json').read_text())
    proxy = json.loads((directory / 'containers.json').read_text())
    foreign = json.loads((directory / 'stub-foreign-peer.json').read_text())
    units = json.loads((directory / 'units.json').read_text())
    context = json.loads((directory / 'native-context.json').read_text())
    run = launch['run']
    if launch['stage'] != 'proof' or launch['nativeAccepted'] is not False or not proof.get('workloadProofPassed') or \
            proof['owner'] != run or proof['sdkStarted'] or proof['nativeAccepted'] or proof['containerProcessStarted'] or \
            proof['expectedProxyRejections'] != 3 or proxy['failures'] != ['ValueError'] * 4 or \
            cleanup['remainingResources'] != 0 or not cleanup['sdkQuiescent'] or not cleanup['containersAbsent'] or \
            cleanup['originalQualificationFailuresRetained'] != ['RuntimeError:Owned phase failed', 'PrivateDockerAdmissionFailureRetained'] or \
            launch['failures'] != ['RuntimeException'] or [row['case'] for row in proof['cases']] != list(CASES) or \
            foreign['run'] != run or foreign['rejected'] is not True or foreign['status'] != 503 or \
            not proof['createdContainer'].get('absenceVerified'):
        raise RuntimeError('Exact proof, expected rejection history or independent cleanup differs')
    if not all(row['exited'] and row['readersClosed'] and row['handleClosed'] for row in proof['cases']):
        raise RuntimeError('Stub child ownership remains unresolved')
    actual_boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    sdk = units['units'][run + '-sdk.service']['mainProcess']
    sdk_exit = units['units'][run + '-sdk.service']
    if context['schemaVersion'] != 3 or context['owner'] != run or units['run'] != run or \
            proof.get('expectedOwnedWorkloadExit') != 7 or sdk_exit['exitCode'] != '7' or sdk_exit['result'] != 'exit-code' or \
            proof['identity']['bootId'] != actual_boot or proof['identity']['pid'] != sdk['pid'] or \
            proof['identity']['startTicks'] != sdk['startTicks'] or proof['identity']['executable'] != sdk['executable'] or \
            proof['identity']['cgroup'] != '0::' + context['sdkCgroup'] or sdk['cgroup'] != context['sdkCgroup']:
        raise RuntimeError('Actual workload/manager/context generation differs')
    expected_caps = {'memory.max': str(128 * 1024 ** 2), 'memory.swap.max': '0',
                     'cpu.max': '100000 100000', 'pids.max': '512'}
    if proof['caps'] != expected_caps:
        raise RuntimeError('Captured actual workload caps differ')
    for suffix, prefix in (('daemon', 'dockerDaemon'), ('proxy', 'dockerProxy')):
        observed = units['units'][run + '-' + suffix + '.service']['mainProcess']
        if observed['pid'] != context[prefix + 'Pid'] or observed['startTicks'] != context[prefix + 'StartTicks'] or \
                observed['cgroup'] != context[prefix + 'Cgroup']:
            raise RuntimeError('Private endpoint owner generation differs')
    created = proof['createdContainer']
    recorded = proxy['containers'].get(created['id'])
    if len(proxy['containers']) != 1 or not proxy['finalInventoryEmpty'] or not recorded or \
            recorded['imageId'] != created['imageId'] or recorded['created'] != created['created'] or \
            recorded['mounts'] or created['mounts'] or created['running'] or not recorded['absenceVerified'] or \
            recorded['memory'] != created['memory'] or created['memory'] != 67108864 or \
            recorded['nanoCpus'] != created['nanoCpus'] or created['nanoCpus'] != 100000000 or \
            recorded['cgroupParent'] != created['cgroupParent'] or created['cgroupParent'] != context['dockerCgroupParent'] or \
            recorded['labels'] != {'codex.hosted-owner': OWNER, 'codex.hosted-run': run}:
        raise RuntimeError('Independent disposable-container generation/caps/absence differs')
    seen = set()
    for row, expected, code in zip(proof['cases'], EXPECTED_FAILURES, (0, -15, -15, -15, 7), strict=True):
        birth = row['identity']
        key = (birth['pid'], birth['startTicks'])
        if row['firstFailure'] != expected or row['exitCode'] != code or \
                row.get('cleanupErrors') != [] or row.get('firstErrorType') is not None or \
                not isinstance(row.get('retainedPidfd'), int) or row['retainedPidfd'] < 0 or \
                birth['bootId'] != actual_boot or birth['executable'] != sdk['executable'] or \
                birth['cgroup'] != '0::' + context['sdkCgroup'] or birth['pid'] <= 0 or \
                not str(birth['startTicks']).isdigit() or int(birth['startTicks']) <= 0 or key in seen or \
                row['caps'] != proof['caps']:
            raise RuntimeError('Exact child generation/outcome/cap evidence differs')
        seen.add(key)
    return dict(owner=run, lifecycleProofAccepted=True, sdkStarted=False, nativeAccepted=False,
                cases=len(proof['cases']), expectedRejectionsRetained=4)


def reset_failed_terminal_unit(name):
    """Reset only retained failed units; inactive units may already be collected."""
    from hosted_owner import command
    state = command(['/usr/bin/systemctl', 'show', name, '--property=ActiveState', '--value']).strip()
    if state not in ('inactive', 'failed'):
        raise RuntimeError('Registered manager unit no longer terminal')
    if state == 'failed':
        command(['/usr/bin/systemctl', 'reset-failed', name])


def physical_cleanup(evidence):
    from hosted_owner import members, properties, command
    directory = evidence / 'resources'
    launch = json.loads((evidence / 'launcher.json').read_text())
    cleanup = json.loads((directory / 'external-cleanup.json').read_text())
    units = json.loads((directory / 'units.json').read_text())
    run = launch['run']
    if not re.fullmatch(r'auth-financial-[0-9]+-[0-9]+-[a-f0-9]{12}', run) or \
            launch['stage'] != 'proof' or launch['lane'] != 'auth' or units['run'] != run or \
            cleanup['remainingResources'] != 0 or not cleanup['sdkQuiescent'] or not cleanup['containersAbsent']:
        raise RuntimeError('Independent physical-cleanup ownership fence differs')
    # Preserve all receipts first. Remove only immutable registered fragments after
    # independent recovery, manager generation checks and actual empty cgroups.
    root = Path('/var/tmp') / run
    birth = json.loads((directory / 'stub-root.json').read_text())
    if birth['run'] != run or root.is_symlink() or root.parent != Path('/var/tmp') or root.stat().st_dev != birth['device'] or root.stat().st_ino != birth['inode']:
        raise RuntimeError('Disposable runtime root generation differs')
    names = dict(units['units'])
    expected = {run + '-' + suffix for suffix in ('daemon.service', 'proxy.service', 'sdk.service', 'expiry.timer', 'expiry.service')}
    expected.add('authfinancial' + run.replace('auth-financial-', '').replace('-', '') + '.slice')
    if not names or not set(names).issubset(expected) or launch['controlUnit'] != run + '-control.service' or \
            launch['recoveryUnit'] != run + '-recovery.service':
        raise RuntimeError('Foreign registered resource in cleanup receipt')
    for name in (launch['controlUnit'], launch['recoveryUnit']):
        state = properties(name)
        if state['ActiveState'] not in ('inactive', 'failed') or (state['ControlGroup'] and members(state['ControlGroup'])):
            raise RuntimeError('Outer allocating owner remains active')
    for name, row in names.items():
        state = properties(name)
        fragment = Path(row['fragment'])
        if state['Id'] != name or state['FragmentPath'] != str(fragment) or \
                (state['InvocationID'] and row['invocationId'] != state['InvocationID']) or \
                state['ActiveState'] not in ('inactive', 'failed') or not row['quiescenceVerified'] or \
                (state['ControlGroup'] and members(state['ControlGroup'])) or fragment.is_symlink() or \
                fragment != Path('/run/systemd/system') / name or \
                hashlib.sha256(fragment.read_bytes()).hexdigest() != row['sha256']:
            raise RuntimeError('Exact registered fragment cleanup rejected')
    sockets = {str(root / 'daemon.sock'), str(root / 'proxy.sock')}
    if any(line.split()[-1] in sockets for line in Path('/proc/net/unix').read_text().splitlines()[1:]):
        raise RuntimeError('Runtime root still has active socket owners')
    manager_names = [*names, launch['controlUnit'], launch['recoveryUnit']]
    for name in manager_names:
        reset_failed_terminal_unit(name)
    for row in names.values():
        Path(row['fragment']).unlink()
    command(['/usr/bin/systemctl', 'daemon-reload'])
    shutil.rmtree(root)  # Exact generation, zero containers/mounts; no persistent database or volume.
    if root.exists() or any(Path(row['fragment']).exists() for row in names.values()):
        raise RuntimeError('Physical cleanup incomplete')
    deadline = time.monotonic() + 5
    while True:
        states = [command(['/usr/bin/systemctl', 'show', name, '--property=LoadState', '--value']).strip() for name in manager_names]
        if all(state == 'not-found' for state in states):
            break
        if time.monotonic() >= deadline:
            raise RuntimeError('Registered manager units remain loaded')
        time.sleep(.1)
    return dict(runtimeRootAbsent=True, registeredFragmentsAbsent=True, registeredUnitsAbsent=True, remainingResources=0)


def readback(evidence):
    failure = None
    result = dict(lifecycleProofAccepted=False, sdkStarted=False, nativeAccepted=False)
    try:
        result = validate_readback(evidence)
    except BaseException as error:
        failure = error
        result['firstFailure'] = type(error).__name__
    finally:
        try:
            result.update(physical_cleanup(evidence))
        except BaseException as error:
            result['cleanupFailure'] = type(error).__name__
            result['lifecycleProofAccepted'] = False
            if failure is None:
                failure = error
                result['firstFailure'] = type(error).__name__
    try:
        save(evidence / 'stub-lifecycle-readback.json', result)
    except BaseException as error:
        result['receiptFailure'] = type(error).__name__
        result['lifecycleProofAccepted'] = False
        if failure is None:
            failure = error
            result['firstFailure'] = type(error).__name__
    if failure:
        raise RuntimeError('Proof or physical cleanup failed; first failure retained') from failure
    print(json.dumps(result, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', choices=('workload', 'readback'), required=True)
    parser.add_argument('--context', type=Path)
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    if os.name != 'posix' or os.geteuid() != 0:
        raise RuntimeError('Actual privileged Linux proof lane required')
    if args.role == 'workload':
        workload(args.context, args.receipt)
    else:
        readback(args.evidence)


if __name__ == '__main__':
    main()
