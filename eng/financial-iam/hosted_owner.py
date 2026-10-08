"""Linux hosted lane coordinator. Invoke ONLY inside a pre-registered finite unit.

systemd owns the entire cgroup before any child starts. Recovery acts on exact
unit identity and the private daemon, never PID names, a recursive process-tree
selector, the runner's default Docker socket, or persistent volumes.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import time
import uuid
from datetime import datetime, timezone

from private_docker_proxy import ID, OWNER, Ledger, rpc


def command(arguments, timeout=30, *, capture=True):
    # Every CLI child is already within the pre-registered finite coordinator
    # cgroup. Killing only this exact Popen child on timeout cannot abandon an
    # unowned descendant: the manager still owns and expires the enclosing unit.
    completed = subprocess.run(arguments, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE if capture else None,
                               stderr=subprocess.PIPE if capture else None,
                               timeout=timeout, check=False)
    if capture and (len(completed.stdout) + len(completed.stderr) > 1024 * 1024):
        raise RuntimeError("Bounded manager response exceeded")
    if completed.returncode:
        raise RuntimeError("Owned manager operation failed; output redacted")
    return completed.stdout.decode("utf-8", errors="strict") if capture else ""


def properties(unit):
    result = command(["/usr/bin/systemctl", "show", unit,
                      "--property=Id,FragmentPath,InvocationID,ControlGroup,ActiveState,SubState,Result,MainPID,ExecMainCode,ExecMainStatus,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,MemoryMax,MemorySwapMax,TasksMax,RuntimeMaxUSec,CPUQuotaPerSecUSec,Description,Transient,ExecStart"])
    observed = dict(line.split("=", 1) for line in result.splitlines() if "=" in line)
    # systemd omits service-only properties for slices and timers. Explicitly
    # classify those unit types; a missing service PID/cgroup still fails closed.
    if unit.endswith((".slice", ".timer")):
        if observed.get("MainPID", "0") != "0":
            raise RuntimeError("Non-service unit reported a main process")
        observed.update(MainPID="0", MainProcessApplicable="false")
    else:
        observed["MainPID"]
        observed["MainProcessApplicable"] = "true"
    if unit.endswith(".timer"):
        if observed.get("ControlGroup", ""):
            raise RuntimeError("Timer reported a process cgroup")
        observed.update(ControlGroup="", ControlGroupApplicable="false")
    else:
        observed["ControlGroup"]
        observed["ControlGroupApplicable"] = "true"
    return observed


def members(cgroup):
    root = pathlib.Path("/sys/fs/cgroup") / cgroup.lstrip("/")
    if not root.exists():
        return []
    return sorted({int(pid) for path in root.rglob("cgroup.procs")
                   for pid in path.read_text().splitlines()})


def quote(value):
    if "\n" in value or "\r" in value or "\x00" in value:
        raise ValueError("Invalid unit argument")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def socket_owner(path, pid, expected_birth):
    filesystem = os.stat(path, follow_symlinks=False)
    import stat
    if not stat.S_ISSOCK(filesystem.st_mode) or filesystem.st_uid != 0:
        raise RuntimeError("Private daemon endpoint is not an owned Unix socket")
    before = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    rows = [line.split() for line in pathlib.Path("/proc/net/unix").read_text().splitlines()[1:]]
    matches = [row for row in rows if len(row) == 8 and row[7] == path and row[3:6] == ["00010000", "0001", "01"]]
    if len(matches) != 1:
        raise RuntimeError("Private endpoint kernel identity ambiguous")
    kernel_inode = matches[0][6]
    descriptors = []
    for descriptor in pathlib.Path(f"/proc/{pid}/fd").iterdir():
        try:
            if os.readlink(descriptor) == "socket:[" + kernel_inode + "]":
                descriptors.append(descriptor.name)
        except FileNotFoundError:
            continue
    after = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    if before != expected_birth or after != before or not descriptors:
        raise RuntimeError("Socket is not held by exact daemon generation")
    return {"filesystemDevice": filesystem.st_dev, "filesystemInode": filesystem.st_ino,
            "kernelSocketInode": kernel_inode, "daemonDescriptors": sorted(descriptors)}


class OwnedUnits:
    def __init__(self, run, receipt):
        self.run, self.receipt = run, receipt
        self.units, self.failures = {}, []

    def save(self):
        temporary = self.receipt.with_suffix(".next")
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump({"schemaVersion": 1, "run": self.run, "units": self.units,
                       "failures": self.failures, "nativeQualified": False}, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.receipt)

    def register(self, name, content):
        path = pathlib.Path("/run/systemd/system") / name
        if path.exists() or name in self.units:
            raise RuntimeError("Refuse existing manager resource")
        with path.open("x", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        self.units[name] = {"fragment": str(path), "sha256": hashlib.sha256(content.encode()).hexdigest(),
                            "dispatchAttempted": False, "invocationId": None, "quiescenceVerified": False}
        self.save()  # Registered evidence before manager dispatch, including failed starts.
        command(["/usr/bin/systemctl", "daemon-reload"])

    def identity(self, name):
        row = self.units[name]
        if hashlib.sha256(pathlib.Path(row["fragment"]).read_bytes()).hexdigest() != row["sha256"]:
            raise RuntimeError("Owned unit fragment changed")
        observed = properties(name)
        if observed["Id"] != name or observed["FragmentPath"] != row["fragment"]:
            raise RuntimeError("Owned unit identity changed")
        if row["invocationId"] and observed["InvocationID"] and observed["InvocationID"] != row["invocationId"]:
            raise RuntimeError("Unit invocation changed")
        if row["dispatchAttempted"] and not row["invocationId"] and observed["InvocationID"]:
            row["invocationId"] = observed["InvocationID"]
        pid = int(observed["MainPID"])
        if pid > 0 and "mainProcess" not in row:
            stat_path = pathlib.Path(f"/proc/{pid}/stat")
            before = stat_path.read_text().rsplit(")", 1)[1].split()[19]
            executable = os.readlink(f"/proc/{pid}/exe")
            actual_cgroup = pathlib.Path(f"/proc/{pid}/cgroup").read_text().strip()
            after = stat_path.read_text().rsplit(")", 1)[1].split()[19]
            if before != after or actual_cgroup != "0::" + observed["ControlGroup"]:
                raise RuntimeError("Owned main process identity changed")
            row["mainProcess"] = {"pid": pid, "startTicks": before, "executable": executable,
                                  "cgroup": observed["ControlGroup"]}
        return observed

    def start(self, name):
        row = self.units[name]
        self.identity(name)
        row["dispatchAttempted"] = True
        self.save()
        try:
            command(["/usr/bin/systemctl", "start", name])
        finally:
            observed = self.identity(name)
            row["invocationId"] = observed["InvocationID"] or None
            row["cgroup"] = observed["ControlGroup"]
            self.save()

    def settle(self, name, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            observed = self.identity(name)
            if observed["ActiveState"] in ("inactive", "failed"):
                if not self.units[name]["invocationId"] or int(observed["ExecMainStartTimestampMonotonic"]) <= 0 or int(observed["ExecMainExitTimestampMonotonic"]) < int(observed["ExecMainStartTimestampMonotonic"]):
                    raise RuntimeError("No actual native invocation/exit proof")
                if observed["ControlGroup"] and members(observed["ControlGroup"]):
                    raise RuntimeError("Manager exit left live owned descendants")
                self.units[name].update(quiescenceVerified=True, result=observed["Result"],
                                        execCode=observed["ExecMainCode"], exitCode=observed["ExecMainStatus"])
                self.save()
                if observed["Result"] != "success" or observed["ExecMainStatus"] != "0":
                    raise RuntimeError("Owned phase failed")
                return
            time.sleep(0.25)
        raise TimeoutError("Owned phase deadline")

    def stop(self, name):
        row = self.units[name]
        observed = self.identity(name)
        cgroup = observed["ControlGroup"] or row.get("cgroup", "")
        # systemd stop sends TERM, waits TimeoutStopSec then KILL to this exact
        # registered unit cgroup. No process-tree enumeration is used for killing.
        command(["/usr/bin/systemctl", "stop", name], timeout=50)
        observed = self.identity(name)
        if observed["ActiveState"] not in ("inactive", "failed") or (cgroup and members(cgroup)):
            raise RuntimeError("Owned unit quiescence unresolved")
        row["quiescenceVerified"] = True
        self.save()


def service(description, argv, *, parent=None, memory="768M", runtime=2400, environment=None, log=None):
    text = "[Unit]\nDescription=" + description + "\n[Service]\nType=exec\nRestart=no\n"
    text += "ExecStart=" + " ".join(quote(argument) for argument in argv) + "\n"
    text += f"MemoryMax={memory}\nMemorySwapMax=0\nCPUQuota=100%\nTasksMax=512\nRuntimeMaxSec={runtime}\nTimeoutStopSec=30\nKillMode=control-group\nSendSIGKILL=yes\nLimitCORE=0\nLimitFSIZE=268435456\n"
    if parent:
        text += "Slice=" + parent + "\n"
    for key, value in (environment or {}).items():
        text += "Environment=" + quote(key + "=" + value) + "\n"
    if log:
        text += "StandardOutput=append:" + str(log) + "\nStandardError=append:" + str(log) + "\n"
    return text


def recover_containers(daemon, ledger_path, run, parent, cgroup):
    status, found = rpc(daemon, "GET", "/containers/json?all=1")
    if status != 200 or not isinstance(found, list):
        raise RuntimeError("Private daemon inventory unavailable")
    ledger = Ledger(daemon, run, parent, cgroup, str(ledger_path))
    if ledger_path.exists():
        previous = json.loads(ledger_path.read_text())
        if previous["run"] != run or previous["owner"] != OWNER:
            raise RuntimeError("Recovery ledger mismatch")
        ledger.rows, ledger.failures = previous["containers"], previous["failures"]
        ledger.execs = previous.get("execs", {})
    errors = []
    for item in found:
        identifier = item.get("Id", "")
        try:
            if not ID.fullmatch(identifier):
                raise RuntimeError("Recovery requires full ID")
            document = ledger.inspect(identifier)
            ledger.write()
            if document["State"].get("Running"):
                status, _ = rpc(daemon, "POST", "/containers/" + identifier + "/stop?t=15")
                if status not in (204, 304):
                    raise RuntimeError("Owned graceful stop failed")
                document = ledger.inspect(identifier)
                if document["State"].get("Running"):
                    raise RuntimeError("Container still running")
            status, _ = rpc(daemon, "DELETE", "/containers/" + identifier + "?force=false&v=false")
            if status not in (204, 404):
                raise RuntimeError("Owned removal failed")
            status, _ = rpc(daemon, "GET", "/containers/" + identifier + "/json")
            if status != 404:
                raise RuntimeError("Only 404 proves container absence")
            ledger.rows[identifier]["absenceVerified"] = True
            ledger.write()
        except Exception as error:
            errors.append(type(error).__name__)
    status, final = rpc(daemon, "GET", "/containers/json?all=1")
    if status != 200 or final:
        errors.append("PrivateInventoryNotEmpty")
    if errors:
        raise RuntimeError("Independent container recovery failures: " + ",".join(errors))
    ledger.final_inventory_empty = True
    ledger.write()


def stop_expiry_owners(owner, names, failures):
    """Backend RPC must not race an independently running expiry controller."""
    quiet = True
    for name in names:
        if name in owner.units:
            try:
                owner.stop(name)
            except Exception as error:
                quiet = False
                failures.append("ExpiryOwnerQuiescence:" + type(error).__name__)
    return quiet


def write_coordinator_receipt(path, owner, writer):
    """Distinct writer-owned temporary paths; never adopt/remove another file."""
    if writer not in ("coordinator", "recovery"):
        raise ValueError("Unknown coordinator receipt writer")
    for attempt in range(3):
        temporary = path.with_name(path.name + "." + writer + "." + uuid.uuid4().hex + ".next")
        try:
            with temporary.open("x", encoding="utf-8") as stream:
                json.dump(owner, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            return
        except OSError as error:
            # Keep this writer's interrupted artifact as recovery evidence; no
            # foreign/shared .next file is opened, reset, adopted or removed.
            owner.setdefault("receiptWriteFailures", []).append({"writer": writer,
                "attempt": attempt + 1, "error": type(error).__name__, "temporary": str(temporary)})
            if attempt < 2:
                time.sleep(0.05)
    raise RuntimeError("Coordinator receipt write failed after bounded retries; retain owner")


def retain_coordinator_identity(args, observed):
    path = pathlib.Path(args.receipt).parent / "coordinator-owner.json"
    owner = json.loads(path.read_text())
    pid = os.getpid()
    birth = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    executable = os.readlink(f"/proc/{pid}/exe")
    argv = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
    if owner["unit"] != args.coordinator_unit or owner["description"] != observed["Description"] or \
            owner["cgroup"] != observed["ControlGroup"] or owner["executable"] != executable or \
            owner["arguments"] != argv[1:] or owner["dispatchAttempted"] is not True:
        raise RuntimeError("Coordinator predispatch fence differs")
    owner.update(invocationId=observed["InvocationID"], execStart=observed["ExecStart"],
        mainProcess={"pid": pid, "startTicks": birth, "executable": executable, "cgroup": observed["ControlGroup"]})
    write_coordinator_receipt(path, owner, "coordinator")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--checkouts", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--coordinator-unit", required=True)
    parser.add_argument("--lane", choices=("auth", "accounting", "procurement", "order"), required=True)
    parser.add_argument("--stage", choices=("full", "build", "proof"), default="full")
    for option in ("commerce-transport", "commerce-driver", "admission-verifier"):
        parser.add_argument("--" + option)
    args = parser.parse_args()
    if args.stage == "proof" and (args.lane != "auth" or any((args.commerce_transport, args.commerce_driver, args.admission_verifier))):
        raise ValueError("Stub proof accepts Auth without producer or SDK inputs")
    if args.stage == "full" and (args.lane not in ("auth", "accounting") or any((args.commerce_transport, args.commerce_driver, args.admission_verifier))):
        raise ValueError("Full route must preserve existing Auth/Accounting inputs")
    if args.stage == "build":
        if args.lane not in ("accounting", "procurement", "order"):
            raise ValueError("BUILD route requires a fixed Commerce profile")
        for name in ("commerce_transport", "commerce_driver", "admission_verifier"):
            value = getattr(args, name)
            if not value or not pathlib.Path(value).is_absolute():
                raise ValueError("BUILD route requires explicit absolute producer paths")
    run = args.coordinator_unit.removesuffix("-control.service")
    if not re.fullmatch(r"auth-financial-[0-9]+-[0-9]+-[a-f0-9]{12}", run) or os.geteuid() != 0:
        raise RuntimeError("Pre-registered hosted coordinator required")
    control = properties(args.coordinator_unit)
    current = pathlib.Path("/proc/self/cgroup").read_text().strip()
    if not control["InvocationID"] or current != "0::" + control["ControlGroup"] or int(control["MainPID"]) != os.getpid():
        raise RuntimeError("Exact finite coordinator invocation required")
    if control["MemoryMax"] != str(512 * 1024 ** 2) or control["MemorySwapMax"] != "0" or control["RuntimeMaxUSec"] not in ("45min", "2700s") or control["CPUQuotaPerSecUSec"] != "1s":
        raise RuntimeError("Actual coordinator capacity/lifetime differs")
    # Retain the actual allocating generation BEFORE even creating resource
    # receipt directories. Independent recovery must quiesce this exact owner.
    retain_coordinator_identity(args, control)
    # Identity of the coordinator itself is part of the outer workflow receipt;
    # it cannot retrospectively create or prove its own finite allocation.
    source = pathlib.Path(args.source).resolve(strict=True)
    root = pathlib.Path("/var/tmp") / run
    if root.exists():
        raise RuntimeError("Fresh isolated runtime root required")
    root.mkdir(mode=0o700)
    receipts = pathlib.Path(args.receipt).resolve()
    receipts.mkdir(parents=True, exist_ok=False)
    if args.stage == "proof":
        birth = root.stat()
        (receipts / "stub-root.json").write_text(json.dumps({"run": run, "device": birth.st_dev, "inode": birth.st_ino}))
    owned = OwnedUnits(run, receipts / "units.json")
    # A slice name without dashes is a direct root child, not an implicitly
    # nested systemd slice hierarchy. Still read the actual manager cgroup.
    parent = "authfinancial" + run.replace("auth-financial-", "").replace("-", "") + ".slice"
    daemon, proxy, sdk = (run + suffix + ".service" for suffix in ("-daemon", "-proxy", "-sdk"))
    timer, guard = run + "-expiry.timer", run + "-expiry.service"
    daemon_socket, proxy_socket = str(root / "daemon.sock"), str(root / "proxy.sock")
    cgroup = None
    bridge = "af" + run[-12:]
    bridge_identity = None
    failures = []
    try:
        owned.register(parent, "[Unit]\nDescription=Owned financial qualification aggregate\n[Slice]\nMemoryMax=6G\nMemorySwapMax=0\nCPUQuota=200%\nTasksMax=1536\n")
        owned.start(parent)
        cgroup = owned.identity(parent)["ControlGroup"]
        if not cgroup or members(cgroup):
            raise RuntimeError("Fresh owned aggregate slice required")
        aggregate = pathlib.Path("/sys/fs/cgroup") / cgroup.lstrip("/")
        generation = aggregate.stat()
        lease_expiry = time.time() + 2400
        if not (aggregate / "cgroup.kill").exists():
            raise RuntimeError("Exact aggregate-job expiry controller unavailable")
        (receipts / "aggregate.json").write_text(json.dumps({"run": run, "unit": parent,
            "cgroup": cgroup, "device": generation.st_dev, "inode": generation.st_ino,
            "expiresAtUnix": lease_expiry}), encoding="utf-8")
        owned.register(guard, service("Independent owned aggregate expiry", ["/usr/bin/python3", "-B",
            str(source / "expiry_guard.py"), "--run", run, "--receipt", str(receipts)],
            memory="128M", runtime=180, log=receipts / "expiry.log"))
        owned.register(timer, "[Unit]\nDescription=Finite financial aggregate lease\n[Timer]\nOnActiveSec=2400\nAccuracySec=1\nUnit=" + guard + "\n")
        owned.start(timer)
        if owned.identity(timer)["ActiveState"] != "active":
            raise RuntimeError("Independent aggregate lease did not arm")
        routes = json.loads(command(["/usr/sbin/ip", "-json", "route", "show", "table", "all"]))
        import ipaddress
        selected = None
        for octet in range(200, 250):
            candidate = ipaddress.ip_network(f"172.31.{octet}.0/24")
            occupied = []
            for route in routes:
                destination = route.get("dst", "default")
                if destination != "default":
                    occupied.append(ipaddress.ip_network(destination, strict=False))
            if not any(candidate.overlaps(network) for network in occupied if network.version == 4):
                selected = candidate
                break
        if selected is None:
            raise RuntimeError("No isolated bridge address available")
        if any(row["ifname"] == bridge for row in json.loads(command(["/usr/sbin/ip", "-json", "link", "show"]))):
            raise RuntimeError("Private bridge identity already exists")
        mac = "02:" + ":".join(run[-10:][index:index+2] for index in range(0, 10, 2))
        bridge_receipt = {"name": bridge, "mac": mac, "subnet": str(selected), "dispatchAttempted": True,
                          "ifindex": None, "absenceVerified": False}
        # Retain intended identity before kernel allocation. An ambiguous failure
        # is never permission to delete an arbitrary same-name interface.
        (receipts / "bridge.json").write_text(json.dumps(bridge_receipt), encoding="utf-8")
        command(["/usr/sbin/ip", "link", "add", "name", bridge, "address", mac, "type", "bridge"])
        observed = json.loads(command(["/usr/sbin/ip", "-json", "link", "show", "dev", bridge]))
        if len(observed) != 1 or observed[0]["address"] != mac:
            raise RuntimeError("Private bridge creation identity uncertain")
        bridge_identity = observed[0]["ifindex"]
        bridge_receipt["ifindex"] = bridge_identity
        (receipts / "bridge.json").write_text(json.dumps(bridge_receipt), encoding="utf-8")
        address = str(selected.network_address + 1) + "/24"
        command(["/usr/sbin/ip", "address", "add", address, "dev", bridge])
        command(["/usr/sbin/ip", "link", "set", bridge, "up"])
        config_path = root / "daemon.json"
        with config_path.open("x", encoding="utf-8") as stream:
            json.dump({"cgroup-parent": parent}, stream, sort_keys=True)
            stream.write("\n")
        os.chmod(config_path, 0o600)
        owned.register(daemon, service("Private financial qualification daemon", ["/usr/bin/dockerd",
            "--config-file=" + str(config_path),
            "--host=unix://" + daemon_socket, "--data-root=" + str(root / "docker-data"),
            "--exec-root=" + str(root / "docker-exec"), "--pidfile=" + str(root / "daemon.pid"),
            "--exec-opt=native.cgroupdriver=systemd",
            "--bridge=" + bridge, "--bip=" + address, "--iptables=false", "--ip6tables=false",
            "--ip-forward=false", "--ip-masq=false", "--userland-proxy=true", "--ip=127.0.0.1"],
            parent=parent, memory="1G", runtime=2400, log=receipts / "daemon.log"))
        owned.start(daemon)
        deadline = time.monotonic() + 60
        while not pathlib.Path(daemon_socket).exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("Private daemon startup")
            time.sleep(0.25)
        status, info = rpc(daemon_socket, "GET", "/info")
        if status != 200 or info.get("DockerRootDir") != str(root / "docker-data") or info.get("CgroupDriver") != "systemd" or info.get("CgroupVersion") != "2":
            raise RuntimeError("Private daemon identity/cgroup admission failed")
        if not info.get("MemoryLimit") or not info.get("CpuCfsQuota"):
            raise RuntimeError("Kernel container resource controllers unavailable")
        aggregate = pathlib.Path("/sys/fs/cgroup") / cgroup.lstrip("/")
        if aggregate.joinpath("memory.max").read_text().strip() != str(6 * 1024 ** 3) or aggregate.joinpath("memory.swap.max").read_text().strip() != "0":
            raise RuntimeError("Actual aggregate memory admission failed")
        quota, period = aggregate.joinpath("cpu.max").read_text().split()
        if quota == "max" or int(quota) > 2 * int(period):
            raise RuntimeError("Actual aggregate CPU admission failed")
        daemon_state = owned.identity(daemon)
        daemon_pid = int(daemon_state["MainPID"])
        if daemon_pid <= 0:
            raise RuntimeError("Private daemon process absent")
        daemon_birth = pathlib.Path(f"/proc/{daemon_pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
        context = {"schemaVersion": 1, "run": run, "socket": daemon_socket,
                   "daemonPid": daemon_pid, "daemonStartTicks": daemon_birth,
                   "daemonInvocationId": daemon_state["InvocationID"], "containerCgroup": cgroup,
                   "cgroupParent": parent, "expiresAtUnix": int(time.time()) + 2400,
                   "dataRoot": str(root / "docker-data"), "execRoot": str(root / "docker-exec")}
        context["socketOwnership"] = socket_owner(daemon_socket, daemon_pid, daemon_birth)
        actual_executable = os.readlink(f"/proc/{daemon_pid}/exe")
        actual_arguments = pathlib.Path(f"/proc/{daemon_pid}/cmdline").read_bytes().split(b"\0")
        if pathlib.Path(actual_executable).resolve() != pathlib.Path("/usr/bin/dockerd").resolve() or \
                ("--config-file=" + str(config_path)).encode() not in actual_arguments or \
                ("--data-root=" + str(root / "docker-data")).encode() not in actual_arguments or \
                ("--host=unix://" + daemon_socket).encode() not in actual_arguments:
            raise RuntimeError("Daemon actual execution configuration differs")
        if json.loads(config_path.read_text()) != {"cgroup-parent": parent} or any(value.startswith(b"--cgroup-parent") for value in actual_arguments):
            raise RuntimeError("Immutable default container parent differs or is overridden")
        actual_daemon_cgroup = pathlib.Path(f"/proc/{daemon_pid}/cgroup").read_text().strip()
        if actual_daemon_cgroup != "0::" + daemon_state["ControlGroup"] or not daemon_state["ControlGroup"].startswith(cgroup + "/"):
            raise RuntimeError("Daemon escaped owned aggregate")
        status, initial = rpc(daemon_socket, "GET", "/containers/json?all=1")
        if status != 200 or initial != []:
            raise RuntimeError("Private daemon was not initially empty")
        context.update(daemonExecutable=actual_executable,
                       daemonConfigPath=str(config_path), daemonConfigSha256=hashlib.sha256(config_path.read_bytes()).hexdigest(),
                       daemonCmdlineSha256=hashlib.sha256(pathlib.Path(f"/proc/{daemon_pid}/cmdline").read_bytes()).hexdigest(),
                       immutableUnitSha256=owned.units[daemon]["sha256"], effectiveCgroupDriver=info["CgroupDriver"],
                       effectiveCgroupVersion=info["CgroupVersion"], initialContainers=0,
                       defaultParentEvidence="Exact immutable config, unit and daemon cmdline; Docker /info exposes no CgroupParent field")
        (receipts / "native-context.json").write_text(json.dumps(context), encoding="utf-8")
        owned.register(proxy, service("Private owned container admission", ["/usr/bin/python3",
            str(source / "private_docker_proxy.py"), "--daemon", daemon_socket, "--socket", proxy_socket,
            "--run", run, "--parent", parent, "--cgroup", cgroup, "--receipt", str(receipts / "containers.json"),
            "--sdk-cgroup", cgroup + "/" + sdk],
            parent=parent, memory="256M", runtime=2400,
            environment={"PYTHONDONTWRITEBYTECODE": "1"}, log=receipts / "proxy.log"))
        owned.start(proxy)
        deadline = time.monotonic() + 30
        while not pathlib.Path(proxy_socket).exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("Private admission startup")
            time.sleep(0.25)
        proxy_state = owned.identity(proxy)
        proxy_pid = int(proxy_state["MainPID"])
        if proxy_pid <= 0:
            raise RuntimeError("Admission proxy process absent")
        proxy_birth = pathlib.Path(f"/proc/{proxy_pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
        proxy_identity = socket_owner(proxy_socket, proxy_pid, proxy_birth)
        daemon_identity = socket_owner(daemon_socket, daemon_pid, daemon_birth)
        context.update(schemaVersion=3, owner=run, expiresUtc=datetime.fromtimestamp(lease_expiry, timezone.utc).isoformat(),
            sdkCgroup=cgroup + "/" + sdk, dockerHost="unix://" + proxy_socket, dockerDaemonHost="unix://" + daemon_socket,
            dockerDaemonPid=daemon_pid, dockerDaemonStartTicks=daemon_birth, dockerDaemonConfig=str(config_path),
            dockerDaemonConfigSha256=hashlib.sha256(config_path.read_bytes()).hexdigest(),
            dockerDaemonCmdlineSha256=hashlib.sha256(pathlib.Path(f"/proc/{daemon_pid}/cmdline").read_bytes()).hexdigest(),
            dockerDaemonCgroup=daemon_state["ControlGroup"], dockerCgroupParent=parent,
            dockerProxyPid=proxy_pid, dockerProxyStartTicks=proxy_birth, dockerProxyExecutable=os.readlink(f"/proc/{proxy_pid}/exe"),
            dockerProxyCgroup=proxy_state["ControlGroup"], dockerProxyScript=str(source / "private_docker_proxy.py"),
            dockerProxyScriptSha256=hashlib.sha256((source / "private_docker_proxy.py").read_bytes()).hexdigest(),
            dockerProxyCmdlineSha256=hashlib.sha256(pathlib.Path(f"/proc/{proxy_pid}/cmdline").read_bytes()).hexdigest(),
            dockerProxySocket={"device": proxy_identity["filesystemDevice"], "inode": proxy_identity["filesystemInode"], "kernelInode": proxy_identity["kernelSocketInode"]},
            dockerDaemonSocket={"device": daemon_identity["filesystemDevice"], "inode": daemon_identity["filesystemInode"], "kernelInode": daemon_identity["kernelSocketInode"]})
        (receipts / "native-context.json").write_text(json.dumps(context), encoding="utf-8")
        if args.stage == "proof":
            status, body = rpc(proxy_socket, "GET", "/info")
            if status != 503 or body != {"message": "Owned Docker admission failed"}:
                raise RuntimeError("Foreign coordinator peer was not rejected")
            (receipts / "stub-foreign-peer.json").write_text(json.dumps({"run": run, "rejected": True,
                "coordinatorPid": os.getpid(), "coordinatorCgroup": current, "status": status}))
        environment = {"DOCKER_HOST": "unix://" + proxy_socket, "DOCKER_CONTEXT": "",
            "DOCKER_TLS_VERIFY": "", "DOCKER_CERT_PATH": "", "TESTCONTAINERS_RYUK_DISABLED": "true",
            "GITHUB_ACTIONS": "false", "FINANCIAL_OWNED_CGROUP": cgroup,
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1", "PYTHONDONTWRITEBYTECODE": "1",
            "GITHUB_SHA": os.environ.get("GITHUB_SHA", ""), "DOTNET_CLI_HOME": str(root / "dotnet-home"),
            "DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER": "1", "MSBUILDDISABLENODEREUSE": "1",
            "BuildInParallel": "false", "UseSharedCompilation": "false", "DOTNET_PROCESSOR_COUNT": "1"}
        if args.stage == "build":
            environment["DOTNET_CLI_UI_LANGUAGE"] = "en"
        environment["MALIEV_ACCOUNTING_NATIVE_CONTEXT"] = str(receipts / "native-context.json")
        sdk_command = ["/usr/bin/pwsh", "-NoProfile", "-File", str(source / "Invoke-FinancialIamQualification.ps1"),
                       "-SourceCheckouts", str(pathlib.Path(args.checkouts).resolve(strict=True)),
                       "-Destination", str(root / "materialized"), "-Receipts", str(receipts), "-Lane", args.lane]
        if args.stage == "build":
            sdk_command = ["/usr/bin/python3", "-B", str(source / "commerce_build_route.py"),
                "--lane", args.lane, "--transport", args.commerce_transport,
                "--driver", args.commerce_driver, "--admission-verifier", args.admission_verifier,
                "--context", str(receipts / "native-context.json"), "--checkouts", str(pathlib.Path(args.checkouts).resolve(strict=True)),
                "--destination", str(root / "commerce-materialized"), "--receipts", str(receipts)]
        if args.stage == "proof":
            sdk_command = ["/usr/bin/python3", "-B", str(source / "finite_stub_proof.py"),
                "--role", "workload", "--context", str(receipts / "native-context.json"),
                "--receipt", str(receipts / "stub-proof.json")]
        owned.register(sdk, service("Exact isolated native qualification", sdk_command, parent=parent,
            memory="128M" if args.stage == "proof" else "3G",
            runtime=180 if args.stage == "proof" else 2100, environment=environment, log=receipts / "sdk.log"))
        owned.start(sdk)
        owned.settle(sdk, 2130)
    except Exception as error:
        failures.append(type(error).__name__ + ":" + str(error))
    finally:
        sdk_quiet = sdk not in owned.units
        proxy_quiet = proxy not in owned.units
        daemon_quiet = daemon not in owned.units
        containers_absent = daemon not in owned.units
        expiry_quiet = False
        if sdk in owned.units:
            try:
                owned.stop(sdk)
                sdk_quiet = True
            except Exception as error:
                failures.append("SDKQuiescence:" + type(error).__name__)
        if sdk_quiet:
            expiry_quiet = stop_expiry_owners(owned, (timer, guard), failures)
        if sdk_quiet and expiry_quiet:
            if proxy in owned.units:
                try:
                    owned.stop(proxy)
                    proxy_quiet = True
                except Exception as error:
                    failures.append("ProxyQuiescence:" + type(error).__name__)
            if daemon in owned.units:
                try:
                    if not proxy_quiet:
                        raise RuntimeError("Proxy readers must be quiescent before backend recovery")
                    recover_containers(daemon_socket, receipts / "containers.json", run, parent, cgroup)
                    containers_absent = True
                except Exception as error:
                    failures.append("ContainerRecovery:" + type(error).__name__)
                # Stop only this private owned daemon; do not remove volume data.
                try:
                    owned.stop(daemon)
                    daemon_quiet = True
                except Exception as error:
                    failures.append("DaemonQuiescence:" + type(error).__name__)
        if bridge_identity is not None and expiry_quiet and sdk_quiet and proxy_quiet and daemon_quiet and containers_absent:
            try:
                observed = json.loads(command(["/usr/sbin/ip", "-json", "link", "show", "dev", bridge]))
                if len(observed) != 1 or observed[0]["ifindex"] != bridge_identity or observed[0]["address"] != mac:
                    raise RuntimeError("Bridge reuse/identity mismatch")
                if any(row.get("master") == bridge for row in json.loads(command(["/usr/sbin/ip", "-json", "link", "show"]))):
                    raise RuntimeError("Bridge retains active interfaces")
                command(["/usr/sbin/ip", "link", "delete", "dev", bridge])
                if any(row["ifname"] == bridge for row in json.loads(command(["/usr/sbin/ip", "-json", "link", "show"]))):
                    raise RuntimeError("Bridge absence not verified")
                bridge_receipt["absenceVerified"] = True
                (receipts / "bridge.json").write_text(json.dumps(bridge_receipt), encoding="utf-8")
            except Exception as error:
                failures.append("BridgeQuiescence:" + type(error).__name__)
        if parent in owned.units:
            try:
                if not expiry_quiet:
                    raise RuntimeError("Expiry controller remains unresolved")
                if cgroup and members(cgroup):
                    raise RuntimeError("Owned slice retains live resources")
                owned.stop(parent)
            except Exception as error:
                failures.append("SliceQuiescence:" + type(error).__name__)
        owned.failures = failures
        container_receipt = receipts / "containers.json"
        if container_receipt.exists() and json.loads(container_receipt.read_text()).get("failures"):
            owned.failures.append("PrivateDockerAdmissionFailureRetained")
        if (receipts / "expiry.json").exists():
            owned.failures.append("IndependentAggregateLeaseExpired")
        owned.save()
    if failures:
        raise RuntimeError("Qualification not accepted; retained owned failure receipt")


if __name__ == "__main__":
    main()
