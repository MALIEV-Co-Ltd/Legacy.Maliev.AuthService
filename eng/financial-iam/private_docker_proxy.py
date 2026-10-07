"""Private-daemon admission proxy. Never connects to the machine's Docker endpoint.

Launched only by the owned capped coordinator unit. The underlying daemon has a
separate private root and an owned capped default cgroup parent. This proxy is
not a general Docker proxy: unsupported upgrades, exec and volume APIs fail
closed. All accepted creates are disposable, loopback-only and pre-birth capped.
"""
import argparse
import hashlib
import http.client
import json
import os
import re
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn, UnixStreamServer
from urllib.parse import urlsplit, parse_qs

MAX_BODY = 2 * 1024 * 1024
CHUNK = 64 * 1024
OWNER = "auth-financial-hosted-qualification"
ID = re.compile(r"[a-f0-9]{64}\Z")


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=20):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.owned_socket = self.sock
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def rpc(path, method, target, body=None):
    connection = UnixConnection(path)
    response = None
    try:
        payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        connection.request(method, target, payload, {"Content-Type": "application/json"})
        response = connection.getresponse()
        raw = bytearray()
        deadline = time.monotonic() + 20
        while True:
            if response.isclosed() or response.length == 0:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Private Docker RPC deadline")
            connection.owned_socket.settimeout(min(remaining, 2))
            chunk = response.read1(min(CHUNK, MAX_BODY + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > MAX_BODY:
                raise RuntimeError("Bounded private Docker response exceeded")
        return response.status, json.loads(raw) if raw else None
    finally:
        if response:
            response.close()
        connection.close()


def create_plan(document, run, parent):
    """Return a detached plan, admitting only this lane's ephemeral Linux workloads."""
    result = json.loads(json.dumps(document))
    if not isinstance(result, dict) or not isinstance(result.get("Image"), str):
        raise ValueError("Container image required")
    if result.get("HostName") or result.get("Domainname"):
        raise ValueError("Unexpected host identity override")
    host = result.setdefault("HostConfig", {})
    if not isinstance(host, dict):
        raise ValueError("Invalid host configuration")
    if host.get("CgroupParent") not in (None, "", parent):
        raise ValueError("Foreign cgroup parent")
    forbidden = ("Binds", "Mounts", "VolumesFrom", "Devices", "DeviceRequests", "CapAdd",
                 "SecurityOpt", "ExtraHosts", "Links", "CgroupnsMode", "PidMode", "IpcMode",
                 "UTSMode", "UsernsMode")
    if any(host.get(key) for key in forbidden) or host.get("Privileged"):
        raise ValueError("Unexpected mount or host privilege")
    if host.get("NetworkMode") not in (None, "", "default", "bridge"):
        raise ValueError("Foreign network mode")
    if host.get("AutoRemove"):
        raise ValueError("Automatic removal destroys ownership evidence")
    if result.get("Volumes"):
        # Image-declared anonymous volumes are inspected after creation and retained
        # until exact container removal; this lane does not remove any volumes.
        raise ValueError("Explicit volumes are not admitted")
    labels = result.setdefault("Labels", {})
    if not isinstance(labels, dict):
        raise ValueError("Invalid labels")
    for key, value in (("codex.hosted-owner", OWNER), ("codex.hosted-run", run)):
        if key in labels and labels[key] != value:
            raise ValueError("Foreign ownership label")
        labels[key] = value
    memory = host.get("Memory", 0)
    cpus = host.get("NanoCpus", 0)
    if not isinstance(memory, int) or memory < 0 or memory > 768 * 1024 * 1024:
        raise ValueError("Unexpected memory allocation")
    if not isinstance(cpus, int) or cpus < 0 or cpus > 1_000_000_000:
        raise ValueError("Unexpected CPU allocation")
    host["Memory"] = memory or 768 * 1024 * 1024
    host["MemorySwap"] = host["Memory"]
    host["NanoCpus"] = cpus or 1_000_000_000
    host["CgroupParent"] = parent
    host["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
    host["AutoRemove"] = False
    host["PublishAllPorts"] = False
    ports = host.setdefault("PortBindings", {})
    for bindings in ports.values():
        if not isinstance(bindings, list):
            raise ValueError("Invalid port binding")
        for binding in bindings:
            if binding.get("HostIp") not in (None, "", "0.0.0.0", "127.0.0.1"):
                raise ValueError("Non-loopback port override")
            binding["HostIp"] = "127.0.0.1"
    return result


class Ledger:
    def __init__(self, daemon, run, parent, cgroup, receipt):
        self.daemon, self.run, self.parent, self.cgroup, self.receipt = daemon, run, parent, cgroup, receipt
        self.lock = threading.Lock()
        self.rows = {}
        self.failures = []
        self.final_inventory_empty = False
        self.execs = {}

    def write(self):
        with self.lock:
            document = {"schemaVersion": 1, "owner": OWNER, "run": self.run,
                        "cgroupParent": self.parent, "containers": self.rows,
                        "failures": self.failures, "finalInventoryEmpty": self.final_inventory_empty,
                        "execs": self.execs,
                        "nativeQualified": False}
            temporary = self.receipt + ".next"
            with open(temporary, "x", encoding="utf-8") as stream:
                json.dump(document, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.receipt)

    def inspect(self, identifier):
        if not ID.fullmatch(identifier):
            raise RuntimeError("Full container identity required")
        status, document = rpc(self.daemon, "GET", "/containers/" + identifier + "/json")
        if status != 200:
            raise RuntimeError("Private container inspection failed")
        if document.get("Id") != identifier:
            raise RuntimeError("Container identity mismatch")
        config, host = document["Config"], document["HostConfig"]
        labels = config.get("Labels", {})
        if labels.get("codex.hosted-owner") != OWNER or labels.get("codex.hosted-run") != self.run:
            raise RuntimeError("Container ownership mismatch")
        if host.get("CgroupParent") != self.parent or not (0 < host.get("Memory", 0) <= 768 * 1024 * 1024):
            raise RuntimeError("Container pre-birth bounds mismatch")
        if not (0 < host.get("NanoCpus", 0) <= 1_000_000_000):
            raise RuntimeError("Container CPU bounds mismatch")
        if host.get("MemorySwap") != host["Memory"] or host.get("RestartPolicy", {}).get("Name") != "no":
            raise RuntimeError("Container swap/restart bounds mismatch")
        if host.get("Binds") or host.get("Privileged") or host.get("VolumesFrom"):
            raise RuntimeError("Unexpected persistent/host resource")
        for bindings in (host.get("PortBindings") or {}).values():
            if any(binding.get("HostIp") != "127.0.0.1" for binding in bindings):
                raise RuntimeError("Non-loopback binding")
        row = {"id": identifier, "created": document["Created"], "imageId": document["Image"],
               "labels": labels, "mounts": document.get("Mounts", []),
               "memory": host["Memory"], "nanoCpus": host["NanoCpus"],
               "cgroupParent": host["CgroupParent"], "absenceVerified": False}
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", row["imageId"]):
            raise RuntimeError("Immutable image identity absent")
        for mount in row["mounts"]:
            if mount.get("Type") not in ("volume", "tmpfs"):
                raise RuntimeError("Host/bind mount not admitted")
        with self.lock:
            previous = self.rows.get(identifier)
            if previous and any(previous[key] != row[key] for key in ("id", "created", "imageId", "labels", "mounts")):
                raise RuntimeError("Container generation changed")
            if previous:
                row.update({key: value for key, value in previous.items() if key not in row})
            self.rows[identifier] = row
            self.final_inventory_empty = False
        return document

    def started(self, identifier):
        document = self.inspect(identifier)
        pid = document["State"]["Pid"]
        if not document["State"].get("Running") or not isinstance(pid, int) or pid <= 0:
            raise RuntimeError("Running container init required")
        before = open(f"/proc/{pid}/stat", encoding="utf-8").read().rsplit(")", 1)[1].split()[19]
        cgroups = open(f"/proc/{pid}/cgroup", encoding="utf-8").read().splitlines()
        if len(cgroups) != 1 or not cgroups[0].startswith("0::" + self.cgroup + "/"):
            raise RuntimeError("Container init escaped owned aggregate slice")
        after = open(f"/proc/{pid}/stat", encoding="utf-8").read().rsplit(")", 1)[1].split()[19]
        if before != after:
            raise RuntimeError("Container init process identity changed")
        controller = "/sys/fs/cgroup" + cgroups[0][3:]
        memory = open(controller + "/memory.max", encoding="utf-8").read().strip()
        swap = open(controller + "/memory.swap.max", encoding="utf-8").read().strip()
        quota, period = open(controller + "/cpu.max", encoding="utf-8").read().split()
        if memory == "max" or int(memory) > document["HostConfig"]["Memory"] or swap != "0":
            raise RuntimeError("Actual container kernel memory bound differs")
        if quota == "max" or int(quota) * 1_000_000_000 > document["HostConfig"]["NanoCpus"] * int(period):
            raise RuntimeError("Actual container kernel CPU bound differs")
        with self.lock:
            self.rows[identifier].update(initPid=pid, initStartTicks=before, actualCgroup=cgroups[0][3:],
                                         startedAt=document["State"]["StartedAt"], containmentVerified=True,
                                         kernelMemoryMax=memory, kernelSwapMax=swap, kernelCpuMax=quota + " " + period)
        self.write()


class Server(ThreadingMixIn, UnixStreamServer):
    daemon_threads = False
    block_on_close = True
    max_threads = threading.BoundedSemaphore(16)

    def process_request(self, request, address):
        self.max_threads.acquire()
        try:
            super().process_request(request, address)
        except BaseException:
            self.max_threads.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.max_threads.release()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass  # Docker requests can carry environment credentials. Never log bodies/URLs.

    def do_GET(self):
        self.forward()

    def do_POST(self):
        self.forward()

    def do_DELETE(self):
        self.forward()

    def do_PUT(self):
        self.forward()

    def do_HEAD(self):
        self.forward()

    def forward(self):
        connection = None
        response = None
        try:
            self.connection.settimeout(20)
            peer_pid, peer_uid, _ = struct.unpack("3i", self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            peer_cgroup = open(f"/proc/{peer_pid}/cgroup", encoding="utf-8").read().strip()
            if peer_uid != 0 or peer_cgroup != "0::" + self.server.sdk_cgroup:
                raise ValueError("Only the exact owned SDK cgroup may allocate or use containers")
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("Streaming request is unsupported")
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= MAX_BODY:
                raise ValueError("Request too large")
            payload = self.rfile.read(length)
            if len(payload) != length:
                raise ValueError("Incomplete request")
            parsed = urlsplit(self.path)
            if parsed.scheme or parsed.netloc or not parsed.path.startswith("/"):
                raise ValueError("Absolute endpoint forbidden")
            route = re.sub(r"^/v[0-9]+\.[0-9]+", "", parsed.path)
            if route.startswith("/volumes") or route.startswith("/networks"):
                raise ValueError("Unsupported resource allocation")
            create = self.command == "POST" and route == "/containers/create"
            start = re.fullmatch(r"/containers/([a-f0-9]{64})/start", route) if self.command == "POST" else None
            remove = re.fullmatch(r"/containers/([a-f0-9]{64})", route) if self.command == "DELETE" else None
            container = re.fullmatch(r"/containers/([a-f0-9]{64})(?:/(json|start|stop|wait|logs|archive))?", route)
            exec_create = re.fullmatch(r"/containers/([a-f0-9]{64})/exec", route) if self.command == "POST" else None
            exec_use = re.fullmatch(r"/exec/([a-f0-9]{64})/(start|json)", route)
            if self.headers.get("Upgrade") and not (exec_use and exec_use[2] == "start" and self.command == "POST"):
                raise ValueError("Unsupported upgrade")
            image = (route == "/images/create" and self.command == "POST") or (route.startswith("/images/") and route.endswith("/json") and self.command == "GET")
            information = route in ("/_ping", "/version", "/info", "/containers/json", "/images/json") and self.command in ("GET", "HEAD")
            if not (create or container or image or information or exec_create or exec_use):
                raise ValueError("Unsupported Docker API route")
            if exec_create:
                self.server.ledger.started(exec_create[1])
                document = json.loads(payload)
                if document.get("Privileged") or document.get("AttachStdin") or document.get("Tty"):
                    raise ValueError("Interactive/privileged exec is forbidden")
                commands = document.get("Cmd")
                if not isinstance(commands, list) or not 0 < len(commands) <= 32 or any(not isinstance(item, str) for item in commands) or sum(len(item) for item in commands) > 8192:
                    raise ValueError("Unbounded exec command")
            if exec_use:
                with self.server.ledger.lock:
                    exec_row = self.server.ledger.execs.get(exec_use[1])
                if not exec_row:
                    raise ValueError("Unknown exec owner")
                self.server.ledger.started(exec_row["containerId"])
                if exec_use[2] == "start":
                    if self.command != "POST":
                        raise ValueError("Wrong exec start verb")
                    document = json.loads(payload)
                    if document.get("Detach") or document.get("Tty"):
                        raise ValueError("Detached/interactive exec forbidden")
                elif self.command != "GET":
                    raise ValueError("Wrong exec inspection verb")
            if container and self.command != "GET":
                self.server.ledger.inspect(container[1])
            target = self.path
            if remove:
                query = parse_qs(parsed.query, keep_blank_values=True)
                if any(value.lower() not in ("false", "0", "") for value in query.get("v", [])):
                    raise ValueError("Volume removal forbidden")
                document = self.server.ledger.inspect(remove[1])
                if document["State"].get("Running"):
                    status, _ = rpc(self.server.ledger.daemon, "POST", "/containers/" + remove[1] + "/stop?t=15")
                    if status not in (204, 304) or self.server.ledger.inspect(remove[1])["State"].get("Running"):
                        raise RuntimeError("Graceful stop before removal failed")
                target = parsed.path + "?force=false&v=false"
            if create:
                payload = json.dumps(create_plan(json.loads(payload), self.server.ledger.run,
                                                self.server.ledger.parent), separators=(",", ":")).encode()
            connection = UnixConnection(self.server.ledger.daemon)
            headers = {"Content-Type": self.headers.get("Content-Type", "application/json")}
            if self.headers.get("Upgrade"):
                headers.update(Upgrade="tcp", Connection="Upgrade")
            connection.request(self.command, target, payload or None, headers)
            response = connection.getresponse()
            if create or exec_create:
                raw = response.read(MAX_BODY + 1)
                if len(raw) > MAX_BODY:
                    raise RuntimeError("Create response too large")
                if response.status == 201:
                    identifier = json.loads(raw)["Id"]
                    # Receipt before SDK sees success. An inspection/receipt failure
                    # deliberately leaves the private-daemon resource quarantined.
                    if create:
                        self.server.ledger.inspect(identifier)
                    else:
                        if not ID.fullmatch(identifier):
                            raise RuntimeError("Full exec identity missing")
                        with self.server.ledger.lock:
                            if identifier in self.server.ledger.execs:
                                raise RuntimeError("Exec identity duplicated")
                            self.server.ledger.execs[identifier] = {"containerId": exec_create[1],
                                "commandSha256": hashlib.sha256(payload).hexdigest()}
                    self.server.ledger.write()
                self.reply(response.status, raw)
                return
            if response.status == 101:
                if not exec_use or exec_use[2] != "start" or not response.fp:
                    raise RuntimeError("Unowned upgrade response")
                self.send_response(101)
                self.send_header("Upgrade", "tcp")
                self.send_header("Connection", "Upgrade")
                self.end_headers()
                total, deadline = 0, time.monotonic() + 30
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("Owned exec output deadline")
                    connection.owned_socket.settimeout(min(remaining, 2))
                    chunk = response.fp.read1(CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_BODY:
                        raise RuntimeError("Owned exec output exceeds bounds")
                    self.wfile.write(chunk)
                    self.wfile.flush()
                self.close_connection = True
                return
            if start and response.status == 204:
                self.server.ledger.started(start[1])
            if remove and response.status in (204, 404):
                status, _ = rpc(self.server.ledger.daemon, "GET", "/containers/" + remove[1] + "/json")
                if status != 404:
                    raise RuntimeError("Removal absence not verified")
                with self.server.ledger.lock:
                    if remove[1] in self.server.ledger.rows:
                        self.server.ledger.rows[remove[1]]["absenceVerified"] = True
                self.server.ledger.write()
            self.send_response(response.status)
            self.send_header("Content-Type", response.getheader("Content-Type", "application/json"))
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            total, deadline = 0, time.monotonic() + 600
            while True:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Response lifetime exceeded")
                chunk = response.read1(CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > 512 * 1024 * 1024:
                    raise RuntimeError("Response byte budget exceeded")
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            self.close_connection = True
        except Exception as error:
            with self.server.ledger.lock:
                self.server.ledger.failures.append(type(error).__name__)
            try:
                self.server.ledger.write()
                self.reply(503, b'{"message":"Owned Docker admission failed"}')
            except Exception:
                self.close_connection = True
        finally:
            if response:
                response.close()
            if connection:
                connection.close()

    def reply(self, status, raw):
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Content-Type", "application/json")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True


def main():
    parser = argparse.ArgumentParser()
    for name in ("daemon", "socket", "run", "parent", "cgroup", "receipt", "sdk-cgroup"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch(r"[a-z0-9-]{16,80}", args.run):
        raise RuntimeError("Owned root coordinator required")
    if os.path.exists(args.socket):
        raise RuntimeError("Do not replace an existing endpoint")
    ledger = Ledger(args.daemon, args.run, args.parent, args.cgroup, args.receipt)
    ledger.write()
    with Server(args.socket, Handler) as server:
        server.ledger = ledger
        server.sdk_cgroup = args.sdk_cgroup
        os.chmod(args.socket, 0o600)
        server.serve_forever(poll_interval=0.25)


if __name__ == "__main__":
    main()
