"""Independent finite aggregate-job expiry. No container/volume/data removal.

The timer is armed BEFORE any daemon/container/SDK allocation. The exact owned
cgroup directory generation is retained in a root-only receipt. This is the
Linux analogue of terminating an owned job, not selecting a process tree/PIDs.
"""
import argparse
import hashlib
import json
import os
import pathlib
import time

from hosted_owner import command, properties


def expire(run, receipt):
    directory = pathlib.Path(receipt)
    ownership = json.loads((directory / "aggregate.json").read_text())
    units = json.loads((directory / "units.json").read_text())
    if ownership["run"] != run or units["run"] != run:
        raise RuntimeError("Expiry receipt owner mismatch")
    parent = ownership["unit"]
    row = units["units"][parent]
    if hashlib.sha256(pathlib.Path(row["fragment"]).read_bytes()).hexdigest() != row["sha256"]:
        raise RuntimeError("Aggregate unit configuration changed")
    state = properties(parent)
    if state["Id"] != parent or state["FragmentPath"] != row["fragment"] or state["ControlGroup"] != ownership["cgroup"]:
        raise RuntimeError("Aggregate manager identity changed")
    path = pathlib.Path("/sys/fs/cgroup") / ownership["cgroup"].lstrip("/")
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    failures = []
    try:
        generation = os.fstat(descriptor)
        if (generation.st_dev, generation.st_ino) != (ownership["device"], ownership["inode"]):
            raise RuntimeError("Aggregate cgroup generation changed")
        # Ask the exact task-owned registered service units to stop gracefully.
        # Manager ownership/cgroup identity remains in force during this window.
        for suffix in ("sdk", "proxy", "daemon"):
            name = run + "-" + suffix + ".service"
            if name in units["units"]:
                owned = units["units"][name]
                observed = properties(name)
                if observed["FragmentPath"] != owned["fragment"] or hashlib.sha256(pathlib.Path(owned["fragment"]).read_bytes()).hexdigest() != owned["sha256"]:
                    raise RuntimeError("Expiry service identity changed")
                try:
                    command(["/usr/bin/systemctl", "stop", name], timeout=40)
                except Exception as error:
                    failures.append(type(error).__name__)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            with open(path / "cgroup.events", encoding="utf-8") as stream:
                if "populated 0" in stream.read().splitlines():
                    break
            time.sleep(0.25)
        with open(path / "cgroup.events", encoding="utf-8") as stream:
            populated = "populated 1" in stream.read().splitlines()
        if populated:
            # Open relative to the retained directory FD, not a re-resolved
            # path susceptible to cgroup deletion/recreation. The whole job was
            # explicitly registered and bounded before any workload birth.
            kill = os.open("cgroup.kill", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                os.write(kill, b"1\n")
            finally:
                os.close(kill)
        deadline = time.monotonic() + 10
        quiet = False
        while time.monotonic() < deadline:
            events = os.open("cgroup.events", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                quiet = b"populated 0" in os.read(events, 1024).splitlines()
            finally:
                os.close(events)
            if quiet:
                break
            time.sleep(0.25)
        (directory / "expiry.json").write_text(json.dumps({"run": run, "expiryTriggered": True,
            "aggregateQuiescent": quiet, "gracefulFailuresRetained": failures,
            "containerAbsenceProved": False, "volumeRemoval": False, "nativeAccepted": False}), encoding="utf-8")
        if not quiet:
            raise RuntimeError("Owned aggregate expiry quiescence unresolved")
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True)
    parser.add_argument("--receipt", required=True)
    args = parser.parse_args()
    actual = properties(args.run + "-expiry.service")
    if os.geteuid() != 0 or int(actual["MainPID"]) != os.getpid() or not actual["InvocationID"] or actual["MemoryMax"] != str(128 * 1024 ** 2) or actual["RuntimeMaxUSec"] not in ("3min", "180s"):
        raise RuntimeError("Finite pre-registered expiry invocation required")
    expire(args.run, args.receipt)
