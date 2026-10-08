"""Independent always-step recovery, inside its own pre-registered finite unit."""
import argparse
import hashlib
import json
import os
import pathlib
import re

from hosted_owner import OwnedUnits, command, members, properties, recover_containers, stop_expiry_owners, write_coordinator_receipt


def coordinator_barrier(run, receipt_path):
    """Quiesce the allocating coordinator before opening its mutable ledger."""
    path = pathlib.Path(receipt_path)
    owner = json.loads(path.read_text())
    unit = run + "-control.service"
    if owner.get("schemaVersion") != 1 or owner.get("run") != run or owner.get("unit") != unit or \
            owner.get("cgroup") != "/system.slice/" + unit or owner.get("dispatchAttempted") is not True:
        raise RuntimeError("Durable coordinator owner fence required")
    if hashlib.sha256(pathlib.Path(owner["script"]).read_bytes()).hexdigest() != owner["scriptSha256"]:
        raise RuntimeError("Coordinator source identity changed")

    def observe():
        state = properties(unit)
        if state.get("Id") != unit or state.get("Transient") != "yes" or state.get("Description") != owner["description"]:
            raise RuntimeError("Ambiguous/replaced coordinator unit; retain owner")
        if state.get("ControlGroup") and state["ControlGroup"] != owner["cgroup"]:
            raise RuntimeError("Coordinator cgroup identity changed")
        if owner.get("invocationId") and state.get("InvocationID") and owner["invocationId"] != state["InvocationID"]:
            raise RuntimeError("Coordinator invocation changed")
        if not owner.get("invocationId"):
            if not state.get("InvocationID"):
                raise RuntimeError("Dispatch has not acquired an actual invocation; retain finite owner")
            owner["invocationId"] = state["InvocationID"]
        if owner.get("execStart") and owner["execStart"] != state.get("ExecStart"):
            raise RuntimeError("Coordinator executable arguments changed")
        owner["execStart"] = state.get("ExecStart")
        pid = int(state["MainPID"])
        if pid:
            stat = pathlib.Path(f"/proc/{pid}/stat")
            birth = stat.read_text().rsplit(")", 1)[1].split()[19]
            executable = os.readlink(f"/proc/{pid}/exe")
            argv = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
            cgroup = pathlib.Path(f"/proc/{pid}/cgroup").read_text().strip()
            after = stat.read_text().rsplit(")", 1)[1].split()[19]
            identity = {"pid": pid, "startTicks": birth, "executable": executable, "cgroup": owner["cgroup"]}
            if birth != after or executable != owner["executable"] or argv[1:] != owner["arguments"] or cgroup != "0::" + owner["cgroup"]:
                raise RuntimeError("Coordinator process generation/arguments changed")
            if owner.get("mainProcess") and identity != owner["mainProcess"]:
                raise RuntimeError("Coordinator PID reused; retain owner")
            owner["mainProcess"] = identity
        return state

    before = observe()
    if int(before["ExecMainStartTimestampMonotonic"]) <= 0:
        raise RuntimeError("Actual coordinator dispatch/entry evidence absent")
    command(["/usr/bin/systemctl", "stop", unit], timeout=50)
    after = observe()
    if after["ActiveState"] not in ("inactive", "failed") or int(after["MainPID"]) != 0 or \
            int(after["ExecMainExitTimestampMonotonic"]) < int(before["ExecMainStartTimestampMonotonic"]) or members(owner["cgroup"]):
        raise RuntimeError("Coordinator retains live members; backend recovery fenced")
    owner.update(quiescenceVerified=True, exitStartMonotonic=before["ExecMainStartTimestampMonotonic"],
                 exitEndMonotonic=after["ExecMainExitTimestampMonotonic"])
    # Persistence cannot prevent the exact allocating coordinator stop. Only
    # after verified exit/empty cgroup do we retry our own distinct temporary
    # receipt; exhausted persistence still fences all backend recovery.
    write_coordinator_receipt(path, owner, "recovery")
    return owner


def recover(run, directory, coordinator_receipt):
    coordinator = coordinator_barrier(run, coordinator_receipt)
    receipt_path = pathlib.Path(directory) / "units.json"
    original = json.loads(receipt_path.read_text())
    if original.get("run") != run or original.get("schemaVersion") != 1:
        raise RuntimeError("Recovery owner receipt mismatch")
    parent = "authfinancial" + run.replace("auth-financial-", "").replace("-", "") + ".slice"
    names = {key: run + "-" + key + ".service" for key in ("sdk", "proxy", "daemon")}
    expiry_units = (run + "-expiry.timer", run + "-expiry.service")
    allowed = {*names.values(), *expiry_units, parent}
    if not set(original["units"]).issubset(allowed):
        raise RuntimeError("Unexpected manager resource in receipt")
    owner = OwnedUnits(run, receipt_path)
    owner.units = original["units"]
    historical_failures = original["failures"]
    if coordinator.get("receiptWriteFailures"):
        historical_failures = historical_failures + ["CoordinatorReceiptWriteFailureRetained"]
    failures = []
    cgroup = owner.identity(parent)["ControlGroup"] if parent in owner.units else None
    quiet = {key: name not in owner.units for key, name in names.items()}
    expiry_quiet = False
    containers_absent = names["daemon"] not in owner.units
    for key, name in names.items():
        if name in owner.units and owner.units[name].get("quiescenceVerified"):
            state = owner.identity(name)
            group = state["ControlGroup"] or owner.units[name].get("cgroup", "")
            quiet[key] = state["ActiveState"] in ("inactive", "failed") and not (group and members(group))
    container_receipt = pathlib.Path(directory) / "containers.json"
    if all(quiet.values()) and container_receipt.exists():
        previous = json.loads(container_receipt.read_text())
        if previous.get("run") != run:
            raise RuntimeError("Cached container proof belongs to a different run")
        # A settled daemon cannot allocate after the retained final empty
        # inventory proof. Preserve the immutable failure ledger separately.
        containers_absent = previous.get("finalInventoryEmpty") is True and all(
            row.get("absenceVerified") is True for row in previous["containers"].values())
    if not quiet["sdk"]:
        try:
            owner.stop(names["sdk"])
            quiet["sdk"] = True
        except Exception as error:
            failures.append("SDKQuiescence:" + type(error).__name__)
    if quiet["sdk"]:
        expiry_quiet = stop_expiry_owners(owner, expiry_units, failures)
    if quiet["sdk"] and expiry_quiet:
        if not quiet["proxy"]:
            try:
                owner.stop(names["proxy"])
                quiet["proxy"] = True
            except Exception as error:
                failures.append("ProxyQuiescence:" + type(error).__name__)
        daemon_socket = str(pathlib.Path("/var/tmp") / run / "daemon.sock")
        if not quiet["daemon"]:
            try:
                if not quiet["proxy"]:
                    raise RuntimeError("Proxy must be quiescent before independent recovery")
                recover_containers(daemon_socket, pathlib.Path(directory) / "containers.json", run, parent, cgroup)
                containers_absent = True
            except Exception as error:
                failures.append("ContainerRecovery:" + type(error).__name__)
            try:
                owner.stop(names["daemon"])
                quiet["daemon"] = True
            except Exception as error:
                failures.append("DaemonQuiescence:" + type(error).__name__)
    bridge_path = pathlib.Path(directory) / "bridge.json"
    if not containers_absent and quiet["daemon"]:
        failures.append("StoppedDaemonWithoutVerifiedContainerAbsence")
    if bridge_path.exists() and expiry_quiet and all(quiet.values()) and containers_absent:
        try:
            bridge = json.loads(bridge_path.read_text())
            if bridge["name"] != "af" + run[-12:]:
                raise RuntimeError("Ambiguous bridge birth retained")
            rows = json.loads(command(["/usr/sbin/ip", "-json", "link", "show"]))
            selected = [row for row in rows if row["ifname"] == bridge["name"]]
            if selected:
                if bridge.get("ifindex") is None:
                    raise RuntimeError("Ambiguous bridge birth retained")
                if len(selected) != 1 or selected[0]["ifindex"] != bridge["ifindex"] or selected[0]["address"] != bridge["mac"]:
                    raise RuntimeError("Bridge generation mismatch")
                if any(row.get("master") == bridge["name"] for row in rows):
                    raise RuntimeError("Bridge active clients retained")
                command(["/usr/sbin/ip", "link", "delete", "dev", bridge["name"]])
                if any(row["ifname"] == bridge["name"] for row in json.loads(command(["/usr/sbin/ip", "-json", "link", "show"]))):
                    raise RuntimeError("Bridge absence not observed")
            bridge["absenceVerified"] = True
            bridge_path.write_text(json.dumps(bridge), encoding="utf-8")
        except Exception as error:
            failures.append("BridgeQuiescence:" + type(error).__name__)
    if parent in owner.units:
        try:
            if not expiry_quiet:
                raise RuntimeError("Expiry controller remains unresolved")
            if cgroup and members(cgroup):
                raise RuntimeError("Aggregate retains live members")
            owner.stop(parent)
        except Exception as error:
            failures.append("SliceQuiescence:" + type(error).__name__)
    owner.failures = historical_failures + failures
    owner.save()
    result = {"schemaVersion": 1, "run": run, "sdkQuiescent": quiet["sdk"],
              "proxyQuiescent": quiet["proxy"], "daemonQuiescent": quiet["daemon"],
              "containersAbsent": containers_absent, "expiryQuiescent": expiry_quiet, "currentCleanupFailures": failures,
              "originalQualificationFailuresRetained": historical_failures,
              "remainingResources": 0 if not failures and expiry_quiet and all(quiet.values()) and containers_absent else None,
              "nativeAccepted": False}
    (pathlib.Path(directory) / "external-cleanup.json").write_text(json.dumps(result), encoding="utf-8")
    if failures or result["remainingResources"] is None:
        raise RuntimeError("Unresolved owned recovery; preserve exact handles and receipts")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--coordinator-receipt", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"auth-financial-[0-9]+-[0-9]+-[a-f0-9]{12}", args.run) or os.geteuid() != 0:
        raise RuntimeError("Exact hosted recovery owner required")
    observed = properties(args.run + "-recovery.service")
    if not observed["InvocationID"] or int(observed["MainPID"]) != os.getpid() or \
            pathlib.Path("/proc/self/cgroup").read_text().strip() != "0::" + observed["ControlGroup"]:
        raise RuntimeError("Pre-registered finite recovery unit required")
    if observed["MemoryMax"] != str(512 * 1024 ** 2) or observed["MemorySwapMax"] != "0" or observed["RuntimeMaxUSec"] not in ("10min", "600s") or observed["CPUQuotaPerSecUSec"] != "1s":
        raise RuntimeError("Actual recovery capacity/lifetime differs")
    recover(args.run, args.receipt, args.coordinator_receipt)


if __name__ == "__main__":
    main()
