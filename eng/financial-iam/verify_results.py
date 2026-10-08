"""Strict native TRX joins. Synthetic parser controls are never native evidence."""
import argparse
import json
import pathlib
import re
import xml.etree.ElementTree as ET

NS = {"t": "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"}
ORDINARY = "Legacy.Maliev.AuthService.OrdinaryFinancialIam.Tests.OrdinaryFinancialIamTests"
ACCOUNTING = "Legacy.Maliev.AuthService.OrdinaryFinancialIam.Tests.AccountingFinancialHttpTests"
TRANSPORT = "Legacy.Maliev.AuthService.Tests.QuotationInvoiceLiveTransportHttpTests"
CASES = {
    (ORDINARY, "OrdinaryFinancial_EnrollmentNeedsItsOwnNormalApiAuthority"): {"anonymous", "check-only", "ordinary-wrong-audience"},
    (ORDINARY, "OrdinaryFinancial_OpaqueIssuedEmployeeUsesOnlyNormalPersistedEnrollment"): {"allowed", "unbound", "wrong-resource", "revoked", "expired", "unknown-opaque", "wrong-key"},
    (ORDINARY, "OrdinaryFinancial_CanceledCallerCannotAcquireOrUseAuthorityAndNextCallRecovers"): {None},
    (ORDINARY, "OrdinaryFinancial_RealServiceSubjectHasOnlyFiniteFinancialReadBinding"): {"legacy-auth", "legacy-quotation"},
    (ACCOUNTING, "OrdinaryAccounting_ActualFinancialHttpReadRequiresLiveNormalBindingAndRevocationWins"): {"legacy-auth", "legacy-quotation"},
    (ACCOUNTING, "OrdinaryAccounting_RealFinancialHttpRejectsWrongWorkloadOrBoundaryWithoutMutation"): {"unrelated", "wrong-key", "wrong-profile", "wrong-audience"},
    (TRANSPORT, "LoginResponseWrongTrust_DoesNotSendCredentialedIamRequest"): {
        "wrong-machine", "wrong-audience", "forged", "duplicate-sub", "duplicate-aud", "duplicate-kind",
        "duplicate-iat", "duplicate-exp", "employee-kind", "session-claim", "executor-claim", "session-id-claim",
        "family-claim", "employee-id-claim", "stamp-claim", "expired", "future-iat", "multiple-audiences",
        "legacy-profile", "wrong-service-name", "wrong-purpose", "wrong-role", "wrong-azp", "wrong-permission",
        "duplicate-service_name", "duplicate-purpose", "duplicate-role", "duplicate-azp", "duplicate-permissions"},
}
ENUM_CASES = {
    "OrdinaryFinancial_EnrollmentNeedsItsOwnNormalApiAuthority": {"anonymous": "Unauthorized", "check-only": "Forbidden", "ordinary-wrong-audience": "Unauthorized"},
    "OrdinaryFinancial_OpaqueIssuedEmployeeUsesOnlyNormalPersistedEnrollment": {"allowed": "Allowed", "unbound": "Denied", "wrong-resource": "Denied", "revoked": "Denied", "expired": "Denied", "unknown-opaque": "Denied", "wrong-key": "Unavailable"},
    "OrdinaryAccounting_RealFinancialHttpRejectsWrongWorkloadOrBoundaryWithoutMutation": {"unrelated": "Forbidden", "wrong-key": "Forbidden", "wrong-profile": "Forbidden", "wrong-audience": "Unauthorized"},
}


def read_trx(path, expected_count):
    raw = pathlib.Path(path).read_bytes()
    if len(raw) > 32 * 1024 * 1024 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("Unsafe or oversized TRX")
    root = ET.fromstring(raw)
    if root.tag != "{" + NS["t"] + "}TestRun":
        raise ValueError("TRX root namespace differs")
    for name in ("TestDefinitions", "Results", "ResultSummary", "Counters"):
        if sum(node.tag.split("}")[-1] == name for node in root.iter()) != 1:
            raise ValueError("Duplicate/missing global TRX container")
    for name, child in (("TestDefinitions", "UnitTest"), ("Results", "UnitTestResult")):
        container = root.find("t:" + name, NS)
        if container is None or any(node.tag != "{" + NS["t"] + "}" + child for node in container):
            raise ValueError("Unexpected native inventory node")
    definitions, executions = {}, {}
    for test in root.findall("t:TestDefinitions/t:UnitTest", NS):
        identity = test.get("id")
        method, execution = test.find("t:TestMethod", NS), test.find("t:Execution", NS)
        if not identity or identity in definitions or method is None or execution is None or not execution.get("id") or len(test.findall("t:TestMethod", NS)) != 1 or len(test.findall("t:Execution", NS)) != 1:
            raise ValueError("Duplicate/incomplete native definition")
        if execution.get("id") in executions:
            raise ValueError("Duplicate native execution identity")
        definitions[identity] = (method.get("className"), method.get("name"), execution.get("id"), test.get("name"))
        executions[execution.get("id")] = identity
    rows, identities = [], set()
    for result in root.findall("t:Results/t:UnitTestResult", NS):
        identity = result.get("testId")
        if identity not in definitions or identity in identities:
            raise ValueError("Orphan/duplicate native result")
        klass, method, execution, name = definitions[identity]
        if result.get("executionId") != execution or result.get("testName") != name or result.get("outcome") != "Passed":
            raise ValueError("Native execution join or outcome failed")
        identities.add(identity)
        rows.append((klass, method, name))
    if identities != set(definitions) or len(rows) != expected_count:
        raise ValueError("Native discovery/result inventory differs")
    summary = root.find("t:ResultSummary", NS)
    counters = root.find("t:ResultSummary/t:Counters", NS)
    if summary is None or summary.get("outcome") not in ("Completed", "Passed") or counters is None:
        raise ValueError("Native result summary missing")
    for key in ("total", "executed", "passed"):
        if counters.get(key) != str(expected_count):
            raise ValueError("Native counters disagree")
    required = dict.fromkeys(("total", "executed", "passed"), str(expected_count))
    required.update(dict.fromkeys(("failed", "error", "timeout", "aborted", "inconclusive", "passedButRunAborted", "notRunnable", "notExecuted", "disconnected", "warning", "completed", "inProgress", "pending"), "0"))
    if counters.attrib != required:
        raise ValueError("Skipped/failed/missing/unknown native counter")
    return rows


def exact_cases(rows, selected):
    expected = {(klass, method, case) for (klass, method), cases in CASES.items()
                if klass in selected for case in cases}
    actual = set()
    for klass, method, name in rows:
        if (klass, method) not in CASES or klass not in selected:
            raise ValueError("Unexpected focused method")
        cases = CASES[(klass, method)]
        if cases == {None}:
            if name != klass + "." + method:
                raise ValueError("Fact display identity differs")
            case = None
        else:
            # Exact single string scenario is the unique parameter coordinate;
            # additional enum expected values are still asserted by native C#.
            match = re.fullmatch(re.escape(klass + "." + method) + r'\([a-zA-Z]+: "([a-z0-9_-]+)"(?:, [a-zA-Z]+: ([a-zA-Z]+))?\)', name or "")
            if not match:
                raise ValueError("Focused display parameter identity differs")
            case = match[1]
            if match[2] != ENUM_CASES.get(method, {}).get(case):
                raise ValueError("Focused enum coordinate differs")
        coordinate = klass, method, case
        if coordinate not in expected or coordinate in actual:
            raise ValueError("Missing/duplicate/unexpected focused coordinate")
        actual.add(coordinate)
    if actual != expected:
        raise ValueError("Focused coordinates incomplete")


def verify(directory):
    directory = pathlib.Path(directory)
    ordinary = read_trx(directory / "ordinary-focus.trx", 19)
    transport = read_trx(directory / "transport-focus.trx", 29)
    exact_cases(ordinary, {ORDINARY, ACCOUNTING})
    exact_cases(transport, {TRANSPORT})
    full_ordinary = read_trx(directory / "ordinary-full.trx", 39)
    full_auth = read_trx(directory / "auth-full.trx", 946)
    full_genuine = read_trx(directory / "genuine-full.trx", 31)
    # Focus coordinates must also occur in each appropriate full inventory.
    if not set(ordinary).issubset(set(full_ordinary)) or not set(transport).issubset(set(full_auth)):
        raise ValueError("Focused/full native binding differs")
    return {"schemaVersion": 1, "ordinaryFocused": 19, "ordinaryFull": len(full_ordinary),
            "transportFocused": 29, "authFull": len(full_auth), "genuineFull": len(full_genuine),
            "newCandidateTuples": 30, "retainedFocusedTuples": 18,
            "buildPassed": False, "cleanupPassed": False, "overallAccepted": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--receipt", required=True)
    args = parser.parse_args()
    result = verify(args.directory)
    pathlib.Path(args.receipt).write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
