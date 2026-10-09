"""Require all ten authored focused cases actually executed successfully."""
import sys
import uuid
from collections import Counter
import xml.etree.ElementTree as E
import json
from pathlib import Path
import discovery

def verify(path, assembly, listing, roster_path):
    actual = discovery.capture(assembly,listing)
    if json.loads(Path(roster_path).read_bytes()) != actual:
        raise ValueError('Discovery or compiled assembly changed')
    root = E.parse(path).getroot()
    ns = {'t':'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}
    for name in ('ResultSummary','Results','TestDefinitions','TestEntries'):
        if len(root.findall('t:'+name,ns)) != 1 or len(root.findall('.//t:'+name,ns)) != 1:
            raise ValueError('Duplicate or stray TRX container')
    if len(root.findall('.//t:Counters',ns)) != 1:
        raise ValueError('Duplicate or stray counters')
    counters = root.find('t:ResultSummary/t:Counters', ns)
    expected = {'total':10, 'executed':10, 'passed':10, 'failed':0, 'notExecuted':0}
    counter_keys = set(expected) | {'error','timeout','aborted','inconclusive','passedButRunAborted','notRunnable','disconnected','warning','completed','inProgress','pending'}
    if counters is None or set(counters.attrib) != counter_keys:
        raise ValueError('Incomplete counter set')
    if counters is None or any(int(counters.attrib.get(k, '-1')) != v for k,v in expected.items()):
        raise ValueError('Focused ten-case counters failed')
    summary = root.find('t:ResultSummary', ns)
    if summary.get('outcome') not in ('Completed', 'Passed') or any(int(v) != 0 for k,v in counters.attrib.items() if k not in expected):
        raise ValueError('Incomplete or nonpassing summary')
    rows = root.findall('t:Results/t:UnitTestResult', ns)
    if len(rows) != 10 or any(row.get('outcome') != 'Passed' for row in rows):
        raise ValueError('Focused ten-case result rows failed')
    if len({row.get('testId') for row in rows}) != 10 or any(not row.get('testId') for row in rows):
        raise ValueError('Duplicate or absent focused test identity')
    definitions = root.findall('t:TestDefinitions/t:UnitTest', ns)
    entries = root.findall('t:TestEntries/t:TestEntry', ns)
    if len(root.findall('.//t:UnitTestResult',ns)) != len(rows) or len(root.findall('.//t:UnitTest',ns)) != len(definitions) or len(root.findall('.//t:TestEntry',ns)) != len(entries):
        raise ValueError('Stray TRX result or definition')
    if len(definitions) != 10 or len(entries) != 10:
        raise ValueError('Missing definition or execution joins')
    defs = {d.get('id'):d for d in definitions}
    joins = {(e.get('testId'),e.get('executionId')) for e in entries}
    if len(defs) != 10 or len(joins) != 10:
        raise ValueError('Duplicate definition or execution join')
    roster = Counter()
    executions = set()
    names = []
    for row in rows:
        test_id, execution = row.get('testId'), row.get('executionId')
        uuid.UUID(test_id); uuid.UUID(execution)
        definition = defs.get(test_id)
        if definition is None or (test_id,execution) not in joins or execution in executions:
            raise ValueError('Invalid execution join')
        executions.add(execution)
        declared = definition.find('t:Execution',ns)
        method = definition.find('t:TestMethod',ns)
        if declared is None or declared.get('id') != execution or method is None:
            raise ValueError('Invalid test method join')
        class_name = method.get('className','')
        full_method = class_name+'.'+method.get('name','')
        if full_method not in discovery.METHODS or method.get('codeBase') != str(Path(assembly).resolve()):
            raise ValueError('Wrong full class or compiled assembly')
        name = row.get('testName')
        if name != definition.get('name') or name not in actual['cases'] or discovery.association(name)[0] != full_method:
            raise ValueError('Wrong result display name or discovered association')
        names.append(name)
        roster[(class_name.split('.')[-1],method.get('name'))] += 1
    if roster != Counter({('CustomerRefreshAdmissionTests','Refresh_RechecksInitialPasswordStateBeforeIssuance'):4, ('LegacyIdentityReaderTests','FindActive_InitialPasswordState_DeniesOnlySetupRequiredCustomer'):4, ('RefreshSessionIdentityBoundaryHttpTests','CustomerRefresh_CurrentInitialPasswordState_ControlsFamilyAdmissionOnly'):2}):
        raise ValueError('Wrong focused method roster')
    if set(names) != set(actual['cases']) or len(set(names)) != 10:
        raise ValueError('Substituted discovered case')

if __name__ == '__main__':
    verify(*sys.argv[1:])
