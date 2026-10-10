param(
    [Parameter(Mandatory = $true)] [string] $ResultsDirectory,
    [Parameter(Mandatory = $true)] [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$reports = @(& (Join-Path $PSScriptRoot 'Get-OwnedCoverageReport.ps1') -ResultsDirectory $ResultsDirectory)
$trxFiles = if (Test-Path -LiteralPath $ResultsDirectory) {
    @(Get-ChildItem -LiteralPath $ResultsDirectory -Recurse -Filter '*.trx')
} else { @() }
$owned = @('Legacy.Maliev.AuthService.Api', 'Legacy.Maliev.AuthService.Application',
    'Legacy.Maliev.AuthService.Domain', 'Legacy.Maliev.AuthService.Infrastructure')

function Get-PhysicalLineCounts($Classes) {
    $lines = [Collections.Generic.Dictionary[string, bool]]::new([StringComparer]::Ordinal)
    foreach ($class in $Classes) {
        $physicalPath = ([string] $class.filename).Replace('\', '/')
        foreach ($line in $class.SelectNodes('lines/line')) {
            $number = [long]::Parse([string] $line.number, [Globalization.CultureInfo]::InvariantCulture)
            $hits = [long]::Parse([string] $line.hits, [Globalization.CultureInfo]::InvariantCulture)
            if ($number -le 0 -or $hits -lt 0) { throw 'Invalid physical-line coverage data.' }
            $key = $physicalPath + [char] 0 + $number.ToString([Globalization.CultureInfo]::InvariantCulture)
            $previous = $false
            $null = $lines.TryGetValue($key, [ref] $previous)
            $lines[$key] = $previous -or $hits -gt 0
        }
    }
    return [pscustomobject]@{ Total = $lines.Count; Covered = @($lines.Values | Where-Object { $_ }).Count }
}
if ($reports.Count -gt 1 -or $trxFiles.Count -gt 1) { throw 'Evidence requires a single full-suite coverage report and TRX.' }
if ($reports.Count -eq 1) {
    [xml] $coverage = Get-Content -LiteralPath $reports[0].FullName -Raw
    foreach ($source in $coverage.SelectNodes('/coverage/sources/source')) { $source.InnerText = '.' }
    foreach ($package in $coverage.coverage.packages.package) {
        if ($package.name -notin $owned) { throw 'Foreign coverage assembly cannot be exported.' }
        $before = Get-PhysicalLineCounts $package.classes.class
        $origins = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
        foreach ($class in $package.classes.class) {
            $path = ([string] $class.filename).Replace('\', '/')
            $originalPath = $path
            $marker = [string] $package.name + '/'
            $index = $path.IndexOf($marker, [StringComparison]::Ordinal)
            if ($index -ge 0) { $path = $path.Substring($index) }
            if ($path.StartsWith('/') -or $path.Contains(':') -or '..' -in $path.Split('/')) {
                throw 'Coverage source path cannot be safely made repository-relative.'
            }
            $previousOrigin = $null
            if ($origins.TryGetValue($path, [ref] $previousOrigin) -and $previousOrigin -cne $originalPath) {
                throw 'Coverage source path collision detected.'
            }
            $origins[$path] = $originalPath
            $class.filename = $path
        }
        $after = Get-PhysicalLineCounts $package.classes.class
        if ($before.Total -ne $after.Total -or $before.Covered -ne $after.Covered) {
            throw 'Evidence export changed physical-line coverage counts.'
        }
    }
    $coverage.Save((Join-Path $OutputDirectory 'coverage.cobertura.xml'))
}
if ($trxFiles.Count -eq 1) {
    [xml] $original = Get-Content -LiteralPath $trxFiles[0].FullName -Raw
    [xml] $clean = '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010" name="Owned Auth validation"><Results /><TestDefinitions /><TestEntries /><ResultSummary><Counters /></ResultSummary></TestRun>'
    $namespace = $clean.DocumentElement.NamespaceURI
    $resultsNode = $clean.DocumentElement.SelectSingleNode('*[local-name()="Results"]')
    $countersNode = $clean.DocumentElement.SelectSingleNode('*[local-name()="ResultSummary"]/*[local-name()="Counters"]')
    $definitionsNode = $clean.DocumentElement.SelectSingleNode('*[local-name()="TestDefinitions"]')
    $entriesNode = $clean.DocumentElement.SelectSingleNode('*[local-name()="TestEntries"]')
    $definitions = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    $entries = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    $resultIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $executionIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($definition in $original.TestRun.TestDefinitions.UnitTest) {
        $id = [guid]::Empty
        if (-not [guid]::TryParse([string] $definition.id, [ref] $id) -or $id -eq [guid]::Empty -or
            -not $definitions.TryAdd($id.ToString('D'), $definition)) { throw 'Invalid or duplicate test definition identity.' }
    }
    foreach ($testEntry in $original.TestRun.TestEntries.TestEntry) {
        $id = [guid]::Empty
        if (-not [guid]::TryParse([string] $testEntry.testId, [ref] $id) -or
            -not $entries.TryAdd($id.ToString('D'), $testEntry)) { throw 'Invalid or duplicate test entry identity.' }
    }
    $outcomeCounters = @{ Passed = 'passed'; Failed = 'failed'; Error = 'error'; Timeout = 'timeout';
        Aborted = 'aborted'; Inconclusive = 'inconclusive'; NotRunnable = 'notRunnable'; NotExecuted = 'notExecuted';
        Pending = 'pending'; Warning = 'warning'; Completed = 'completed'; InProgress = 'inProgress' }
    $observedOutcomes = @{}
    $caseIdentities = @()
    foreach ($result in $original.TestRun.Results.UnitTestResult) {
        $entry = $clean.CreateElement('UnitTestResult', $namespace)
        $method = ([string] $result.testName).Split('(')[0].Trim()
        if ($method -notmatch '^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$') { $method = 'Recorded.TestMethod' }
        $testId = [guid]::Empty
        $executionId = [guid]::Empty
        if (-not [guid]::TryParse([string] $result.testId, [ref] $testId) -or $testId -eq [guid]::Empty -or
            -not [guid]::TryParse([string] $result.executionId, [ref] $executionId) -or $executionId -eq [guid]::Empty -or
            -not $resultIds.Add($testId.ToString('D')) -or -not $executionIds.Add($executionId.ToString('D'))) {
            throw 'Invalid or duplicate test result identity.'
        }
        $definition = $null
        $testEntry = $null
        if (-not $definitions.TryGetValue($testId.ToString('D'), [ref] $definition) -or
            -not $entries.TryGetValue($testId.ToString('D'), [ref] $testEntry)) { throw 'Missing test identity join.' }
        $definitionExecution = [guid]::Empty
        $entryExecution = [guid]::Empty
        if (-not [guid]::TryParse([string] $definition.Execution.id, [ref] $definitionExecution) -or
            -not [guid]::TryParse([string] $testEntry.executionId, [ref] $entryExecution) -or
            $definitionExecution -ne $executionId -or $entryExecution -ne $executionId) {
            throw 'Mismatched test execution identity.'
        }
        if (-not [string]::Equals([string] $definition.name, [string] $result.testName, [StringComparison]::Ordinal)) {
            throw 'Mismatched test display identity.'
        }
        $className = ([string] $definition.TestMethod.className).Split(',')[0].Trim()
        $methodName = [string] $definition.TestMethod.name
        if (($className + '.' + $methodName) -cne $method -or
            $method -notmatch '^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$') { throw 'Unsafe or mismatched test method identity.' }
        $safeDefinition = $clean.CreateElement('UnitTest', $namespace)
        $safeDefinition.SetAttribute('id', $testId.ToString('D'))
        $safeDefinition.SetAttribute('name', $method)
        $safeExecution = $clean.CreateElement('Execution', $namespace)
        $safeExecution.SetAttribute('id', $executionId.ToString('D'))
        $null = $safeDefinition.AppendChild($safeExecution)
        $safeMethod = $clean.CreateElement('TestMethod', $namespace)
        $safeMethod.SetAttribute('className', $className)
        $safeMethod.SetAttribute('name', $methodName)
        $null = $safeDefinition.AppendChild($safeMethod)
        $null = $definitionsNode.AppendChild($safeDefinition)
        $safeEntry = $clean.CreateElement('TestEntry', $namespace)
        $safeEntry.SetAttribute('testId', $testId.ToString('D'))
        $safeEntry.SetAttribute('executionId', $executionId.ToString('D'))
        $null = $entriesNode.AppendChild($safeEntry)
        # Export only hashes of case display identity; never its parameter text or failure output.
        $identityBytes = [Text.Encoding]::UTF8.GetBytes($method + '|' + $testId.ToString('D'))
        $caseIdentities += [ordered]@{ Method = $method; TestId = $testId.ToString('D');
            ExecutionId = $executionId.ToString('D');
            IdentitySha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($identityBytes)).ToLowerInvariant();
            DisplayCaseIdentitySha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
                [Text.Encoding]::UTF8.GetBytes([string] $result.testName))).ToLowerInvariant() }
        $entry.SetAttribute('testName', $method)
        if ([string] $result.outcome -notin @('Passed', 'Failed', 'Error', 'Timeout', 'Aborted', 'Inconclusive', 'NotExecuted', 'NotRunnable', 'Pending', 'Warning', 'Completed', 'InProgress')) {
            throw 'Unexpected test outcome in evidence.'
        }
        $entry.SetAttribute('outcome', [string] $result.outcome)
        $outcome = [string] $result.outcome
        $observedOutcomes[$outcome] = 1 + [long] $observedOutcomes[$outcome]
        foreach ($name in @('testId', 'executionId')) {
            $id = [guid]::Empty
            if ([guid]::TryParse([string] $result.$name, [ref] $id)) { $entry.SetAttribute($name, $id.ToString('D')) }
        }
        $duration = [timespan]::Zero
        if ([timespan]::TryParse([string] $result.duration, [ref] $duration)) { $entry.SetAttribute('duration', $duration.ToString()) }
        $null = $resultsNode.AppendChild($entry)
    }
    foreach ($counter in $original.TestRun.ResultSummary.Counters.Attributes) {
        $number = [long]::Parse($counter.Value, [Globalization.CultureInfo]::InvariantCulture)
        if ($number -lt 0 -or $counter.Name -notmatch '^[A-Za-z]+$') { throw 'Invalid test counter in evidence.' }
        $countersNode.SetAttribute($counter.Name, $number.ToString([Globalization.CultureInfo]::InvariantCulture))
    }
    if ($definitions.Count -ne $resultIds.Count -or $entries.Count -ne $resultIds.Count -or
        [long] $original.TestRun.ResultSummary.Counters.total -ne $resultIds.Count -or
        [long] $original.TestRun.ResultSummary.Counters.executed -ne $resultIds.Count) { throw 'Incomplete test identity roster.' }
    foreach ($outcome in $outcomeCounters.Keys) {
        $counter = $original.TestRun.ResultSummary.Counters.GetAttribute($outcomeCounters[$outcome])
        $reported = if ($counter -eq '') { 0 } else { [long] $counter }
        if ($reported -ne [long] $observedOutcomes[$outcome]) { throw 'Inconsistent test outcome counters.' }
    }
    $clean.Save((Join-Path $OutputDirectory 'owned-tests.trx'))
    [ordered]@{ SchemaVersion = 2; IdentitySource = 'Validated original TRX definition/result/entry joins';
        ParameterValuesRetained = $false; Cases = $caseIdentities } | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $OutputDirectory 'test-identities.json') -Encoding utf8
}
[ordered]@{ CoverageAvailable = ($reports.Count -eq 1); TestResultsAvailable = ($trxFiles.Count -eq 1);
    TestOutputRetained = $false; FailureMessagesRetained = $false; ParameterValuesRetained = $false } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'availability.json') -Encoding utf8
