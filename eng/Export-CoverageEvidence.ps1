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
    [xml] $clean = '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010" name="Owned Auth validation"><Results /><ResultSummary><Counters /></ResultSummary></TestRun>'
    $namespace = $clean.DocumentElement.NamespaceURI
    $resultsNode = $clean.DocumentElement.SelectSingleNode('*[local-name()="Results"]')
    $countersNode = $clean.DocumentElement.SelectSingleNode('*[local-name()="ResultSummary"]/*[local-name()="Counters"]')
    foreach ($result in $original.TestRun.Results.UnitTestResult) {
        $entry = $clean.CreateElement('UnitTestResult', $namespace)
        $method = ([string] $result.testName).Split('(')[0].Trim()
        if ($method -notmatch '^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$') { $method = 'Recorded.TestMethod' }
        $entry.SetAttribute('testName', $method)
        if ([string] $result.outcome -notin @('Passed', 'Failed', 'Error', 'Timeout', 'Aborted', 'Inconclusive', 'NotExecuted', 'NotRunnable', 'Pending', 'Warning', 'Completed', 'InProgress')) {
            throw 'Unexpected test outcome in evidence.'
        }
        $entry.SetAttribute('outcome', [string] $result.outcome)
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
    $clean.Save((Join-Path $OutputDirectory 'owned-tests.trx'))
}
[ordered]@{ CoverageAvailable = ($reports.Count -eq 1); TestResultsAvailable = ($trxFiles.Count -eq 1);
    TestOutputRetained = $false; FailureMessagesRetained = $false; ParameterValuesRetained = $false } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'availability.json') -Encoding utf8
