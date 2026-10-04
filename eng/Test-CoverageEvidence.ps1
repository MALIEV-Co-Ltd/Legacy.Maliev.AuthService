$ErrorActionPreference = 'Stop'
$fixture = Join-Path $PSScriptRoot '../artifacts/evidence-controls/input'
$output = Join-Path $PSScriptRoot '../artifacts/evidence-controls/output'
New-Item -ItemType Directory -Path $fixture -Force | Out-Null
$owned = @('Legacy.Maliev.AuthService.Api', 'Legacy.Maliev.AuthService.Application',
    'Legacy.Maliev.AuthService.Domain', 'Legacy.Maliev.AuthService.Infrastructure')
$generated = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../Legacy.Maliev.AuthService.Infrastructure/Migrations') -File |
    Where-Object { $_.Name -match '(\.Designer|ModelSnapshot)\.cs$' })
$packages = foreach ($assembly in $owned) {
    $classes = '<class name="Production" filename="C:/Users/PRIVATE_SUBJECT/work/{0}/Production.cs"><lines><line number="1" hits="1" /><line number="2" hits="0" /></lines></class>' -f $assembly
    if ($assembly -eq 'Legacy.Maliev.AuthService.Infrastructure') {
        $classes += ($generated | ForEach-Object {
            '<class name="Generated" filename="C:/Users/PRIVATE_SUBJECT/work/Legacy.Maliev.AuthService.Infrastructure/Migrations/{0}"><lines><line number="1" hits="1" /><line number="2" hits="0" /></lines></class>' -f $_.Name
        }) -join ''
    }
    '<package name="{0}"><classes>{1}</classes></package>' -f $assembly, $classes
}
$coverage = '<coverage line-rate="0.5"><sources><source>C:/Users/PRIVATE_SUBJECT/work</source></sources><packages>' + ($packages -join '') + '</packages></coverage>'
$trx = '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010" name="PRIVATE_SUBJECT"><Results><UnitTestResult testName="Auth.Tests.Failed(secret:PRIVATE_TOKEN)" outcome="Failed" duration="00:00:01"><Output><ErrorInfo><Message>PRIVATE_TOKEN</Message><StackTrace>PRIVATE_SUBJECT</StackTrace></ErrorInfo><StdOut>PRIVATE_TOKEN</StdOut></Output></UnitTestResult><UnitTestResult testName="Auth.Tests.Passed" outcome="Passed" duration="00:00:02" /></Results><ResultSummary><Counters total="2" executed="2" passed="1" failed="1" /></ResultSummary></TestRun>'
[IO.File]::WriteAllText((Join-Path $fixture 'coverage.cobertura.xml'), $coverage)
[IO.File]::WriteAllText((Join-Path $fixture 'original.trx'), $trx)
$alias = Join-Path $fixture 'trx-attachment'
New-Item -ItemType Directory -Path $alias -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $alias 'coverage.cobertura.xml'), $coverage)
$selected = @(& (Join-Path $PSScriptRoot 'Get-OwnedCoverageReport.ps1') -ResultsDirectory $fixture)
if ($selected.Count -ne 1) { throw 'Byte-identical attachment aliases were not selected as one report.' }
$conflicting = Join-Path $PSScriptRoot '../artifacts/evidence-controls/conflicting-input'
New-Item -ItemType Directory -Path $conflicting -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $conflicting 'coverage.cobertura.xml'), $coverage.Replace('line-rate="0.5"', 'line-rate="0.4"'))
$conflictingAlias = Join-Path $conflicting 'attachment'
New-Item -ItemType Directory -Path $conflictingAlias -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $conflictingAlias 'coverage.cobertura.xml'), $coverage)
$conflictRejected = $false
try {
    & (Join-Path $PSScriptRoot 'Get-OwnedCoverageReport.ps1') -ResultsDirectory $conflicting
} catch {
    if ($_.Exception.Message -cne 'Conflicting full-suite coverage reports.') { throw }
    $conflictRejected = $true
}
if (-not $conflictRejected) { throw 'Different measured reports were combined or selected.' }
& (Join-Path $PSScriptRoot 'Export-CoverageEvidence.ps1') -ResultsDirectory $fixture -OutputDirectory $output
$retained = (Get-ChildItem -LiteralPath $output -File | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join ''
if ($retained -match 'PRIVATE_TOKEN|PRIVATE_SUBJECT') { throw 'Private fixture metadata escaped into exported evidence.' }
[xml] $safeCoverage = Get-Content -LiteralPath (Join-Path $output 'coverage.cobertura.xml') -Raw
if ($safeCoverage.coverage.'line-rate' -ne '0.5' -or @($safeCoverage.coverage.packages.package).Count -ne 4) {
    throw 'Coverage metadata or owned assembly count changed during export.'
}
foreach ($package in $safeCoverage.coverage.packages.package) {
    $expectedClasses = if ($package.name -eq 'Legacy.Maliev.AuthService.Infrastructure') { 1 + $generated.Count } else { 1 }
    if (@($package.classes.class).Count -ne $expectedClasses) { throw 'Generated or production source disappeared during export.' }
    foreach ($class in $package.classes.class) {
        if (@($class.SelectNodes('lines/line')).Count -ne 2 -or $class.lines.line[0].hits -ne '1' -or $class.lines.line[1].hits -ne '0') {
            throw 'Raw reported line hits changed during export.'
        }
    }
}
[xml] $safeTrx = Get-Content -LiteralPath (Join-Path $output 'owned-tests.trx') -Raw
if ($safeTrx.TestRun.ResultSummary.Counters.failed -ne '1' -or $safeTrx.TestRun.ResultSummary.Counters.passed -ne '1' -or
    @($safeTrx.TestRun.Results.UnitTestResult).Count -ne 2 -or $safeTrx.TestRun.Results.UnitTestResult[0].outcome -ne 'Failed' -or
    $safeTrx.TestRun.Results.UnitTestResult[1].outcome -ne 'Passed') { throw 'Test outcomes or counters changed during export.' }
$collisionInput = Join-Path $PSScriptRoot '../artifacts/evidence-controls/collision-input'
New-Item -ItemType Directory -Path $collisionInput -Force | Out-Null
[xml] $collision = $coverage
$apiClasses = @($collision.coverage.packages.package | Where-Object name -eq 'Legacy.Maliev.AuthService.Api')[0].classes
foreach ($origin in @('first', 'second')) {
    $class = $collision.CreateElement('class')
    $class.SetAttribute('name', 'CollidingSource')
    $class.SetAttribute('filename', "/tmp/$origin/Legacy.Maliev.AuthService.Api/Program.cs")
    $class.InnerXml = '<lines><line number="1" hits="1" /></lines>'
    $null = $apiClasses.AppendChild($class)
}
$collision.Save((Join-Path $collisionInput 'coverage.cobertura.xml'))
$rejected = $false
try {
    & (Join-Path $PSScriptRoot 'Export-CoverageEvidence.ps1') -ResultsDirectory $collisionInput -OutputDirectory (Join-Path $PSScriptRoot '../artifacts/evidence-controls/collision-output')
} catch {
    if ($_.Exception.Message -cne 'Coverage source path collision detected.') { throw }
    $rejected = $true
}
if (-not $rejected) { throw 'Distinct physical source paths collapsed without rejection.' }
$unavailable = Join-Path $PSScriptRoot '../artifacts/evidence-controls/unavailable'
& (Join-Path $PSScriptRoot 'Export-CoverageEvidence.ps1') -ResultsDirectory (Join-Path $fixture 'not-present') -OutputDirectory $unavailable
$availability = Get-Content -LiteralPath (Join-Path $unavailable 'availability.json') -Raw | ConvertFrom-Json
if ($availability.CoverageAvailable -or $availability.TestResultsAvailable) { throw 'Missing evidence was represented as available.' }
Write-Output 'PASS: byte-identical attachments accepted/conflicting reports rejected; four assemblies/generated inventory and raw hits/outcomes retained; collisions rejected; private output omitted; missing evidence unavailable.'
