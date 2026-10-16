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
$trx = '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010" name="PRIVATE_SUBJECT"><Results><UnitTestResult testId="00000000-0000-0000-0000-000000000001" executionId="00000000-0000-0000-0000-000000000003" testName="Auth.Tests.Failed(secret:PRIVATE_TOKEN)" outcome="Failed" duration="00:00:01"><Output><ErrorInfo><Message>PRIVATE_TOKEN</Message><StackTrace>PRIVATE_SUBJECT</StackTrace></ErrorInfo><StdOut>PRIVATE_TOKEN</StdOut></Output></UnitTestResult><UnitTestResult testId="00000000-0000-0000-0000-000000000002" executionId="00000000-0000-0000-0000-000000000004" testName="Auth.Tests.Passed" outcome="Passed" duration="00:00:02" /></Results><TestDefinitions><UnitTest id="00000000-0000-0000-0000-000000000001" name="Auth.Tests.Failed(secret:PRIVATE_TOKEN)"><Execution id="00000000-0000-0000-0000-000000000003" /><TestMethod className="Auth.Tests" name="Failed" codeBase="PRIVATE_SUBJECT" /></UnitTest><UnitTest id="00000000-0000-0000-0000-000000000002" name="Auth.Tests.Passed"><Execution id="00000000-0000-0000-0000-000000000004" /><TestMethod className="Auth.Tests" name="Passed" /></UnitTest></TestDefinitions><TestEntries><TestEntry testId="00000000-0000-0000-0000-000000000001" executionId="00000000-0000-0000-0000-000000000003" /><TestEntry testId="00000000-0000-0000-0000-000000000002" executionId="00000000-0000-0000-0000-000000000004" /></TestEntries><ResultSummary><Counters total="2" executed="2" passed="1" failed="1" /></ResultSummary></TestRun>'
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
$identities = Get-Content -LiteralPath (Join-Path $output 'test-identities.json') -Raw | ConvertFrom-Json
if ($identities.SchemaVersion -ne 2 -or $identities.Cases.Count -ne 2 -or $identities.ParameterValuesRetained) { throw 'Identity schema unavailable or unsafe.' }
if (@($safeTrx.TestRun.TestDefinitions.UnitTest).Count -ne 2 -or @($safeTrx.TestRun.TestEntries.TestEntry).Count -ne 2) { throw 'Definition/entry joins not retained.' }
[xml] $theory = $trx
$theory.TestRun.TestDefinitions.UnitTest[1].TestMethod.name = 'Failed'
$theory.TestRun.TestDefinitions.UnitTest[1].name = 'Auth.Tests.Failed(secret:PRIVATE_OTHER)'
$theory.TestRun.Results.UnitTestResult[1].testName = 'Auth.Tests.Failed(secret:PRIVATE_OTHER)'
$theoryInput = Join-Path $PSScriptRoot '../artifacts/evidence-controls/theory-input'
New-Item -ItemType Directory -Path $theoryInput -Force | Out-Null
$theory.Save((Join-Path $theoryInput 'theory.trx'))
$theoryOutput = Join-Path $PSScriptRoot '../artifacts/evidence-controls/theory-output'
& (Join-Path $PSScriptRoot 'Export-CoverageEvidence.ps1') -ResultsDirectory $theoryInput -OutputDirectory $theoryOutput
$theoryIdentities = Get-Content -LiteralPath (Join-Path $theoryOutput 'test-identities.json') -Raw | ConvertFrom-Json
if (@($theoryIdentities.Cases.DisplayCaseIdentitySha256 | Sort-Object -Unique).Count -ne 2) { throw 'Distinct theory display identities collapsed.' }
if ((Get-Content -LiteralPath (Join-Path $theoryOutput 'test-identities.json') -Raw) -match 'PRIVATE_|secret:') { throw 'Private theory parameters leaked.' }
foreach ($name in @('missing-definition', 'duplicate-definition', 'missing-entry', 'duplicate-result', 'wrong-execution', 'wrong-method', 'wrong-display', 'swapped-theory', 'wrong-total', 'wrong-outcome-counter')) {
    [xml] $invalid = $trx
    switch ($name) {
        'missing-definition' { $null = $invalid.TestRun.TestDefinitions.RemoveChild($invalid.TestRun.TestDefinitions.UnitTest[0]) }
        'duplicate-definition' { $null = $invalid.TestRun.TestDefinitions.AppendChild($invalid.TestRun.TestDefinitions.UnitTest[0].CloneNode($true)) }
        'missing-entry' { $null = $invalid.TestRun.TestEntries.RemoveChild($invalid.TestRun.TestEntries.TestEntry[0]) }
        'duplicate-result' { $null = $invalid.TestRun.Results.AppendChild($invalid.TestRun.Results.UnitTestResult[0].CloneNode($true)) }
        'wrong-execution' { $invalid.TestRun.TestEntries.TestEntry[0].executionId = '00000000-0000-0000-0000-000000000009' }
        'wrong-method' { $invalid.TestRun.TestDefinitions.UnitTest[0].TestMethod.name = 'Other' }
        'wrong-display' { $invalid.TestRun.TestDefinitions.UnitTest[0].name = 'Auth.Tests.Failed(secret:PRIVATE_OTHER)' }
        'swapped-theory' {
            $invalid.TestRun.TestDefinitions.UnitTest[1].TestMethod.name = 'Failed'
            $invalid.TestRun.TestDefinitions.UnitTest[1].name = 'Auth.Tests.Failed(secret:PRIVATE_OTHER)'
            $invalid.TestRun.Results.UnitTestResult[1].testName = 'Auth.Tests.Failed(secret:PRIVATE_OTHER)'
            $firstTestId = $invalid.TestRun.Results.UnitTestResult[0].testId
            $firstExecutionId = $invalid.TestRun.Results.UnitTestResult[0].executionId
            $invalid.TestRun.Results.UnitTestResult[0].testId = $invalid.TestRun.Results.UnitTestResult[1].testId
            $invalid.TestRun.Results.UnitTestResult[0].executionId = $invalid.TestRun.Results.UnitTestResult[1].executionId
            $invalid.TestRun.Results.UnitTestResult[1].testId = $firstTestId
            $invalid.TestRun.Results.UnitTestResult[1].executionId = $firstExecutionId
        }
        'wrong-total' { $invalid.TestRun.ResultSummary.Counters.total = '3' }
        'wrong-outcome-counter' { $invalid.TestRun.ResultSummary.Counters.passed = '2' }
    }
    $invalidInput = Join-Path $PSScriptRoot "../artifacts/evidence-controls/$name"
    New-Item -ItemType Directory -Path $invalidInput -Force | Out-Null
    $invalid.Save((Join-Path $invalidInput 'invalid.trx'))
    $rejected = $false
    try { & (Join-Path $PSScriptRoot 'Export-CoverageEvidence.ps1') -ResultsDirectory $invalidInput -OutputDirectory (Join-Path $invalidInput 'output') }
    catch { if ($_.Exception.Message -notmatch 'test (definition|entry|result|execution|method|display|identity|outcome)|test identity roster') { throw }; $rejected = $true }
    if (-not $rejected) { throw 'Invalid identity join was exported.' }
}
$identityText = Get-Content -LiteralPath (Join-Path $output 'test-identities.json') -Raw
if ($identityText -match 'PRIVATE_|secret:|codeBase|StackTrace|StdOut') { throw 'Private case content leaked.' }
$unavailable = Join-Path $PSScriptRoot '../artifacts/evidence-controls/unavailable'
& (Join-Path $PSScriptRoot 'Export-CoverageEvidence.ps1') -ResultsDirectory (Join-Path $fixture 'not-present') -OutputDirectory $unavailable
$availability = Get-Content -LiteralPath (Join-Path $unavailable 'availability.json') -Raw | ConvertFrom-Json
if ($availability.CoverageAvailable -or $availability.TestResultsAvailable) { throw 'Missing evidence was represented as available.' }
Write-Output 'PASS: byte-identical attachments accepted/conflicting reports rejected; four assemblies/generated inventory and raw hits/outcomes retained; collisions rejected; private output omitted; missing evidence unavailable.'
