param([string] $GatePath = (Join-Path $PSScriptRoot 'Assert-OwnedCoverage.ps1'))

$ErrorActionPreference = 'Stop'
$owned = @('Legacy.Maliev.AuthService.Api', 'Legacy.Maliev.AuthService.Application',
    'Legacy.Maliev.AuthService.Domain', 'Legacy.Maliev.AuthService.Infrastructure')
$fixtureDirectory = Join-Path $PSScriptRoot '../artifacts/coverage-gate-controls'
New-Item -ItemType Directory -Path $fixtureDirectory -Force | Out-Null
$generatedNames = @(Get-ChildItem -LiteralPath (Join-Path (Split-Path -Parent $GatePath) '../Legacy.Maliev.AuthService.Infrastructure/Migrations') -File |
    Where-Object { $_.Name -match '(\.Designer|ModelSnapshot)\.cs$' } | Select-Object -ExpandProperty Name)

function Write-Fixture([string] $Name, [string[]] $Assemblies, [string] $LowAssembly, [switch] $DuplicateLines, [switch] $EmptyLines, [switch] $OmitGenerated, [switch] $EmptyGeneratedLines) {
    $packages = foreach ($assembly in $Assemblies) {
        $hits = if ($assembly -eq $LowAssembly) { 0 } else { 1 }
        $duplicate = if ($DuplicateLines) {
            '<class name="Duplicate" filename="production.cs"><lines><line number="1" hits="0" /></lines></class>'
        } else { '' }
        $rawLines = if ($EmptyLines) { '' } else { '<line number="1" hits="{0}" />' -f $hits }
        $generatedClasses = if ($assembly -eq 'Legacy.Maliev.AuthService.Infrastructure' -and -not $OmitGenerated) {
            $generatedLines = if ($EmptyGeneratedLines) { '' } else { $rawLines }
            ($generatedNames | ForEach-Object {
                '<class name="Generated" filename="Migrations/{0}"><lines>{1}</lines></class>' -f $_, $generatedLines
            }) -join ''
        } else { '' }
        '<package name="{0}" line-rate="1"><classes><class name="Production" filename="production.cs"><lines>{1}</lines></class>{2}{3}</classes></package>' -f $assembly, $rawLines, $duplicate, $generatedClasses
    }
    $path = Join-Path $fixtureDirectory "$Name.xml"
    [IO.File]::WriteAllText($path, '<coverage line-rate="1"><packages>' + ($packages -join '') + '</packages></coverage>')
    return $path
}

function Assert-Rejected([string] $Path, [string] $ExpectedMessage) {
    $rejected = $false
    try { & $GatePath -CoveragePath $Path | Out-Null }
    catch {
        if ($_.Exception.Message -notlike "*$ExpectedMessage*") { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw "Gate accepted invalid fixture: $Path" }
}

$positive = Write-Fixture -Name 'positive-union' -Assemblies $owned -DuplicateLines
$output = @(& $GatePath -CoveragePath $positive)
$results = $output[0] | ConvertFrom-Json
if ($results.Count -ne 4 -or @($results | Where-Object {
    $expected = if ($_.Assembly -eq 'Legacy.Maliev.AuthService.Infrastructure') { 1 + $generatedNames.Count } else { 1 }
    $_.Total -ne $expected -or $_.Covered -ne $expected -or $_.Percent -ne 100
}).Count -ne 0) {
    throw 'Duplicate class lines inflated or reduced the source-line union.'
}
Assert-Rejected (Write-Fixture -Name 'inflated-metadata' -Assemblies $owned -LowAssembly $owned[2]) 'below 80%'
Assert-Rejected (Write-Fixture -Name 'missing-assembly' -Assemblies $owned[0..2]) 'exactly the four'
Assert-Rejected (Write-Fixture -Name 'foreign-assembly' -Assemblies @($owned[0..2] + 'Foreign.Production')) 'exactly the four'
Assert-Rejected (Write-Fixture -Name 'duplicate-assembly' -Assemblies @($owned[0..2] + $owned[0])) 'Missing or duplicate'
Assert-Rejected (Write-Fixture -Name 'unavailable-lines' -Assemblies $owned -EmptyLines) 'Coverage unavailable'
Assert-Rejected (Write-Fixture -Name 'missing-generated-source' -Assemblies $owned -OmitGenerated) 'Expected measured generated EF source is missing'
Assert-Rejected (Write-Fixture -Name 'empty-generated-source' -Assemblies $owned -EmptyGeneratedLines) 'Expected measured generated EF source is missing'
Write-Output 'PASS: source-line union/generated-source positive control and seven invalid-report negative controls.'
