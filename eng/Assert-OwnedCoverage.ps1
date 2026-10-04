param(
    [Parameter(Mandatory = $true)] [string] $CoveragePath,
    [decimal] $MinimumPercent = 80
)

$ErrorActionPreference = 'Stop'
$owned = @('Legacy.Maliev.AuthService.Api', 'Legacy.Maliev.AuthService.Application',
    'Legacy.Maliev.AuthService.Domain', 'Legacy.Maliev.AuthService.Infrastructure')
[xml] $settings = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'coverage.runsettings') -Raw
$configuration = $settings.RunSettings.DataCollectionRunSettings.DataCollectors.DataCollector.Configuration
foreach ($name in @('Exclude', 'ExcludeByAttribute', 'ExcludeByFile')) {
    if (-not [string]::IsNullOrWhiteSpace([string] $configuration.$name)) {
        throw "Raw owned assembly coverage cannot use $name."
    }
}
if ([string] $configuration.SkipAutoProps -ne 'false' -or [string] $configuration.IncludeTestAssembly -ne 'false') {
    throw 'Automatic property accessors must be included and test assemblies omitted.'
}
$expectedInclude = ($owned | ForEach-Object { "[$_]*" }) -join ','
if ([string] $configuration.Include -cne $expectedInclude) {
    throw 'Expected exact four owned production assembly filters.'
}
[xml] $coverage = Get-Content -LiteralPath $CoveragePath -Raw
$packages = @($coverage.coverage.packages.package)
if ($packages.Count -ne $owned.Count -or @($packages | Where-Object { $_.name -notin $owned }).Count -ne 0) {
    throw 'Coverage must contain exactly the four owned production assemblies.'
}
$results = foreach ($assembly in $owned) {
    $matches = @($packages | Where-Object name -eq $assembly)
    if ($matches.Count -ne 1) { throw "Missing or duplicate owned assembly: $assembly" }
    $lines = @{}
    foreach ($class in $matches[0].classes.class) {
        foreach ($line in $class.lines.line) {
            $key = "$($class.filename):$($line.number)"
            $lines[$key] = ([long] $line.hits -gt 0) -or ($lines[$key] -eq $true)
        }
    }
    if ($lines.Count -eq 0) { throw "Coverage unavailable for $assembly; no measured production lines." }
    $covered = @($lines.Values | Where-Object { $_ -eq $true }).Count
    [pscustomobject]@{
        Assembly = $assembly
        Covered = $covered
        Total = $lines.Count
        Percent = [decimal] 100 * $covered / $lines.Count
        Pass = ([decimal] 100 * $covered / $lines.Count -ge $MinimumPercent)
    }
}
$results | ConvertTo-Json
$generatedDirectory = Join-Path $PSScriptRoot '../Legacy.Maliev.AuthService.Infrastructure/Migrations'
$generatedFiles = @(Get-ChildItem -LiteralPath $generatedDirectory -File | Where-Object {
    $_.Name.EndsWith('.Designer.cs', [StringComparison]::Ordinal) -or
    $_.Name.EndsWith('ModelSnapshot.cs', [StringComparison]::Ordinal)
})
if ($generatedFiles.Count -eq 0) { throw 'Expected generated EF source inventory is unavailable.' }
$infrastructure = @($packages | Where-Object name -eq 'Legacy.Maliev.AuthService.Infrastructure')[0]
foreach ($file in $generatedFiles) {
    $suffix = '/Migrations/' + $file.Name
    $measured = @($infrastructure.classes.class | Where-Object {
        ('/' + ([string] $_.filename).Replace('\', '/').TrimStart('/')).EndsWith($suffix, [StringComparison]::Ordinal) -and
        @($_.SelectNodes('lines/line')).Count -gt 0
    })
    if ($measured.Count -eq 0) { throw "Expected measured generated EF source is missing: $($file.Name)" }
}
Write-Output "Reported generated EF sources retained: $($generatedFiles.Count)"
if (@($results | Where-Object { -not $_.Pass }).Count -gt 0) {
    throw "At least one owned production assembly is below $MinimumPercent% raw line coverage."
}
