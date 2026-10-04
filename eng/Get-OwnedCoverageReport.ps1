param([Parameter(Mandatory = $true)] [string] $ResultsDirectory)
$ErrorActionPreference = 'Stop'
$reports = if (Test-Path -LiteralPath $ResultsDirectory) {
    @(Get-ChildItem -LiteralPath $ResultsDirectory -Recurse -Filter coverage.cobertura.xml)
} else { @() }
if ($reports.Count -eq 0) { return }
$hashes = @($reports | ForEach-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash } | Sort-Object -Unique)
if ($hashes.Count -ne 1) { throw 'Conflicting full-suite coverage reports.' }
# VSTest may copy the same collector attachment into its TRX attachment folder.
# Accept only byte-identical aliases; do not combine separate measured reports.
return $reports[0]
