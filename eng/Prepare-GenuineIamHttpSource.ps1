param([Parameter(Mandatory)][string]$CommittedSourceRoot, [string]$LegacySourceRoot = $CommittedSourceRoot)
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path $PSScriptRoot -Parent
$destinationRoot = Join-Path $repositoryRoot '.genuine-iam-source'
$pins = @(
    [pscustomobject]@{ Repository = 'Maliev.IAMService'; Commit = '4fe6642e5674013de9a3672505aec898fdcae0ed' }
    [pscustomobject]@{ Repository = 'Maliev.Aspire'; Commit = '01d506203763b914e237268a8746f1406423df86' }
    [pscustomobject]@{ Repository = 'Maliev.MessagingContracts'; Commit = '559a00db0c7920a5247fdff60d4476ad23a9a501' }
    [pscustomobject]@{ Repository = 'Legacy.Maliev.AuthService'; Commit = '88e430946465a1df6238e10b815d495d43453411' }
    [pscustomobject]@{ Repository = 'Legacy.Maliev.ServiceDefaults'; Commit = '7b3099bf67d0f17e56cfdb3dcf36541304abaac2' }
    [pscustomobject]@{ Repository = 'Legacy.Maliev.CompatibilityContracts'; Commit = '78e48ffc4ee000df0510cba5e7c7a3c4c4d539d7' }
)
if (Test-Path -LiteralPath $destinationRoot) { throw 'Use a fresh isolated source destination; existing contents will not be overwritten.' }
New-Item -ItemType Directory -Path $destinationRoot | Out-Null
$manifest = @()
foreach ($pin in $pins) {
    $name = $pin.Repository
    $source = Join-Path $CommittedSourceRoot $name
    if ($name.StartsWith('Legacy.')) { $source = Join-Path $LegacySourceRoot $name }
    if ($name -eq 'Legacy.Maliev.AuthService') { $source = $repositoryRoot }
    if ($name -eq 'Legacy.Maliev.ServiceDefaults' -and (Test-Path (Join-Path $CommittedSourceRoot 'GenuineIamDefaults'))) {
        $source = Join-Path $CommittedSourceRoot 'GenuineIamDefaults'
    }
    $archive = Join-Path $destinationRoot "$name.zip"
    & git -C $source archive --format=zip --output=$archive $pin.Commit
    if ($LASTEXITCODE -ne 0) { throw "Committed archive failed for $name" }
    $destination = Join-Path $destinationRoot $name
    Expand-Archive -LiteralPath $archive -DestinationPath $destination
    $manifest += [ordered]@{ repository = $name; commit = $pin.Commit; archiveSha256 = (Get-FileHash -LiteralPath $archive).Hash.ToLowerInvariant() }
    # Retain the immutable archive as provenance; no source-tree transforms occur.
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $destinationRoot 'source-manifest.json') -Encoding utf8
