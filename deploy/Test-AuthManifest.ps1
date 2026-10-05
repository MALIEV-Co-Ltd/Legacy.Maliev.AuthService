[CmdletBinding()]
param([Parameter(Mandatory = $true)][string] $ManifestPath)
$ErrorActionPreference = 'Stop'
try {
    $manifest = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $ManifestPath).Path)
    $images = [regex]::Matches($manifest,
        '(?m)^[ \t]*image: (?<image>[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[a-f0-9]{64})[ \t]*\r?$')
    if ($images.Count -ne 1) { throw 'Expected one immutable image.' }
    $image = $images[0].Groups['image'].Value
    if ($image.EndsWith(('0' * 64), [StringComparison]::Ordinal)) { throw 'Placeholder digest.' }
    $approvedTemplate = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'base/deployment.yaml'))
    $placeholder = 'image: legacy-maliev-auth-service'
    if ([regex]::Matches($approvedTemplate, [regex]::Escape($placeholder)).Count -ne 1 -or
        -not $manifest.Equals($approvedTemplate.Replace($placeholder, "image: $image"), [StringComparison]::Ordinal)) {
        throw 'Only the reviewed template image may change.'
    }
    Write-Output 'PASS: offline Auth manifest boundaries; no deployment performed.'
    exit 0
} catch {
    [Console]::Error.WriteLine('Auth manifest boundary check failed; private details omitted.')
    exit 1
}
