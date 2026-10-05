$ErrorActionPreference = 'Stop'
$repository = Split-Path $PSScriptRoot -Parent
$wrapper = Join-Path $repository 'deploy/Invoke-AuthManifestReview.ps1'
$template = Join-Path $repository 'deploy/base/deployment.yaml'
$before = (Get-FileHash -LiteralPath $template -Algorithm SHA256).Hash
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('legacy-auth-script-tests-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixture) | Out-Null
$image = 'registry.invalid/legacy/auth@sha256:' + ('a' * 64)
$checks = 0
$faultRenderedPath = $null
try {
    $tokens = $null
    $parseErrors = $null
    foreach ($script in @($wrapper, (Join-Path $repository 'deploy/Test-AuthManifest.ps1'))) {
        [System.Management.Automation.Language.Parser]::ParseFile($script, [ref] $tokens, [ref] $parseErrors) | Out-Null
        if ($parseErrors.Count -ne 0) { throw 'Script parse failed.' }
    }
    $checks++
    & (Join-Path $PSHOME 'pwsh') -NoLogo -NoProfile -NonInteractive -File $wrapper -Image $image
    if ($LASTEXITCODE -ne 0) { throw 'Valid offline review failed.' }
    $checks++
    foreach ($invalid in @('registry.invalid/auth:latest', ('registry.invalid/auth@sha256:' + ('0' * 64)))) {
        & (Join-Path $PSHOME 'pwsh') -NoLogo -NoProfile -NonInteractive -File $wrapper -Image $invalid
        if ($LASTEXITCODE -ne 1) { throw 'Mutable/placeholder image was accepted.' }
        $checks++
    }
    foreach ($mode in @('exit 0', 'exit 23', "throw 'synthetic failure'")) {
        $observedPath = Join-Path $fixture 'observed.txt'
        $reviewer = Join-Path $fixture 'reviewer.ps1'
        $escapedPath = $observedPath.Replace("'", "''")
        $privacyCheck = @'
if ($IsWindows) {
    $acl = Get-Acl -LiteralPath (Split-Path $ManifestPath -Parent)
    if (-not $acl.AreAccessRulesProtected) { exit 42 }
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($access in $acl.Access) {
        if ($access.AccessControlType -eq 'Allow' -and
            $access.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -ne $user) { exit 42 }
    }
} else {
    if ([IO.File]::GetUnixFileMode((Split-Path $ManifestPath -Parent)) -ne
        [IO.UnixFileMode]'UserRead, UserWrite, UserExecute' -or
        [IO.File]::GetUnixFileMode($ManifestPath) -ne [IO.UnixFileMode]'UserRead, UserWrite') { exit 42 }
}
'@
        [IO.File]::WriteAllText($reviewer, "param([string]`$ManifestPath)`n[IO.File]::WriteAllText('$escapedPath', `$ManifestPath)`n$privacyCheck`nWrite-Output 'synthetic private reviewer output'`n$mode`n")
        $observedOutput = & (Join-Path $PSHOME 'pwsh') -NoLogo -NoProfile -NonInteractive -File $wrapper -Image $image -ReviewerScript $reviewer 2>&1
        $expected = if ($mode -eq 'exit 23') { 23 } elseif ($mode -eq 'exit 0') { 0 } else { 1 }
        if ($LASTEXITCODE -ne $expected) { throw 'Child process failure did not propagate.' }
        if (($observedOutput | Out-String) -match 'synthetic private reviewer output|synthetic failure') {
            throw 'Child private output was exposed.'
        }
        $rendered = [IO.File]::ReadAllText($observedPath)
        if (Test-Path -LiteralPath (Split-Path $rendered -Parent)) { throw 'Throwaway rendering survived failure.' }
        $checks++
    }
    $badTemplate = Join-Path $fixture 'invalid.yaml'
    foreach ($invalidTemplate in @(
        [IO.File]::ReadAllText($template).Replace('namespace: maliev-legacy', 'namespace: unsupported'),
        [IO.File]::ReadAllText($template).Replace('replicas: 1', 'replicas: 10'),
        ([IO.File]::ReadAllText($template).Replace('namespace: maliev-legacy', 'namespace: unsupported') + "`n# namespace: maliev-legacy`n"),
        ([IO.File]::ReadAllText($template) + "`n  replicas: 1`n"),
        ([IO.File]::ReadAllText($template) + "`n          image: registry.invalid/another@sha256:$('b' * 64)`n"),
        ([IO.File]::ReadAllText($template) + [char] 0),
        ([IO.File]::ReadAllText($template) + [char] 0x200B),
        ([IO.File]::ReadAllText($template) + "`n          value: synthetic-inline-configuration`n"),
        ([IO.File]::ReadAllText($template) + "`n      nodeSelector: synthetic-node`n"))) {
        [IO.File]::WriteAllText($badTemplate, $invalidTemplate)
        & (Join-Path $PSHOME 'pwsh') -NoLogo -NoProfile -NonInteractive -File $wrapper -Image $image -TemplatePath $badTemplate
        if ($LASTEXITCODE -ne 1) { throw 'Unexpected manifest configuration was accepted.' }
        $checks++
    }
    [IO.File]::WriteAllText($badTemplate, 'kind: Deployment')
    & (Join-Path $PSHOME 'pwsh') -NoLogo -NoProfile -NonInteractive -File $wrapper -Image $image -TemplatePath $badTemplate
    if ($LASTEXITCODE -ne 1) { throw 'Missing image placeholder was accepted.' }
    $checks++
    if ((Get-FileHash -LiteralPath $template -Algorithm SHA256).Hash -ne $before) { throw 'Tracked manifest changed.' }
    $checks++
    $faultObservation = Join-Path $fixture 'cleanup-fault-path.txt'
    $faultReviewer = Join-Path $fixture 'cleanup-fault-reviewer.ps1'
    $escapedObservation = $faultObservation.Replace("'", "''")
    $faultWrapper = Join-Path $fixture 'cleanup-fault-wrapper.ps1'
    $injection = @'
function Remove-Item {
    [CmdletBinding()]
    param([string] $LiteralPath, [switch] $Recurse, [switch] $Force)
    throw 'synthetic cleanup dependency failure'
}
'@
    $wrapperText = [IO.File]::ReadAllText($wrapper)
    $marker = '$' + "ErrorActionPreference = 'Stop'"
    if ([regex]::Matches($wrapperText, [regex]::Escape($marker)).Count -ne 1) { throw 'Fault injection boundary changed.' }
    [IO.File]::WriteAllText($faultWrapper, $wrapperText.Replace($marker, "$marker`n$injection"))
    [IO.File]::WriteAllText($faultReviewer, "param([string]`$ManifestPath)`n[IO.File]::WriteAllText('$escapedObservation', `$ManifestPath)`nexit 0`n")
    $faultOutput = & (Join-Path $PSHOME 'pwsh') -NoLogo -NoProfile -NonInteractive -File $faultWrapper -Image $image -TemplatePath $template -ReviewerScript $faultReviewer 2>&1
    $faultStatus = $LASTEXITCODE
    $faultRenderedPath = [IO.File]::ReadAllText($faultObservation)
    if ($faultStatus -ne 1 -or ($faultOutput | Out-String) -notmatch 'temporary cleanup failed' -or
        ($faultOutput | Out-String) -match 'PASS:|synthetic cleanup dependency failure' -or -not (Test-Path -LiteralPath $faultRenderedPath)) {
        throw 'Injected cleanup dependency fault was not reported as failure.'
    }
    $checks++
    Write-Output "PASS: $checks offline script checks; native exit propagation, failed-render cleanup, private configuration boundaries and template byte identity."
} finally {
    if ($null -ne $faultRenderedPath) {
        $faultDirectory = [IO.Path]::GetFullPath((Split-Path $faultRenderedPath -Parent))
        if ([IO.Path]::GetDirectoryName($faultDirectory).TrimEnd([IO.Path]::DirectorySeparatorChar) -eq
            [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) -and
            [IO.Path]::GetFileName($faultDirectory) -match '^legacy-auth-review-[a-f0-9]{32}$') {
            if (Test-Path -LiteralPath $faultDirectory) { Remove-Item -LiteralPath $faultDirectory -Recurse -Force }
        }
    }
    $resolved = [IO.Path]::GetFullPath($fixture)
    if ([IO.Path]::GetDirectoryName($resolved).TrimEnd([IO.Path]::DirectorySeparatorChar) -eq
        [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) -and
        [IO.Path]::GetFileName($resolved) -match '^legacy-auth-script-tests-[a-f0-9]{32}$') {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
# GitHub's pwsh wrapper inspects LASTEXITCODE, including deliberate negative controls.
exit 0
