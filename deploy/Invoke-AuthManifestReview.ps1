[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Image,
    [string] $TemplatePath = (Join-Path $PSScriptRoot 'base/deployment.yaml'),
    [string] $ReviewerScript = (Join-Path $PSScriptRoot 'Test-AuthManifest.ps1')
)

# Offline review only: never authenticate, publish, apply or acquire cluster credentials.
$ErrorActionPreference = 'Stop'
$exitCode = 1
$reviewDirectory = $null
try {
    if ($Image -cnotmatch '^[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$' -or
        $Image.EndsWith(('0' * 64), [StringComparison]::Ordinal)) {
        throw 'An immutable, non-placeholder image digest is required.'
    }
    $template = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $TemplatePath).Path)
    $placeholder = 'image: legacy-maliev-auth-service'
    if ([regex]::Matches($template, [regex]::Escape($placeholder)).Count -ne 1) {
        throw 'Expected exactly one Auth image placeholder.'
    }
    $reviewer = (Resolve-Path -LiteralPath $ReviewerScript).Path
    if (-not $reviewer.EndsWith('.ps1', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The offline reviewer must be a PowerShell script.'
    }
    $reviewDirectory = Join-Path ([IO.Path]::GetTempPath()) ('legacy-auth-review-' + [Guid]::NewGuid().ToString('N'))
    if ($IsWindows) {
        [IO.Directory]::CreateDirectory($reviewDirectory) | Out-Null
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = Get-Acl -LiteralPath $reviewDirectory
        $acl.SetAccessRuleProtection($true, $false)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $reviewDirectory -AclObject $acl
    } else {
        [IO.Directory]::CreateDirectory($reviewDirectory, [IO.UnixFileMode]'UserRead, UserWrite, UserExecute') | Out-Null
    }
    $renderedPath = Join-Path $reviewDirectory 'deployment.yaml'
    [IO.File]::WriteAllText($renderedPath, $template.Replace($placeholder, "image: $Image"))
    if (-not $IsWindows) { [IO.File]::SetUnixFileMode($renderedPath, [IO.UnixFileMode]'UserRead, UserWrite') }
    $reviewOutput = & (Join-Path $PSHOME 'pwsh') -NoLogo -NoProfile -NonInteractive -File $reviewer -ManifestPath $renderedPath 2>&1
    $exitCode = $LASTEXITCODE
} catch {
    # Neither configuration values nor child output are reflected in failure messages.
    [Console]::Error.WriteLine('Auth manifest review failed; private details omitted.')
    $exitCode = 1
} finally {
    if ($null -ne $reviewDirectory) {
        $resolved = [IO.Path]::GetFullPath($reviewDirectory)
        $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if ([IO.Path]::GetDirectoryName($resolved).TrimEnd([IO.Path]::DirectorySeparatorChar) -eq
            $temporaryRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) -and
            [IO.Path]::GetFileName($resolved) -match '^legacy-auth-review-[a-f0-9]{32}$') {
            $cleanupFailed = $false
            try { Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction Stop } catch { $cleanupFailed = $true }
            if ($cleanupFailed -or (Test-Path -LiteralPath $resolved)) {
                [Console]::Error.WriteLine('Auth review temporary cleanup failed; private details omitted.')
                if ($exitCode -eq 0) { $exitCode = 1 }
            }
        } else {
            [Console]::Error.WriteLine('Auth review temporary cleanup boundary failed; private details omitted.')
            if ($exitCode -eq 0) { $exitCode = 1 }
        }
    }
}
if ($exitCode -eq 0) { Write-Output 'PASS: offline Auth manifest review; no deployment performed.' }
exit $exitCode
