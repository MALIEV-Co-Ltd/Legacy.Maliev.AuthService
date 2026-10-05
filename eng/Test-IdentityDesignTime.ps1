param([string] $OutputDirectory = 'artifacts/coverage-evidence/identity-design-time')

$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('auth-design-' + [Guid]::NewGuid().ToString('N'))
$toolVersion = '10.0.12'
$records = [Collections.Generic.List[object]]::new()
$phase = 'ToolInstallation'
$installation = $null
$version = $null
$rsa = [Security.Cryptography.RSA]::Create(2048)
New-Item -ItemType Directory -Path $temporary -Force | Out-Null

# Child configuration is allowlisted; inherited application settings and secrets are absent.
$childEnvironment = @{}
foreach ($name in @('PATH', 'HOME', 'DOTNET_ROOT', 'DOTNET_ROOT_X64', 'TMPDIR')) {
    $value = [Environment]::GetEnvironmentVariable($name)
    if ($value) { $childEnvironment[$name] = $value }
}
$childEnvironment['GITHUB_ACTIONS'] = 'false'
$childEnvironment['UseLocalMalievDependencies'] = 'true'
$childEnvironment['MalievWorkspaceRoot'] = Join-Path $repository '.dependencies'
$childEnvironment['DOTNET_ENVIRONMENT'] = 'Production'
$childEnvironment['ASPNETCORE_ENVIRONMENT'] = 'Production'
$childEnvironment['CORS__AllowedOrigins__0'] = 'https://design-only.invalid'
$childEnvironment['Jwt__Issuer'] = 'https://design-only.invalid'
$childEnvironment['Jwt__Audience'] = 'design-only'
$childEnvironment['Jwt__KeyId'] = 'design-only'
$childEnvironment['Jwt__PrivateKeyPem'] = $rsa.ExportPkcs8PrivateKeyPem()
$childEnvironment['EmployeeRecovery__Enabled'] = 'false'
foreach ($kind in @('CustomerIdentity', 'EmployeeIdentity', 'RefreshSessions')) {
    $childEnvironment['ConnectionStrings__' + $kind] = "Host=127.0.0.1;Port=1;Database=legacy_auth_design_$kind;Username=design_only;Timeout=1;Command Timeout=1;Pooling=false"
}

function Invoke-PrivateTool([string] $Executable, [string[]] $Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.WorkingDirectory = $repository
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Environment.Clear()
    foreach ($entry in $childEnvironment.GetEnumerator()) { $start.Environment[$entry.Key] = $entry.Value }
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(60000)) {
            $process.Kill($true)
            $process.WaitForExit()
            return @{ ExitCode = -1; TimedOut = $true; Output = ''; Error = '' }
        }
        return @{ ExitCode = $process.ExitCode; TimedOut = $false; Output = $stdout.GetAwaiter().GetResult(); Error = $stderr.GetAwaiter().GetResult() }
    } finally { $process.Dispose() }
}

try {
    $toolPath = Join-Path $temporary 'tools'
    $installation = Invoke-PrivateTool 'dotnet' @('tool', 'install', 'dotnet-ef', '--version', $toolVersion, '--tool-path', $toolPath)
    if ($installation.ExitCode -ne 0) { throw 'Pinned design-time tool installation failed; raw output withheld.' }
    $executable = Join-Path $toolPath 'dotnet-ef'
    $phase = 'ToolVersion'
    $version = Invoke-PrivateTool $executable @('--version')
    if ($version.ExitCode -ne 0 -or $version.Output.Trim() -notmatch '10\.0\.12$') { throw 'Design-time tool version mismatch.' }
    $contexts = @(
        @{ Name = 'CustomerIdentityDbContext'; Database = 'legacy_auth_design_CustomerIdentity'; Source = 'tcp://127.0.0.1:1'; Path = 'normal-host' },
        @{ Name = 'EmployeeIdentityDbContext'; Database = 'legacy_auth_design_EmployeeIdentity'; Source = 'tcp://127.0.0.1:1'; Path = 'normal-host' },
        @{ Name = 'RefreshSessionDbContext'; Database = 'legacy_auth_design'; Source = 'tcp://localhost:5432'; Path = 'existing-factory' }
    )
    foreach ($context in $contexts) {
        $phase = $context.Name
        $qualified = 'Legacy.Maliev.AuthService.Infrastructure.' + $context.Name
        $common = @('--project', 'Legacy.Maliev.AuthService.Infrastructure', '--startup-project', 'Legacy.Maliev.AuthService.Api', '--configuration', 'Release', '--no-build', '--context', $qualified, '--no-color')
        $info = Invoke-PrivateTool $executable (@('dbcontext', 'info', '--json') + $common)
        $metadata = $null
        try {
            # EF emits host diagnostics before its JSON. Parse only the final metadata object.
            $startIndex = $info.Output.LastIndexOf("`n{")
            $json = if ($startIndex -ge 0) { $info.Output.Substring($startIndex + 1) } else { $info.Output }
            $metadata = $json | ConvertFrom-Json -ErrorAction Stop
        } catch { $metadata = $null }
        $infoPassed = $info.ExitCode -eq 0 -and $null -ne $metadata -and
            $metadata.type -eq $qualified -and $metadata.providerName -eq 'Npgsql.EntityFrameworkCore.PostgreSQL' -and
            $metadata.databaseName -eq $context.Database -and $metadata.dataSource -eq $context.Source
        $sqlPath = Join-Path $temporary ($context.Name + '.sql')
        $script = Invoke-PrivateTool $executable (@('migrations', 'script', '--idempotent', '--output', $sqlPath) + $common)
        $size = if (Test-Path -LiteralPath $sqlPath) { (Get-Item -LiteralPath $sqlPath).Length } else { 0 }
        $hash = if ($size -gt 0) { (Get-FileHash -LiteralPath $sqlPath -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        $records.Add([ordered]@{
            Context = $qualified; CreationPath = $context.Path; ToolVersion = $toolVersion
            InfoExit = $info.ExitCode; InfoTimedOut = $info.TimedOut; InfoPassed = $infoPassed
            HostAbortReported = ($info.Output + $info.Error).Contains('HostAbortedException', [StringComparison]::Ordinal)
            ContextCreationFailureReported = ($info.Output + $info.Error).Contains('Unable to create', [StringComparison]::Ordinal)
            Provider = if ($infoPassed) { 'Npgsql.EntityFrameworkCore.PostgreSQL' } else { $null }
            SyntheticDatabase = $context.Database; SyntheticDataSource = $context.Source
            ScriptExit = $script.ExitCode; ScriptTimedOut = $script.TimedOut
            ScriptPassed = $script.ExitCode -eq 0 -and $size -gt 0
            ScriptBytes = $size; ScriptSha256 = $hash
        })
    }
    $phase = 'ContextAssertions'
    if (@($records | Where-Object { -not $_.InfoPassed -or -not $_.ScriptPassed }).Count -gt 0) {
        throw 'Offline design-time discovery or script generation failed; inspect allowlisted discovery.json.'
    }
    $phase = 'Passed'
    Write-Output 'Offline design-time context discovery and SQL generation passed: 3 contexts, no database commands.'
} finally {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    [ordered]@{
        Phase = $phase; ToolVersion = $toolVersion
        InstallationExit = if ($installation) { $installation.ExitCode } else { $null }
        InstallationTimedOut = if ($installation) { $installation.TimedOut } else { $null }
        VersionExit = if ($version) { $version.ExitCode } else { $null }
        Contexts = @($records.ToArray()); RawOutputRetained = $false; SqlRetained = $false; DatabaseCommandsExecuted = $false
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'discovery.json') -Encoding utf8
    $rsa.Dispose()
    $childEnvironment.Clear()
    $resolvedTemporary = [IO.Path]::GetFullPath($temporary)
    if (-not $resolvedTemporary.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::Ordinal)) { throw 'Temporary cleanup path outside expected root.' }
    Remove-Item -LiteralPath $resolvedTemporary -Recurse -Force
}
