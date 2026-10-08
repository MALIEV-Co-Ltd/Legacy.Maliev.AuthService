[CmdletBinding()]
param([Parameter(Mandatory)][string]$SourceCheckouts,
      [Parameter(Mandatory)][string]$Destination,
      [Parameter(Mandatory)][string]$ReceiptPath)
$ErrorActionPreference = 'Stop'
# This source materializer runs only inside the externally verified capped SDK unit.
if (-not $IsLinux -or -not $env:FINANCIAL_OWNED_CGROUP -or
    -not ([IO.File]::ReadAllText('/proc/self/cgroup').Contains($env:FINANCIAL_OWNED_CGROUP + '/'))) {
    throw 'The owned Linux SDK cgroup is required before source materialization.'
}
$inputs = Join-Path $PSScriptRoot 'inputs'
$inputHashes = [ordered]@{
    'auth-source-manifest.json' = '6541dcdbba89175b556e50004902c681361f21cbae003fe909f5e60ace8dd81a'
    'auth-source.patch' = '4f46a141a47f7c85fbefbcdf93872f2b80d28a5cbe4e2e1dd16a34e54673e1ce'
    'accounting-source.patch' = 'fd8abaca9cc21be74546a7880f8421a2f22cbf1873ee3c44fb5ef3047fb5fc50'
    'quotation-catalogue.json' = '7a7ff1e9122be3ff8f914390d63b447a50e25f5f03f41e75e7609eed499ed34d'
}
foreach ($name in $inputHashes.Keys) {
    $path = Join-Path $inputs $name
    if ((Get-Item -LiteralPath $path).Length -gt 1048576 -or
        (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant() -ne $inputHashes[$name]) {
        throw 'Immutable input admission failed; details redacted.'
    }
}
$auth = Get-Content -Raw -LiteralPath (Join-Path $inputs 'auth-source-manifest.json') | ConvertFrom-Json
$encodedHashes = [ordered]@{
    'accounting-source-manifest'='cc314f03b3cee337ddd2ea40609a7c40d664a8e8177eae82b6a87b353590d0a2'
    'accounting-catalogue'='7ef027009178f40ec7d21645d4fb15dea39e779c4a5929edb8cde10a46074ef7'
    'accounting-container-control'='e50457fc02634024ec5b9fb37328f008139a06dd806c08dbbf0a63ed8f1ac129'
    'accounting-hosted-manifest'='d007f0981514a895cd7bf490cce4c2293d3c032720180cfd984adf1f9d654eac'
    'accounting-hosted-run'='09813ade8642e0c00dc8feed850fb1996911d0230b1b49c18f28cc224572e23d'
    'accounting-hosted-verify'='3e48f50cadabf216020f10f426d7b837c1f1946500a643470e3d7ca71c5da4cd'
    'accounting-hosted-controls'='41436ec506045155a1103e0adb8ee591e43a21f358fbab957dad46d54f9618d6'
}
$decoded = @{}
foreach ($name in $encodedHashes.Keys) {
    $encodedPath = Join-Path $inputs "$name.bytes.b64"
    if ((Get-Item -LiteralPath $encodedPath).Length -gt 1048576) { throw 'Encoded input exceeds bounds.' }
    $decoded[$name] = [Convert]::FromBase64String([IO.File]::ReadAllText($encodedPath).Trim())
    if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($decoded[$name])).ToLowerInvariant() -cne $encodedHashes[$name]) { throw 'Exact encoded raw owner bytes differ.' }
}
$accounting = [Text.Encoding]::UTF8.GetString($decoded['accounting-source-manifest']) | ConvertFrom-Json
if ($auth.files.Count -ne 17 -or $accounting.files.Count -ne 49) { throw 'Source inventory differs.' }
$control = $accounting.files | Where-Object path -eq 'tooling/Accounting.PermissionRegistration.Tests/OwnedFinancialPrincipalTestContainers.cs'
if (@($control).Count -ne 1 -or
    $encodedHashes['accounting-container-control'] -cne $control.sha256) {
    throw 'Immutable Accounting raw control postimage differs.'
}
$destinationPath = [IO.Path]::GetFullPath($Destination)
if (Test-Path -LiteralPath $destinationPath) { throw 'Use a fresh exact owned destination; no overwrite or reset.' }
New-Item -ItemType Directory -Path $destinationPath | Out-Null
$rawInputs = Join-Path $destinationPath '.source-inputs'
[IO.Directory]::CreateDirectory($rawInputs) | Out-Null
[IO.File]::WriteAllBytes((Join-Path $rawInputs 'accounting-source-manifest.json'), $decoded['accounting-source-manifest'])
[IO.File]::WriteAllBytes((Join-Path $rawInputs 'accounting-hosted-manifest.json'), $decoded['accounting-hosted-manifest'])
$checkouts = [IO.Path]::GetFullPath($SourceCheckouts)
$pins = @(
    @{name='Legacy.Maliev.AuthService'; commit='85a00d4bb54cf95199ee67dfd97d2b168233ff68'; destination='Auth'}
    @{name='Legacy.Maliev.AccountingService'; commit='668f2cb63c64b911db776329b983dd91944b3b8c'; destination='Auth/.accounting-financial-source'}
    @{name='Maliev.IAMService'; commit='4fe6642e5674013de9a3672505aec898fdcae0ed'; destination='Auth/.genuine-iam-source/Maliev.IAMService'}
    @{name='Maliev.Aspire'; commit='01d506203763b914e237268a8746f1406423df86'; destination='Auth/.genuine-iam-source/Maliev.Aspire'}
    @{name='Maliev.MessagingContracts'; commit='559a00db0c7920a5247fdff60d4476ad23a9a501'; destination='Auth/.genuine-iam-source/Maliev.MessagingContracts'}
    @{name='Legacy.Maliev.ServiceDefaults'; commit='7b3099bf67d0f17e56cfdb3dcf36541304abaac2'; destination='Auth/.genuine-iam-source/Legacy.Maliev.ServiceDefaults'}
    @{name='Legacy.Maliev.CompatibilityContracts'; commit='78e48ffc4ee000df0510cba5e7c7a3c4c4d539d7'; destination='Auth/.genuine-iam-source/Legacy.Maliev.CompatibilityContracts'}
    @{name='Legacy.Maliev.CustomerService'; commit='4eedecd81d1d8dcb4f38d8f76e51e7e9cb2110be'; destination='Auth/.genuine-iam-source/Legacy.Maliev.CustomerService'}
    @{name='Legacy.Maliev.AuthService'; source='Archived.Legacy.Maliev.AuthService'; commit='88e430946465a1df6238e10b815d495d43453411'; destination='Auth/.genuine-iam-source/Legacy.Maliev.AuthService'}
)
$archives = @()
foreach ($pin in $pins) {
    $checkoutName = if ($pin.source) { $pin.source } else { $pin.name }
    $source = Join-Path $checkouts $checkoutName
    $object = & git -C $source rev-parse "$($pin.commit)^{commit}"
    if ($LASTEXITCODE -ne 0 -or $object -ne $pin.commit) { throw 'Exact committed source object unavailable.' }
    $archive = Join-Path $destinationPath "$($pin.name)-$($pin.commit).zip"
    & git -C $source archive --format=zip --output=$archive $pin.commit
    if ($LASTEXITCODE -ne 0) { throw 'Exact committed archive failed.' }
    $target = Join-Path $destinationPath $pin.destination
    if (Test-Path -LiteralPath $target) { throw 'Exact archive destination already exists.' }
    [IO.Directory]::CreateDirectory($target) | Out-Null
    # Reject traversal and archive links before any extracted file is written.
    $zip = [IO.Compression.ZipFile]::OpenRead($archive)
    $entryModes = @()
    try {
        foreach ($entry in $zip.Entries) {
            $path = [IO.Path]::GetFullPath((Join-Path $target $entry.FullName))
            if (-not $path.StartsWith([IO.Path]::GetFullPath($target).TrimEnd('/') + '/', [StringComparison]::Ordinal) -or
                (($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000) { throw 'Unsafe archive entry refused.' }
            if (-not $entry.FullName.EndsWith('/')) {
                $entryModes += @{path=$path;mode=(($entry.ExternalAttributes -shr 16) -band 0x1FF)}
            }
        }
    } finally { $zip.Dispose() }
    [IO.Compression.ZipFile]::ExtractToDirectory($archive, $target)
    foreach ($entry in $entryModes) {
        if ($entry.mode -ne 0) { [IO.File]::SetUnixFileMode($entry.path, [IO.UnixFileMode]$entry.mode) }
    }
    # Preserve REAL existing committed-object identity for dependency/source
    # validators, without manufacturing a new candidate commit. A detached bare
    # metadata clone is made only inside this fresh disposable archive copy.
    $head = & git -C $source rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $head -cne $pin.commit) { throw 'Checkout HEAD is not the exact archive source pin.' }
    & git clone --bare --no-hardlinks --local $source (Join-Path $target '.git')
    if ($LASTEXITCODE -ne 0) { throw 'Exact committed metadata copy failed.' }
    & git -C $target config core.bare false
    if ($LASTEXITCODE -ne 0) { throw 'Disposable metadata configuration failed.' }
    & git -C $target read-tree $pin.commit
    if ($LASTEXITCODE -ne 0) { throw 'Exact committed index materialization failed.' }
    $actualHead = & git -C $target rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $actualHead -cne $pin.commit) { throw 'Copied committed-object identity differs.' }
    $archives += [ordered]@{repository=$pin.name;commit=$pin.commit;relativeDestination=$pin.destination;
        archiveSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()}
}
$authRoot = Join-Path $destinationPath 'Auth'
$accountingRoot = Join-Path $authRoot '.accounting-financial-source'
foreach ($item in @(@{root=$authRoot;patch='auth-source.patch'},@{root=$accountingRoot;patch='accounting-source.patch'})) {
    $patch = Join-Path $inputs $item.patch
    & git -C $item.root apply --check $patch
    if ($LASTEXITCODE -ne 0) { throw 'Exact patch preimage is inapplicable.' }
    & git -C $item.root apply $patch
    if ($LASTEXITCODE -ne 0) { throw 'Exact patch application failed.' }
}
# git archive/apply preserves committed LF, while these TWO frozen raw owner postimages are CRLF.
# Restore only their independently sealed raw bytes, then verify every one of the 49 postimages.
[IO.File]::WriteAllBytes((Join-Path $accountingRoot 'provisioning/iam/accounting-financial-ownership.json'),
    $decoded['accounting-catalogue'])
[IO.File]::WriteAllBytes((Join-Path $accountingRoot 'tooling/Accounting.PermissionRegistration.Tests/OwnedFinancialPrincipalTestContainers.cs'),
    $decoded['accounting-container-control'])
$toolRoot = Join-Path $accountingRoot 'eng/financial-qualification'
if (Test-Path -LiteralPath $toolRoot) { throw 'Tool overlay would overwrite an unreviewed preimage.' }
[IO.Directory]::CreateDirectory($toolRoot) | Out-Null
foreach ($item in @(@{name='run.sh';input='accounting-hosted-run'}, @{name='verify.py';input='accounting-hosted-verify'}, @{name='test_verify.py';input='accounting-hosted-controls'})) {
    [IO.File]::WriteAllBytes((Join-Path $toolRoot $item.name), $decoded[$item.input])
}
$hosted = [Text.Encoding]::UTF8.GetString($decoded['accounting-hosted-manifest']) | ConvertFrom-Json
if ($hosted.fileCount -ne 52 -or $hosted.files.Count -ne 52) { throw 'Exact hosted Accounting 52-file cohort required.' }
foreach ($group in @(@{root=$authRoot;manifest=$auth},@{root=$accountingRoot;manifest=$accounting},@{root=$accountingRoot;manifest=$hosted})) {
    foreach ($file in $group.manifest.files) {
        $path = [IO.Path]::GetFullPath((Join-Path $group.root $file.path))
        if (-not $path.StartsWith([IO.Path]::GetFullPath($group.root).TrimEnd('/') + '/', [StringComparison]::Ordinal) -or
            (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant() -ne $file.sha256) {
            throw 'Exact materialized postimage seal failed.'
        }
    }
}
$receipt = [ordered]@{
    schemaVersion=1; authenticatingExecutionCommit=$env:GITHUB_SHA; candidateAuthCommit=$null
    authBase='85a00d4bb54cf95199ee67dfd97d2b168233ff68'; authManifest=$inputHashes['auth-source-manifest.json']
    accountingBase='668f2cb63c64b911db776329b983dd91944b3b8c'; accountingManifest=$encodedHashes['accounting-source-manifest']
    authPaths=17;accountingPaths=49;accountingHostedPaths=52;accountingHostedManifest=$encodedHashes['accounting-hosted-manifest'];postimageMismatches=0;rawCrLfRestorations=2;archives=$archives
    oldAuth88EquivalentToCurrent=$false; wholeBusinessQualified=$false;completePrepareQualified=$false
}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($ReceiptPath), ($receipt | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
Write-Output 'Exact source materialization completed; native qualification has not been inferred.'
