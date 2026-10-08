[CmdletBinding()]
param([Parameter(Mandatory)][string]$SourceCheckouts,
      [Parameter(Mandatory)][string]$Destination,
      [Parameter(Mandatory)][string]$Receipts,
      [Parameter(Mandatory)][ValidateSet('auth','accounting')][string]$Lane)
$ErrorActionPreference = 'Stop'
if (-not $IsLinux -or $env:GITHUB_ACTIONS -ne 'false' -or -not $env:FINANCIAL_OWNED_CGROUP) {
    throw 'Exact hosted local-dependency admission required.'
}
& (Join-Path $PSScriptRoot 'Materialize-FinancialIamSource.ps1') -SourceCheckouts $SourceCheckouts -Destination $Destination -ReceiptPath (Join-Path $Receipts 'materialization.json')
$auth = Join-Path $Destination 'Auth'
$dependencies = Join-Path $auth '.genuine-iam-source'
$accounting = Join-Path $auth '.accounting-financial-source'
$env:MalievWorkspaceRoot = $dependencies
$env:UseLocalMalievDependencies = 'true'
$env:AccountingSourceRoot = $accounting
$env:ORDINARY_FINANCIAL_QUOTATION_CATALOGUE_PATH = Join-Path $PSScriptRoot 'inputs/quotation-catalogue.json'
$env:ORDINARY_FINANCIAL_ACCOUNTING_SOURCE_MANIFEST = Join-Path $Destination '.source-inputs/accounting-source-manifest.json'
$env:ORDINARY_FINANCIAL_RESOURCE_LEDGER = Join-Path $Receipts 'ordinary-owned-resources'
$env:GENUINE_IAM_RESOURCE_LEDGER = Join-Path $Receipts 'genuine-owned-resources'
$results = Join-Path $Receipts 'trx'
[IO.Directory]::CreateDirectory($results) | Out-Null
$common = @('--configuration', 'Release', '-p:GITHUB_ACTIONS=false', '-p:UseLocalMalievDependencies=true', "-p:MalievWorkspaceRoot=$dependencies", "-p:AccountingSourceRoot=$accounting")
function Invoke-Dotnet([string[]]$Arguments) {
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Native qualification command failed; no later phase is accepted.' }
}
Push-Location $auth
try {
    $workflowSource = Join-Path $SourceCheckouts 'Legacy.Maliev.Workflows'
    $workflowCommit = & git -C $workflowSource rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $workflowCommit -cne 'e3a6093324a24968876782153286f52db8b29fd8') { throw 'Exact trusted scanner source required.' }
    # A fresh disposable index permits the UNCHANGED accepted tracked-resource
    # scanner to enumerate the materialized candidate; no original Git state is
    # changed and no commit is fabricated.
    & git init --quiet
    if ($LASTEXITCODE -ne 0) { throw 'Disposable candidate index failed.' }
    & git add -- .
    if ($LASTEXITCODE -ne 0) { throw 'Disposable candidate enumeration failed.' }
    foreach ($root in @($auth,$accounting)) {
        & git -C $root add -- .
        if($LASTEXITCODE -ne 0){throw 'Disposable source enumeration failed.'}
        foreach ($scanner in @('Invoke-JwtSigningResourceScan.ps1', 'Invoke-CurrentTreeCredentialScan.ps1')) {
            & pwsh -NoProfile -File (Join-Path $workflowSource "scripts/$scanner") -RepositoryPath $root
            if ($LASTEXITCODE -ne 0) { throw 'Accepted credential/resource scanner failed.' }
        }
    }
    $env:GOBIN = Join-Path $Destination 'owned-tools'
    [IO.Directory]::CreateDirectory($env:GOBIN) | Out-Null
    & go install github.com/zricethezav/gitleaks/v8@6eaad039603a4de39fddd1cf5f727391efe9974e
    if ($LASTEXITCODE -ne 0) { throw 'Pinned credential scanner setup failed.' }
    & (Join-Path $env:GOBIN 'gitleaks') dir --redact --exit-code 1 $auth
    if ($LASTEXITCODE -ne 0) { throw 'Pinned credential scanner failed.' }
    & (Join-Path $env:GOBIN 'gitleaks') git --redact --exit-code 1 (Join-Path $SourceCheckouts 'Legacy.Maliev.AuthService')
    if ($LASTEXITCODE -ne 0) { throw 'Pinned historical credential scanner failed.' }
    if($Lane -eq 'accounting'){
        $accountingResults=Join-Path $Receipts 'accounting-results'
        & bash (Join-Path $accounting 'eng/financial-qualification/run.sh') $accounting (Join-Path $Destination '.source-inputs/accounting-source-manifest.json') $dependencies $accountingResults
        if($LASTEXITCODE -ne 0){throw 'Exact Accounting sequence failed.'}
        [IO.File]::WriteAllText((Join-Path $Receipts 'accounting-lane.json'), '{"sealedToolingV5SequenceExited":true,"fullForecast":1671,"employeeSubsetForecast":169,"focusedForecast":18,"nativeAccepted":false}')
        return
    }
    # Build FIRST, all affected graphs, warnings-as-errors. Nothing below counts
    # as native qualification if even one graph fails compilation.
    foreach ($project in @('Legacy.Maliev.AuthService.slnx',
        'acceptance/GenuineIamHost/GenuineIamHost.csproj',
        'acceptance/GenuineIamHttp.Tests/GenuineIamHttp.Tests.csproj',
        'acceptance/OrdinaryFinancialIamHost/OrdinaryFinancialIamHost.csproj',
        'acceptance/OrdinaryFinancialIam.Tests/OrdinaryFinancialIam.Tests.csproj')) {
        Invoke-Dotnet (@('build', $project, '--warnaserror') + $common)
    }
    [IO.File]::WriteAllText((Join-Path $Receipts 'build.json'), '{"allFiveGraphsBuilt":true,"warnings":0,"errors":0}')
    $ordinary = 'acceptance/OrdinaryFinancialIam.Tests/OrdinaryFinancialIam.Tests.csproj'
    $main = 'Legacy.Maliev.AuthService.Tests/Legacy.Maliev.AuthService.Tests.csproj'
    $genuine = 'acceptance/GenuineIamHttp.Tests/GenuineIamHttp.Tests.csproj'
    $runs = @(
        @{project=$ordinary;filter='FullyQualifiedName~OrdinaryFinancial_|FullyQualifiedName~OrdinaryAccounting_';name='ordinary-focus.trx'}
        @{project=$main;filter='FullyQualifiedName~LoginResponseWrongTrust_DoesNotSendCredentialedIamRequest';name='transport-focus.trx'}
        @{project=$ordinary;filter=$null;name='ordinary-full.trx'}
        @{project=$main;filter=$null;name='auth-full.trx'}
        @{project=$genuine;filter=$null;name='genuine-full.trx'}
    )
    foreach ($run in $runs) {
        $arguments = @('test', $run.project, '--no-build', '--no-restore') + $common + @('--logger', "trx;LogFileName=$($run.name)", '--results-directory', $results)
        if ($run.filter) { $arguments += @('--filter', $run.filter) }
        if ($run.name -eq 'auth-full.trx') { $arguments += @('--collect', 'XPlat Code Coverage', '--settings', 'eng/coverage.runsettings') }
        Invoke-Dotnet $arguments
    }
    $coverage = @(& ./eng/Get-OwnedCoverageReport.ps1 -ResultsDirectory $results)
    if ($coverage.Count -ne 1) { throw 'Exact raw owned coverage report required.' }
    & ./eng/Assert-OwnedCoverage.ps1 -CoveragePath $coverage[0].FullName
    & ./eng/Export-CoverageEvidence.ps1 -ResultsDirectory $results -OutputDirectory (Join-Path $Receipts 'coverage-evidence')
    & python3 -B (Join-Path $PSScriptRoot 'verify_results.py') $results --receipt (Join-Path $Receipts 'native-discovery.json')
    if ($LASTEXITCODE -ne 0) { throw 'Exact native discovery/result proof failed.' }
    foreach ($project in @('Legacy.Maliev.AuthService.slnx', $ordinary,
        'acceptance/OrdinaryFinancialIamHost/OrdinaryFinancialIamHost.csproj', $genuine,
        'acceptance/GenuineIamHost/GenuineIamHost.csproj')) {
        Invoke-Dotnet (@('format', $project, '--verify-no-changes', '--no-restore'))
    }
    [IO.File]::WriteAllText((Join-Path $Receipts 'static.json'), '{"formatNoChanges":true,"overallAccepted":false}')
} finally {
    Pop-Location
    # External exact SDK-unit owner performs container recovery only AFTER this
    # process and all its actual descendants/readers are quiescent. No fixture
    # startup wrapper or this finally block is substituted for that proof.
}
