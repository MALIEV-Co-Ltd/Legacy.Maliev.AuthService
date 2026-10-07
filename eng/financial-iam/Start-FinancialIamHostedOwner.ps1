[CmdletBinding()]
param([Parameter(Mandatory)][string]$SourceCheckouts,
      [Parameter(Mandatory)][string]$EvidenceRoot,
      [Parameter(Mandatory)][ValidateSet('auth','accounting')][string]$Lane)
$ErrorActionPreference = 'Stop'
if (-not $IsLinux -or $env:GITHUB_REPOSITORY -cne 'MALIEV-Co-Ltd/Legacy.Maliev.AuthService' -or
    $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or $env:GITHUB_RUN_ID -notmatch '^\d+$' -or
    $env:GITHUB_RUN_ATTEMPT -notmatch '^\d+$') { throw 'Exact manually dispatched isolated hosted lane required.' }
$memoryMatch=[regex]::Match([IO.File]::ReadAllText('/proc/meminfo'), '(?m)^MemAvailable:\s+(\d+)\s+kB$')
if(-not $memoryMatch.Success){throw 'Memory census unavailable.'}
$available=[long]$memoryMatch.Groups[1].Value
if ($available -lt 4194304) { throw '4096 MiB admission floor failed; no owner or workload allocated.' }
if (-not (Test-Path -LiteralPath '/sys/fs/cgroup/cgroup.controllers')) { throw 'Unified Linux cgroup admission required.' }
$run = "auth-financial-$($env:GITHUB_RUN_ID)-$($env:GITHUB_RUN_ATTEMPT)-$([Guid]::NewGuid().ToString('N').Substring(0,12))"
$control = "$run-control.service"
$recovery = "$run-recovery.service"
$evidence = [IO.Path]::GetFullPath($EvidenceRoot)
if (Test-Path -LiteralPath $evidence) { throw 'Fresh evidence root required.' }
[IO.Directory]::CreateDirectory($evidence) | Out-Null
$receipt = Join-Path $evidence 'resources'
$coordinatorReceipt=Join-Path $evidence 'coordinator-owner.json'
$launch = [ordered]@{schemaVersion=1;run=$run;lane=$Lane;controlUnit=$control;recoveryUnit=$recovery;executionCommit=$env:GITHUB_SHA;candidateCommit=$null;memoryAvailableKiB=$available;dispatchAttempted=$false;nativeAccepted=$false}
[IO.File]::WriteAllText((Join-Path $evidence 'launcher.json'), ($launch | ConvertTo-Json -Depth 10))
function Get-Unit([string]$Name) {
    $lines = & sudo -n systemctl show $Name --property=Id,InvocationID,MainPID,ControlGroup,ActiveState,SubState,Result,ExecMainStatus,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic
    if ($LASTEXITCODE -ne 0) { throw 'Exact manager observation unavailable.' }
    $result = @{}
    foreach ($line in $lines) { $pair=$line -split '=',2; if($pair.Count -eq 2){$result[$pair[0]]=$pair[1]} }
    if ($result.Id -cne $Name) { throw 'Manager identity mismatch.' }
    return $result
}
function Start-Unit([string]$Name, [string]$Script, [string[]]$Arguments, [int]$Lifetime) {
    $loadState = & sudo -n systemctl show $Name --property=LoadState --value
    if($LASTEXITCODE -ne 0 -or $loadState -cne 'not-found'){throw 'Refuse an existing or uncertain manager unit.'}
    # systemd creates the finite capped invocation BEFORE spawning Python. A
    # failed return is not evidence of no dispatch: retain this exact unit name.
    $command = @('-n','systemd-run',"--unit=$Name",'--service-type=exec','--remain-after-exit',
        '--property=MemoryMax=512M','--property=MemorySwapMax=0','--property=CPUQuota=100%',
        '--property=TasksMax=64',"--property=RuntimeMaxSec=$Lifetime",'--property=TimeoutStopSec=30',
        '--property=KillMode=control-group','--property=SendSIGKILL=yes','--property=LimitCORE=0',
        '--property=LimitFSIZE=268435456',"--setenv=GITHUB_SHA=$($env:GITHUB_SHA)",
        '--setenv=PYTHONDONTWRITEBYTECODE=1','/usr/bin/python3','-B',$Script) + $Arguments
    if($Name -ceq $control){
        $description="AuthFinancialCoordinator:$($run):$([Guid]::NewGuid().ToString('N'))"
        $owner=[ordered]@{schemaVersion=1;run=$run;unit=$Name;description=$description;script=$Script;
            scriptSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $Script).Hash.ToLowerInvariant();
            executable=[IO.FileInfo]::new('/usr/bin/python3').ResolveLinkTarget($true).FullName;
            arguments=@('-B',$Script)+$Arguments;cgroup="/system.slice/$Name";dispatchAttempted=$true;
            invocationId=$null;mainProcess=$null;quiescenceVerified=$false}
        # This fence survives an ambiguous manager return. No backend recovery
        # may interpret a missing/partial manager reply as coordinator exit.
        [IO.File]::WriteAllText($coordinatorReceipt,($owner|ConvertTo-Json -Depth 12))
        # sudo options must remain before its systemd-run executable.
        $command=@('-n','systemd-run',('--description='+$description))+$command[2..($command.Count-1)]
    }
    & sudo @command
    if ($LASTEXITCODE -ne 0) { throw 'Owned manager dispatch failed or ambiguous; retain exact owner.' }
}
function Wait-Unit([string]$Name, [int]$DeadlineSeconds) {
    $deadline=[DateTime]::UtcNow.AddSeconds($DeadlineSeconds)
    $invocation=$null
    while([DateTime]::UtcNow -lt $deadline){
        $state=Get-Unit $Name
        if($state.InvocationID){if($invocation -and $state.InvocationID -cne $invocation){throw 'Unit generation changed.'};$invocation=$state.InvocationID}
        if($state.SubState -eq 'exited' -or $state.ActiveState -in @('inactive','failed')){
            if(-not $invocation -or [long]$state.ExecMainStartTimestampMonotonic -le 0 -or [long]$state.ExecMainExitTimestampMonotonic -lt [long]$state.ExecMainStartTimestampMonotonic){throw 'Actual invocation/exit evidence absent.'}
            if($state.ControlGroup -and (Test-Path -LiteralPath ("/sys/fs/cgroup"+$state.ControlGroup))){
                $members=@(Get-ChildItem -LiteralPath ("/sys/fs/cgroup"+$state.ControlGroup) -Filter cgroup.procs -Recurse | ForEach-Object {[IO.File]::ReadAllLines($_.FullName)} | Where-Object {$_})
                if($members.Count){throw 'Coordinator retains actual live members.'}
            }
            [IO.File]::WriteAllText((Join-Path $evidence "$Name.json"), ($state | ConvertTo-Json))
            if($state.Result -ne 'success' -or $state.ExecMainStatus -ne '0'){throw 'Owned invocation failed.'}
            return
        }
        Start-Sleep -Milliseconds 250
    }
    throw 'Owned invocation deadline expired.'
}
function Stop-ObservedUnit([string]$Name) {
    $path=Join-Path $evidence "$Name.json"
    if(-not (Test-Path -LiteralPath $path)){throw 'Retain finite unit without settled exact invocation evidence.'}
    $before=Get-Content -Raw -LiteralPath $path|ConvertFrom-Json
    $current=Get-Unit $Name
    if($current.InvocationID -and $current.InvocationID -cne $before.InvocationID){throw 'Do not stop a reused manager invocation.'}
    & sudo -n systemctl stop $Name
    if($LASTEXITCODE -ne 0){throw 'Exact settled unit stop failed.'}
    $after=Get-Unit $Name
    if($after.ActiveState -notin @('inactive','failed')){throw 'Settled launcher unit remains active.'}
}
$failures=[Collections.Generic.List[string]]::new()
try {
    $launch.dispatchAttempted=$true
    [IO.File]::WriteAllText((Join-Path $evidence 'launcher.json'),($launch|ConvertTo-Json))
    Start-Unit $control (Join-Path $PSScriptRoot 'hosted_owner.py') @('--source',$PSScriptRoot,'--checkouts',[IO.Path]::GetFullPath($SourceCheckouts),'--receipt',$receipt,'--coordinator-unit',$control,'--lane',$Lane) 2700
    Wait-Unit $control 2730
} catch {
    $failures.Add($_.Exception.GetType().Name)
} finally {
    # Even if the inner ledger is not created yet, an allocating coordinator
    # must be settled before the launcher yields. Missing inner ownership is a
    # retained cleanup failure AFTER this exact coordinator barrier, not a
    # reason to leave the coordinator free to allocate concurrently.
    if(Test-Path -LiteralPath $coordinatorReceipt){
        try {
            Start-Unit $recovery (Join-Path $PSScriptRoot 'recover_owner.py') @('--run',$run,'--receipt',$receipt,'--coordinator-receipt',$coordinatorReceipt) 600
            Wait-Unit $recovery 630
        } catch {$failures.Add('IndependentRecovery:'+ $_.Exception.GetType().Name)}
    } elseif($launch.dispatchAttempted){$failures.Add('OwnedReceiptUnavailable')}
    foreach($unit in @($recovery,$control)){
        if(Test-Path -LiteralPath (Join-Path $evidence "$unit.json")){
            try{Stop-ObservedUnit $unit}catch{$failures.Add('LauncherUnitQuiescence:'+ $_.Exception.GetType().Name)}
        }
    }
    $launch.failures=@($failures)
    [IO.File]::WriteAllText((Join-Path $evidence 'launcher.json'),($launch|ConvertTo-Json -Depth 10))
}
if($failures.Count){throw 'Hosted qualification or cleanup failed; original failure evidence retained.'}
if(Test-Path -LiteralPath (Join-Path $receipt 'expiry.json')){throw 'Independent resource lease expired; no native acceptance.'}
$cleanup=Get-Content -Raw -LiteralPath (Join-Path $receipt 'external-cleanup.json')|ConvertFrom-Json
if($cleanup.remainingResources -ne 0 -or -not $cleanup.sdkQuiescent -or -not $cleanup.containersAbsent){throw 'Combined source-bound cleanup acceptance incomplete.'}
if(@($cleanup.originalQualificationFailuresRetained).Count){throw 'Recovered cleanup cannot erase original qualification or receipt-write failures.'}
if($Lane -eq 'auth'){
    $native=Get-Content -Raw -LiteralPath (Join-Path $receipt 'native-discovery.json')|ConvertFrom-Json
    $build=Get-Content -Raw -LiteralPath (Join-Path $receipt 'build.json')|ConvertFrom-Json
    if(-not $build.allFiveGraphsBuilt -or $native.newCandidateTuples -ne 30 -or $native.retainedFocusedTuples -ne 18){throw 'Auth source-bound native acceptance incomplete.'}
}else{
    $sequence=Get-Content -Raw -LiteralPath (Join-Path $receipt 'accounting-results/sequence.json')|ConvertFrom-Json
    $laneResult=Get-Content -Raw -LiteralPath (Join-Path $receipt 'accounting-lane.json')|ConvertFrom-Json
    if(-not $sequence.testsAndStaticSequenceExited -or -not $laneResult.sealedToolingV5SequenceExited){throw 'Accounting source-bound native acceptance incomplete.'}
}
$launch.nativeAccepted=$true
[IO.File]::WriteAllText((Join-Path $evidence 'launcher.json'),($launch|ConvertTo-Json -Depth 10))
