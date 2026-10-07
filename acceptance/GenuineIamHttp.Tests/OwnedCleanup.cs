using System.Diagnostics;

namespace Legacy.Maliev.AuthService.GenuineIamHttp.Tests;

internal sealed class OwnedHelperSetupException()
    : InvalidOperationException("Owned helper launch or reader setup failed.") { }

// The caller registers this lease before ExecuteAsync can launch its exact process.
internal sealed class OwnedProcessLease(ProcessStartInfo start, int reapMilliseconds)
{
    internal Process Process { get; } = new() { StartInfo = start };
    internal CancellationTokenSource? Deadline { get; private set; }
    internal Task<string>? Output { get; private set; }
    internal Task<string>? Error { get; private set; }
    internal StreamReader? OutputReader { get; private set; }
    internal StreamReader? ErrorReader { get; private set; }
    internal bool OutputReaderDisposed { get; private set; }
    internal bool ErrorReaderDisposed { get; private set; }
    internal bool DeadlineDisposed { get; private set; }
    internal bool ProcessHandleDisposed { get; private set; }
    internal int? ProcessId { get; private set; }
    internal DateTime? StartedAtUtc { get; private set; }
    internal string Executable { get; private set; } = start.FileName;
    internal int? ExitCode { get; private set; }
    internal bool Started { get; private set; }
    internal bool StartAttempted { get; private set; }
    internal bool Disposed => ProcessHandleDisposed && (Deadline is null || DeadlineDisposed)
        && (OutputReader is null || OutputReaderDisposed) && (ErrorReader is null || ErrorReaderDisposed);
    internal bool CleanupComplete { get; private set; }
    internal bool CleanupFaultObserved { get; private set; }
    internal bool Exited { get; private set; }
    internal bool TerminationFailed { get; private set; }
    internal bool ReadersObserved { get; private set; }
    internal bool ReadersSettled => (Output is null || Output.IsCompleted) && (Error is null || Error.IsCompleted);

    internal async Task<(int ExitCode, string Output, string Error)> ExecuteAsync(
        CancellationToken token, int commandSeconds, Func<OwnedProcessLease, Task> record,
        Action? afterStart = null, Action? beforeReap = null, Action? afterReaders = null, Action? beforeKill = null)
    {
        var setupComplete = false;
        try
        {
            Deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            Deadline.CancelAfter(TimeSpan.FromSeconds(commandSeconds));
            Deadline.Token.ThrowIfCancellationRequested();
            StartAttempted = true;
            Started = Process.Start();
            if (!Started) throw new OwnedHelperSetupException();
            ProcessId = Process.Id;
            afterStart?.Invoke(); // Native fault controls exercise this same protected setup boundary.
            StartedAtUtc = Process.StartTime.ToUniversalTime();
            try { Executable = Process.MainModule?.FileName ?? Executable; }
            catch (Exception) { /* PID and nullable birth metadata remain attached to the owned handle. */ }
            OutputReader = Process.StandardOutput;
            Output = BoundedProcessOutput.ReadAsync(OutputReader, 64 * 1024, Deadline.Token);
            ErrorReader = Process.StandardError;
            Error = BoundedProcessOutput.ReadAsync(ErrorReader, 64 * 1024, Deadline.Token);
            afterReaders?.Invoke();
            setupComplete = true;
            await BoundedProcessOutput.ObserveConcurrentAsync(Output, Error, Process.WaitForExitAsync(Deadline.Token));
            return (Process.ExitCode, await Output, await Error);
        }
        catch (Exception) when (!setupComplete) { throw new OwnedHelperSetupException(); }
        finally { await ReconcileAsync(record, beforeReap, beforeKill); }
    }

    internal async Task ReconcileAsync(Func<OwnedProcessLease, Task> record, Action? beforeReap = null, Action? beforeKill = null)
    {
        List<Exception> failures = [];
        CleanupComplete = false;
        try { if (!DeadlineDisposed) Deadline?.Cancel(); }
        catch (Exception) { Fail("readers-cancel"); }
        // Kill, reap, exit observation, both readers and receipt are independent attempts.
        if (StartAttempted && !Started)
        {
            try { ProcessId = Process.Id; Started = true; }
            catch (Exception) { /* Retain an unverified partial launch rather than invent process absence. */ }
        }
        if (Started && !ProcessHandleDisposed)
        {
            try { if (!Process.HasExited) { beforeKill?.Invoke(); Process.Kill(); } }
            catch (Exception) { Fail("terminate"); }
            try { beforeReap?.Invoke(); if (!Process.WaitForExit(reapMilliseconds)) Fail("reap"); }
            catch (Exception) { Fail("reap"); }
            try { Exited = Process.HasExited; }
            catch (Exception) { Fail("process-absence"); }
            if (Exited)
            {
                try { ExitCode = Process.ExitCode; }
                catch (Exception) { Fail("exit-code"); }
            }
        }
        else if (!ProcessHandleDisposed)
        {
            // A failed Start may have associated a handle before throwing: do not invent absence.
            Exited = !StartAttempted;
            if (StartAttempted) Fail("launch-unverified");
        }
        TerminationFailed = failures.Count != 0 || !Exited;
        ReadersObserved = false;
        await RecordAsync();
        await SettleAsync(Output);
        await SettleAsync(Error);
        // Process.Close does not close caller-exposed synchronous redirected readers.
        // Close each acquired reader only after its asynchronous task has settled.
        if ((Output is null || Output.IsCompleted) && OutputReader is not null && !OutputReaderDisposed)
        {
            try { OutputReader.Dispose(); OutputReaderDisposed = true; }
            catch (Exception) { Fail("output-reader-handle"); }
        }
        if ((Error is null || Error.IsCompleted) && ErrorReader is not null && !ErrorReaderDisposed)
        {
            try { ErrorReader.Dispose(); ErrorReaderDisposed = true; }
            catch (Exception) { Fail("error-reader-handle"); }
        }
        if (ReadersSettled && !DeadlineDisposed)
        {
            try { Deadline?.Dispose(); DeadlineDisposed = true; }
            catch (Exception) { Fail("deadline-handle"); }
        }
        if (!Exited) Fail("process-unreaped");
        if (!ReadersSettled) Fail("readers-unsettled");
        if (failures.Count == 0 && !ProcessHandleDisposed)
        {
            try { Process.Dispose(); ProcessHandleDisposed = true; }
            catch (Exception) { Fail("process-handle"); }
        }
        ReadersObserved = true;
        await RecordAsync(); // Actual disposition, using captured identity even after Process.Dispose.
        if (failures.Count != 0) throw new OwnedHelperCleanupException(failures);
        CleanupComplete = true;

        async Task RecordAsync()
        {
            try { await record(this).WaitAsync(TimeSpan.FromSeconds(1)); }
            catch (Exception) { Fail("quiescence-receipt"); }
        }
        async Task SettleAsync(Task<string>? reader)
        {
            if (reader is null) return; // No asynchronous reader was acquired; receipt preserves that distinction.
            try { await reader.WaitAsync(TimeSpan.FromSeconds(1)); }
            catch (Exception) when (reader.IsCompleted) { /* Settled faults remain in the original execution result. */ }
            catch (Exception) { Fail("reader-settle"); }
        }
        void Fail(string step)
        {
            CleanupFaultObserved = true;
            failures.Add(new InvalidOperationException("Owned helper cleanup incomplete: " + step));
        }
    }
}

internal sealed class OwnedHelperCleanupException(IEnumerable<Exception> failures)
    : AggregateException("Owned Docker helper cleanup failed; retained handles require independent quiescence verification.", failures)
{ }

internal sealed class OwnedHelperSafety
{
    internal bool IsQuarantined { get; private set; }
    internal void Quarantine() => IsQuarantined = true;
    internal void ReleaseAfterVerifiedQuiescence() => IsQuarantined = false;
    internal void RequireQuiescence()
    {
        if (IsQuarantined)
            throw new OwnedHelperCleanupException([new InvalidOperationException("Owned Docker helper remains quarantined.")]);
    }

    internal async Task<(bool Complete, T? Value)> ObservePolicyAsync<T>(Func<Task<T>> observe) where T : class
    {
        RequireQuiescence();
        try { return (true, await observe()); }
        catch (OwnedHelperCleanupException) { Quarantine(); throw; }
        catch (OwnedHelperSetupException) { throw; }
        catch (Exception) { return (false, null); }
    }

    internal async Task<T> MutateAsync<T>(Func<Task<T>> mutation)
    {
        RequireQuiescence();
        return await mutation();
    }
}

internal static class OwnedCleanup
{
    internal static async Task RunAsync(
        IEnumerable<(string Name, Func<CancellationToken, Task> Dispose)> resources,
        Func<string, bool, CancellationToken, Task> record,
        TimeSpan timeout)
    {
        List<Exception> failures = [];
        foreach (var resource in resources)
        {
            var complete = false;
            using var deadline = new CancellationTokenSource(timeout);
            try
            {
                await resource.Dispose(deadline.Token).WaitAsync(deadline.Token);
                complete = true;
            }
            catch (Exception)
            {
                // Resource names are fixed fixture code; arbitrary failure text is not retained.
                failures.Add(new InvalidOperationException("Owned cleanup incomplete: " + resource.Name));
            }
            using var receiptDeadline = new CancellationTokenSource(timeout);
            try { await record(resource.Name, complete, receiptDeadline.Token).WaitAsync(receiptDeadline.Token); }
            catch (Exception) { failures.Add(new InvalidOperationException("Owned cleanup receipt unavailable: " + resource.Name)); }
        }
        if (failures.Count != 0) throw new AggregateException("Owned fixture cleanup failed; retained ownership requires attention.", failures);
    }

    internal static bool IsExactContainerAbsence(string id, int exitCode, string error)
        => exitCode != 0 && (string.Equals(error.Trim(), "Error: No such object: " + id, StringComparison.Ordinal)
            || string.Equals(error.Trim(), "Error response from daemon: No such container: " + id, StringComparison.Ordinal));
}

public sealed class OwnedCleanupTests
{
    [Fact]
    public async Task OwnedHelper_BirthMetadataFaultStillReapsAndFailsOriginalObservation()
    {
        var safety = new OwnedHelperSafety();
        var helper = NativeHelper();
        var receipts = 0;
        Exception? originalFailure = null;
        try
        {
            await Assert.ThrowsAsync<OwnedHelperSetupException>(() => safety.ObservePolicyAsync<string>(async () =>
            {
                await helper.ExecuteAsync(CancellationToken.None, 5, lease =>
                {
                    receipts++;
                    Assert.True(lease.Exited);
                    if (lease.ReadersObserved) Assert.True(lease.ReadersSettled);
                    Assert.Null(lease.StartedAtUtc);
                    Assert.Null(lease.Output);
                    return Task.CompletedTask;
                }, afterStart: () => throw new InvalidOperationException("Injected birth metadata fault."));
                return "unreachable";
            }));
            Assert.Equal(2, receipts);
            Assert.True(helper.Disposed);
            Assert.False(safety.IsQuarantined);
            var removed = false;
            await safety.MutateAsync(() => { removed = true; return Task.FromResult(0); });
            Assert.True(removed);
        }
        catch (Exception failure) { originalFailure = failure; throw; }
        finally
        {
            try { if (!helper.CleanupComplete) await helper.ReconcileAsync(_ => Task.CompletedTask); }
            catch (Exception cleanupFailure) when (originalFailure is not null)
            { throw new AggregateException("Native helper assertion and cleanup both failed.", originalFailure, cleanupFailure); }
        }
    }

    [Fact]
    public async Task OwnedHelper_ReaderSetupAndReapFaultRetainsLeaseButStillSettlesAndRecords()
    {
        var safety = new OwnedHelperSafety();
        var helper = NativeHelper();
        var receipts = 0;
        Exception? originalFailure = null;
        try
        {
            await Assert.ThrowsAsync<OwnedHelperCleanupException>(() => safety.ObservePolicyAsync<string>(async () =>
            {
                await helper.ExecuteAsync(CancellationToken.None, 5, lease =>
                {
                    receipts++;
                    Assert.NotNull(lease.Output);
                    Assert.NotNull(lease.Error);
                    if (lease.ReadersObserved) Assert.True(lease.ReadersSettled);
                    return Task.CompletedTask;
                }, beforeReap: () => throw new InvalidOperationException("Injected reap fault."),
                    afterReaders: () => throw new InvalidOperationException("Injected reader setup fault."));
                return "unreachable";
            }));
            Assert.Equal(2, receipts);
            Assert.False(helper.Disposed);
            Assert.True(helper.OutputReaderDisposed);
            Assert.True(helper.ErrorReaderDisposed);
            Assert.Throws<ObjectDisposedException>(() => helper.OutputReader!.Peek());
            Assert.Throws<ObjectDisposedException>(() => helper.ErrorReader!.Peek());
            Assert.True(safety.IsQuarantined);
            var removed = false;
            await Assert.ThrowsAsync<OwnedHelperCleanupException>(() => safety.MutateAsync(() =>
            { removed = true; return Task.FromResult(0); }));
            Assert.False(removed);
            // Independent recovery uses the same production stages without injected faults.
            await helper.ReconcileAsync(lease =>
            {
                receipts++;
                Assert.True(lease.Exited);
                if (lease.ReadersObserved) Assert.True(lease.ReadersSettled);
                return Task.CompletedTask;
            });
            Assert.Equal(4, receipts);
            Assert.True(helper.Disposed);
            safety.ReleaseAfterVerifiedQuiescence();
            await safety.MutateAsync(() => { removed = true; return Task.FromResult(0); });
            Assert.True(removed);
        }
        catch (Exception failure) { originalFailure = failure; throw; }
        finally
        {
            try { if (!helper.CleanupComplete) await helper.ReconcileAsync(_ => Task.CompletedTask); }
            catch (Exception cleanupFailure) when (originalFailure is not null)
            { throw new AggregateException("Native helper assertion and cleanup both failed.", originalFailure, cleanupFailure); }
        }
    }

    [Fact]
    public async Task OwnedHelper_KillFaultStillAttemptsBothReadersAndRecordsBeforeRecovery()
    {
        var safety = new OwnedHelperSafety();
        var helper = NativeHelper();
        var receipts = 0;
        List<(bool Observed, bool OutputSettled, bool ErrorSettled, bool OutputDisposed, bool ErrorDisposed)> snapshots = [];
        Exception? originalFailure = null;
        try
        {
            await Assert.ThrowsAsync<OwnedHelperCleanupException>(() => safety.ObservePolicyAsync<string>(async () =>
            {
                await helper.ExecuteAsync(CancellationToken.None, 5, lease =>
                {
                    receipts++;
                    snapshots.Add((lease.ReadersObserved, lease.Output!.IsCompleted, lease.Error!.IsCompleted,
                        lease.OutputReaderDisposed, lease.ErrorReaderDisposed));
                    return Task.CompletedTask;
                }, afterReaders: () => throw new InvalidOperationException("Injected reader setup fault."),
                    beforeKill: () => throw new InvalidOperationException("Injected kill fault."));
                return "unreachable";
            }));
            Assert.Equal(2, receipts);
            Assert.Equal(new[] { false, true }, snapshots.Select(snapshot => snapshot.Observed));
            Assert.All(snapshots, snapshot =>
            {
                if (!snapshot.OutputSettled) Assert.False(snapshot.OutputDisposed);
                if (!snapshot.ErrorSettled) Assert.False(snapshot.ErrorDisposed);
            });
            Assert.True(safety.IsQuarantined);
            Assert.False(helper.Disposed);
            Assert.False(helper.Process.HasExited);
            await Assert.ThrowsAsync<OwnedHelperCleanupException>(() => safety.MutateAsync(() => Task.FromResult(0)));
        }
        catch (Exception failure) { originalFailure = failure; throw; }
        finally
        {
            try { if (!helper.CleanupComplete) await helper.ReconcileAsync(_ => Task.CompletedTask); }
            catch (Exception cleanupFailure) when (originalFailure is not null)
            { throw new AggregateException("Native helper assertion and cleanup both failed.", originalFailure, cleanupFailure); }
        }
        Assert.True(helper.Exited);
        Assert.True(helper.ReadersSettled);
        Assert.True(helper.Disposed);
    }

    private static OwnedProcessLease NativeHelper()
    {
        var start = new ProcessStartInfo(OperatingSystem.IsWindows() ? "powershell.exe" : "/bin/sh")
        { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var argument in OperatingSystem.IsWindows()
            ? new[] { "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30" }
            : new[] { "-c", "exec sleep 30" }) start.ArgumentList.Add(argument);
        return new OwnedProcessLease(start, 500);
    }

    [Fact]
    public async Task OwnedStorageObservation_HelperCleanupFaultQuarantinesStopAndRemove()
    {
        var safety = new OwnedHelperSafety();
        List<string> mutations = [];
        await Assert.ThrowsAsync<OwnedHelperCleanupException>(() => safety.ObservePolicyAsync<string>(
            () => throw new OwnedHelperCleanupException([new InvalidOperationException("Owned helper did not settle.")])));
        foreach (var command in new[] { "stop", "rm" })
            await Assert.ThrowsAsync<OwnedHelperCleanupException>(() => safety.MutateAsync(() =>
            {
                mutations.Add(command);
                return Task.FromResult(0);
            }));
        Assert.Empty(mutations);
        Assert.True(safety.IsQuarantined);
    }

    [Fact]
    public async Task OwnedStorageObservation_QuiescentPolicyFailureAllowsStopAndRemove()
    {
        var safety = new OwnedHelperSafety();
        List<string> mutations = [];
        var policy = await safety.ObservePolicyAsync<string>(() => throw new InvalidOperationException("Owned policy mismatch."));
        Assert.False(policy.Complete);
        Assert.Null(policy.Value);
        foreach (var command in new[] { "stop", "rm" })
            await safety.MutateAsync(() => { mutations.Add(command); return Task.FromResult(0); });
        Assert.Equal(new[] { "stop", "rm" }, mutations);
        Assert.False(safety.IsQuarantined);
    }

    [Fact]
    public async Task OwnedCleanup_DisposalFailureStillAttemptsEveryLaterResource()
    {
        List<string> attempted = [];
        List<(string Name, bool Complete)> receipts = [];
        await Assert.ThrowsAsync<AggregateException>(() => OwnedCleanup.RunAsync(
            [("Auth", _ => { attempted.Add("Auth"); throw new InvalidOperationException("fault"); }),
             ("WrongAudienceAuth", _ => { attempted.Add("WrongAudienceAuth"); return Task.CompletedTask; }),
             ("Container", _ => { attempted.Add("Container"); return Task.CompletedTask; })],
            (name, complete, _) => { receipts.Add((name, complete)); return Task.CompletedTask; }, TimeSpan.FromSeconds(1)));
        Assert.Equal(new[] { "Auth", "WrongAudienceAuth", "Container" }, attempted);
        Assert.Equal(new[] { ("Auth", false), ("WrongAudienceAuth", true), ("Container", true) }, receipts);
    }

    [Fact]
    public async Task OwnedCleanup_TimeoutCancelsOwnedOperationAndStillAttemptsLaterResource()
    {
        var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var later = false;
        await Assert.ThrowsAsync<AggregateException>(() => OwnedCleanup.RunAsync(
            [("Host", async token => { try { await Task.Delay(Timeout.Infinite, token); } finally { cancelled.TrySetResult(); } }),
             ("Container", _ => { later = true; return Task.CompletedTask; })],
            (_, _, _) => Task.CompletedTask, TimeSpan.FromMilliseconds(25)));
        await cancelled.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.True(later);
    }

    [Theory]
    [InlineData(1, "Error: No such object: owned-id", true)]
    [InlineData(1, "Error response from daemon: No such container: owned-id", true)]
    [InlineData(1, "Cannot connect to the Docker daemon", false)]
    [InlineData(127, "docker: command not found", false)]
    [InlineData(1, "Error: No such object: another-id", false)]
    [InlineData(0, "Error: No such object: owned-id", false)]
    public void OwnedCleanup_OnlyExactDaemonAbsenceProvesRemoval(int exitCode, string error, bool expected)
        => Assert.Equal(expected, OwnedCleanup.IsExactContainerAbsence("owned-id", exitCode, error));
}
