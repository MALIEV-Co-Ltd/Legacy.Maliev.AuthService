namespace Legacy.Maliev.AuthService.GenuineIamHttp.Tests;

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
