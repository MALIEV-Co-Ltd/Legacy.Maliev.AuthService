using System.Text;

namespace Legacy.Maliev.AuthService.GenuineIamHttp.Tests;

internal static class BoundedProcessOutput
{
    internal static async Task<string> ReadAsync(TextReader reader, int maximumCharacters, CancellationToken cancellationToken)
    {
        var output = new StringBuilder();
        var buffer = new char[2048];
        while (true)
        {
            var count = await reader.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (count == 0) return output.ToString();
            if (output.Length + count > maximumCharacters) throw new InvalidOperationException("Owned helper output limit exceeded.");
            output.Append(buffer, 0, count);
        }
    }

    internal static async Task ObserveConcurrentAsync(params Task[] tasks)
    {
        var pending = tasks.ToList();
        while (pending.Count != 0)
        {
            var completed = await Task.WhenAny(pending);
            await completed; // A stream fault is surfaced immediately, before waiting for other streams.
            pending.Remove(completed);
        }
    }

    internal static async Task<bool> TerminateAsync(Func<bool> exited, Action kill, Func<bool> reap, Func<bool, bool, Task> record)
    {
        var terminationFailed = false;
        try { if (!exited()) kill(); }
        catch (Exception) { terminationFailed = true; }
        try { if (!exited() && !reap()) terminationFailed = true; }
        catch (Exception) { terminationFailed = true; }
        var observedExited = false;
        try { observedExited = exited(); }
        catch (Exception) { terminationFailed = true; }
        await record(observedExited, terminationFailed).WaitAsync(TimeSpan.FromSeconds(10));
        return observedExited;
    }
}

public sealed class BoundedProcessOutputTests
{
    [Fact]
    public async Task BoundedOutput_ExactLimitIsAccepted()
        => Assert.Equal("1234", await BoundedProcessOutput.ReadAsync(new StringReader("1234"), 4, CancellationToken.None));

    [Fact]
    public async Task BoundedOutput_OneCharacterOverflowFailsWithoutRetainingArbitraryText()
    {
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => BoundedProcessOutput.ReadAsync(new StringReader("12345"), 4, CancellationToken.None));
        Assert.DoesNotContain("12345", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BoundedOutput_OverflowIsObservedWithoutWaitingForOtherOpenStream()
    {
        var unfinished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var overflow = BoundedProcessOutput.ReadAsync(new StringReader("12345"), 4, CancellationToken.None);
        await Assert.ThrowsAsync<InvalidOperationException>(() => BoundedProcessOutput.ObserveConcurrentAsync(overflow, unfinished.Task).WaitAsync(TimeSpan.FromSeconds(1)));
        unfinished.SetResult();
    }

    [Fact]
    public async Task BoundedOutput_KillFailureStillReapsAndRecordsRemainingOwnership()
    {
        var reaped = false;
        (bool Exited, bool Failed)? receipt = null;
        var result = await BoundedProcessOutput.TerminateAsync(() => false, () => throw new InvalidOperationException("fault"),
            () => { reaped = true; return false; }, (exited, failed) => { receipt = (exited, failed); return Task.CompletedTask; });
        Assert.False(result);
        Assert.True(reaped);
        Assert.True(receipt.HasValue);
        Assert.Equal((false, true), receipt.GetValueOrDefault());
    }
}
