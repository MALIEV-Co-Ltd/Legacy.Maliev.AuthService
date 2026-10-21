using Microsoft.Extensions.Time.Testing;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>
/// Exercises idempotent PostgreSQL fixture cleanup, failure preservation, and bounded graceful stop without starting a container.
/// </summary>
public sealed class PostgresFixtureCleanupTests
{
    /// <summary>
    /// Checks concurrent cleanup callers await one graceful stop before one removal.
    /// </summary>
    /// <returns>A task that completes when the regression assertions have finished.</returns>
    [Fact]
    public async Task ConcurrentAndRepeatedCleanup_AwaitsOneGracefulStopBeforeOneRemoval()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var order = new List<string>();
        var cleanup = PostgresFixture.CreateContainerCleanup(async token =>
        {
            Assert.True(token.CanBeCanceled);
            order.Add("stop");
            entered.TrySetResult();
            await release.Task.WaitAsync(token);
            order.Add("stopped");
        }, () =>
        {
            order.Add("remove");
            return ValueTask.CompletedTask;
        });
        try
        {
            var calls = Enumerable.Range(0, 8)
                .Select(_ => Task.Run(() => Tuple.Create(cleanup.Value))).ToArray();
            var tasks = await Task.WhenAll(calls).WaitAsync(TimeSpan.FromSeconds(5));
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.All(tasks, task => Assert.Same(cleanup.Value, task.Item1));
            Assert.Equal(new[] { "stop" }, order);
            Assert.False(cleanup.Value.IsCompleted);
        }
        finally
        {
            release.TrySetResult();
            await cleanup.Value.WaitAsync(TimeSpan.FromSeconds(5));
        }
        await cleanup.Value;
        Assert.Equal(new[] { "stop", "stopped", "remove" }, order);
    }

    /// <summary>
    /// Checks stop failure still attempts removal and preserves the original failure identity and throw site.
    /// </summary>
    /// <param name="cancelled">Whether graceful stop fails through cancellation rather than an ordinary exception.</param>
    /// <returns>A task that completes when the regression assertions have finished.</returns>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StopFailure_StillRemovesAndPreservesOriginalFailure(bool cancelled)
    {
        Exception original = cancelled ? new TaskCanceledException("private-stop")
            : new InvalidOperationException("private-stop");
        var order = new List<string>();
        var cleanup = PostgresFixture.CreateContainerCleanup(async _ =>
        {
            order.Add("stop");
            await ThrowOriginalAsync(original);
        }, () =>
        {
            order.Add("remove");
            return ValueTask.CompletedTask;
        });
        var actual = await Record.ExceptionAsync(() => cleanup.Value);
        Assert.Same(original, actual);
        Assert.Contains(nameof(ThrowOriginalAsync), actual!.StackTrace);
        Assert.Same(actual, await Record.ExceptionAsync(() => cleanup.Value));
        Assert.Equal(new[] { "stop", "remove" }, order);
    }

    /// <summary>
    /// Checks removal failure preserves its original exception and throw site across repeated cleanup calls.
    /// </summary>
    /// <returns>A task that completes when the regression assertions have finished.</returns>
    [Fact]
    public async Task RemovalFailure_PreservesExistingFailureIdentityAndThrowSite()
    {
        var original = new TaskCanceledException("private-removal");
        var order = new List<string>();
        var cleanup = PostgresFixture.CreateContainerCleanup(_ =>
        {
            order.Add("stop");
            return Task.CompletedTask;
        }, async () =>
        {
            order.Add("remove");
            await ThrowOriginalAsync(original);
        });
        var actual = await Record.ExceptionAsync(() => cleanup.Value);
        Assert.Same(original, actual);
        Assert.Contains(nameof(ThrowOriginalAsync), actual!.StackTrace);
        Assert.Same(actual, await Record.ExceptionAsync(() => cleanup.Value));
        Assert.Equal(new[] { "stop", "remove" }, order);
    }

    /// <summary>
    /// Checks simultaneous stop and removal failures are both reported without replacing either original exception.
    /// </summary>
    /// <returns>A task that completes when the regression assertions have finished.</returns>
    [Fact]
    public async Task BothFailures_ReportBothOriginalInstancesWithoutSuppressingEither()
    {
        var stop = new TaskCanceledException("private-stop");
        var removal = new InvalidOperationException("private-removal");
        var cleanup = PostgresFixture.CreateContainerCleanup(
            _ => Task.FromException(stop), () => ValueTask.FromException(removal));
        var actual = await Assert.ThrowsAsync<AggregateException>(() => cleanup.Value);
        Assert.Collection(actual.InnerExceptions,
            failure => Assert.Same(stop, failure),
            failure => Assert.Same(removal, failure));
        Assert.Same(actual, await Assert.ThrowsAsync<AggregateException>(() => cleanup.Value));
    }

    /// <summary>
    /// Checks the graceful-stop deadline cancels stop while still attempting independent removal exactly once.
    /// </summary>
    /// <returns>A task that completes when the regression assertions have finished.</returns>
    [Fact]
    public async Task GracefulStopDeadline_CancelsAndStillAttemptsIndependentRemoval()
    {
        var clock = new FakeTimeProvider();
        CancellationToken stopToken = default;
        var removals = 0;
        var cleanup = PostgresFixture.CreateContainerCleanup(token =>
        {
            stopToken = token;
            return Task.Delay(Timeout.InfiniteTimeSpan, token);
        }, () =>
        {
            Assert.True(stopToken.IsCancellationRequested);
            removals++;
            return ValueTask.CompletedTask;
        }, clock);
        var task = cleanup.Value;
        try
        {
            clock.Advance(TimeSpan.FromSeconds(29));
            Assert.False(task.IsCompleted);
            Assert.Equal(0, removals);
        }
        finally { clock.Advance(TimeSpan.FromSeconds(1)); }
        var actual = await Record.ExceptionAsync(() => task.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.IsAssignableFrom<OperationCanceledException>(actual);
        Assert.Same(actual, await Record.ExceptionAsync(() => cleanup.Value));
        Assert.Equal(1, removals);
    }

    /// <summary>
    /// Checks that stop failure retains the owned identifier even when successful removal clears the container metadata.
    /// </summary>
    /// <returns>A task that completes when the cleanup observation assertions have finished.</returns>
    [Fact]
    public async Task StopFailureAfterSuccessfulRemoval_ObservesIdentifierCapturedBeforeCleanup()
    {
        const string ownedId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        var currentId = ownedId;
        var original = new TaskCanceledException("private-stop");
        var order = new List<string>();
        var cleanup = PostgresFixture.CreateContainerCleanup(_ =>
        {
            order.Add("stop");
            return Task.FromException(original);
        }, () =>
        {
            order.Add("remove");
            currentId = string.Empty;
            return ValueTask.CompletedTask;
        });
        var observed = new List<string>();
        var actual = await Record.ExceptionAsync(() => PostgresFixture.AwaitContainerCleanupAsync(cleanup, () =>
        {
            order.Add("id");
            return currentId.Length != 0 ? currentId : throw new InvalidOperationException("Container metadata cleared.");
        }, (exception, elapsed, capturedId) =>
        {
            Assert.Same(original, exception);
            Assert.True(elapsed >= TimeSpan.Zero);
            CleanupFailureObserver.Observe(exception, elapsed, () => 1, _ => { },
                _ => observed.Add(capturedId));
        }));
        Assert.Same(original, actual);
        Assert.Equal(new[] { "id", "stop", "remove" }, order);
        Assert.Equal(ownedId, Assert.Single(observed));
        Assert.Equal(string.Empty, currentId);
    }

    /// <summary>
    /// Checks that unavailable identifiers never prevent idempotent cleanup after failed startup or repeated disposal.
    /// </summary>
    /// <param name="failStop">Whether graceful stop fails rather than completing successfully.</param>
    /// <returns>A task that completes when cleanup and failure-preservation assertions have finished.</returns>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnavailableIdentifier_DoesNotPreventCleanupOrReplaceItsFailure(bool failStop)
    {
        var original = new InvalidOperationException("private-stop");
        var stops = 0;
        var removals = 0;
        var observations = 0;
        var cleanup = PostgresFixture.CreateContainerCleanup(_ =>
        {
            stops++;
            return failStop ? Task.FromException(original) : Task.CompletedTask;
        }, () =>
        {
            removals++;
            return ValueTask.CompletedTask;
        });
        for (var call = 0; call < 2; call++)
        {
            var actual = await Record.ExceptionAsync(() => PostgresFixture.AwaitContainerCleanupAsync(cleanup,
                () => throw new InvalidOperationException("Container metadata unavailable."),
                (exception, _, capturedId) =>
                {
                    Assert.Same(original, exception);
                    Assert.Equal(string.Empty, capturedId);
                    observations++;
                }));
            if (failStop) Assert.Same(original, actual);
            else Assert.Null(actual);
        }
        Assert.Equal(1, stops);
        Assert.Equal(1, removals);
        Assert.Equal(failStop ? 2 : 0, observations);
    }

    /// <summary>
    /// Checks that an observation sink failure cannot replace the original cleanup exception or throw site.
    /// </summary>
    /// <returns>A task that completes when the original-failure assertions have finished.</returns>
    [Fact]
    public async Task ObservationFailure_PreservesOriginalCleanupFailureAndThrowSite()
    {
        var original = new TaskCanceledException("private-stop");
        var cleanup = PostgresFixture.CreateContainerCleanup(
            _ => ThrowOriginalAsync(original), () => ValueTask.CompletedTask);
        var actual = await Record.ExceptionAsync(() => PostgresFixture.AwaitContainerCleanupAsync(cleanup,
            () => string.Empty, (_, _, _) => throw new IOException("private-sink")));
        Assert.Same(original, actual);
        Assert.Contains(nameof(ThrowOriginalAsync), actual!.StackTrace);
    }

    private static async Task ThrowOriginalAsync(Exception exception)
    {
        await Task.Yield();
        throw exception;
    }
}
