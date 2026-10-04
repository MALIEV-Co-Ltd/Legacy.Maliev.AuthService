using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class CleanupFailureObserverTests
{
    [Fact]
    public void Format_ExcludesMessagesDataAndPaths_ReportsOnlyBoundedStructure()
    {
        var canary = Guid.NewGuid().ToString("N");
        var exception = Capture(CreateConnectionString(canary));
        exception.Data["Password"] = "synthetic-secret";
        var report = CleanupFailureObserver.Format(exception, TimeSpan.FromMilliseconds(123), 2);
        Assert.Contains("TaskCanceledException", report);
        Assert.Contains("Capture", report);
        Assert.Contains("CleanupFailureObserverTests.Capture", report);
        Assert.DoesNotContain("Legacy.Maliev.AuthService.Tests", report);
        Assert.Contains("elapsed_ms=123", report);
        Assert.Contains("owned_state=2", report);
        Assert.DoesNotContain("synthetic-secret", report);
        Assert.DoesNotContain(canary, report);
        Assert.DoesNotContain("Host=", report);
        Assert.DoesNotContain(".cs", report);
        Assert.DoesNotContain("Password", report);
        Assert.InRange(report.Length, 1, 2048);
    }

    [Fact]
    public void Format_InnerFailureChain_IsBoundedAndMessageFree()
    {
        Exception exception = new TaskCanceledException("synthetic-secret");
        for (var i = 0; i < 100; i++) exception = new InvalidOperationException("synthetic-secret", exception);
        var report = CleanupFailureObserver.Format(exception, TimeSpan.MaxValue, 2);
        Assert.Contains("InvalidOperationException", report);
        Assert.DoesNotContain("synthetic-secret", report);
        Assert.DoesNotContain("TaskCanceledException", report);
        Assert.InRange(report.Length, 1, 2048);
    }

    [Fact]
    public void Format_UnthrownException_HasNoInventedStack()
    {
        var report = CleanupFailureObserver.Format(new InvalidOperationException("synthetic-secret"), TimeSpan.Zero, 0);
        Assert.Contains("frames=none", report);
        Assert.DoesNotContain("synthetic-secret", report);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ObserverFailure_BareRethrow_PreservesOriginalInstanceAndThrowSite(bool stateFails)
    {
        var original = new TaskCanceledException("synthetic-secret");
        var caught = await Assert.ThrowsAsync<TaskCanceledException>(async () =>
        {
            try { await ThrowOriginalAsync(original); }
            catch (Exception exception)
            {
                CleanupFailureObserver.Observe(exception, TimeSpan.Zero,
                    () => stateFails ? throw new InvalidOperationException("observer-secret") : 2,
                    _ => throw new InvalidOperationException("writer-secret"));
                throw;
            }
        });
        Assert.Same(original, caught);
        Assert.Contains(nameof(ThrowOriginalAsync), caught.StackTrace);
    }

    [Fact]
    public void Observe_WritesOneBoundedReportWithoutMutatingException()
    {
        var canary = Guid.NewGuid().ToString("N");
        var connectionString = CreateConnectionString(canary);
        var original = Capture(connectionString);
        var count = 0;
        string? captured = null;
        CleanupFailureObserver.Observe(original, TimeSpan.Zero, () => 2, report =>
        {
            count++;
            captured = report;
        });
        Assert.Equal(1, count);
        Assert.Contains("TaskCanceledException", captured);
        Assert.Equal(connectionString, original.Message);
        Assert.DoesNotContain(canary, captured);
    }

    private static string CreateConnectionString(string password) =>
        new NpgsqlConnectionStringBuilder { Host = "synthetic", Password = password }.ConnectionString;

    private static Exception Capture(string connectionString)
    {
        try { throw new TaskCanceledException(connectionString); }
        catch (Exception exception) { return exception; }
    }

    private static async Task ThrowOriginalAsync(Exception exception)
    {
        await Task.Yield();
        throw exception;
    }
}
