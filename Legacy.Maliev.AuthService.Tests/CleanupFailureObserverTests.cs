using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>
/// Verifies bounded cleanup diagnostics, independent sinks, and private exclusive receipt creation.
/// </summary>
public sealed class CleanupFailureObserverTests
{
    /// <summary>
    /// Verifies diagnostic formatting excludes exception messages, data, and paths while retaining bounded structure.
    /// </summary>
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

    /// <summary>
    /// Verifies nested failures remain bounded and do not disclose exception messages.
    /// </summary>
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

    /// <summary>
    /// Verifies an exception without a throw site does not acquire a fabricated stack.
    /// </summary>
    [Fact]
    public void Format_UnthrownException_HasNoInventedStack()
    {
        var report = CleanupFailureObserver.Format(new InvalidOperationException("synthetic-secret"), TimeSpan.Zero, 0);
        Assert.Contains("frames=none", report);
        Assert.DoesNotContain("synthetic-secret", report);
    }

    /// <summary>
    /// Verifies observer failure preserves the original exception instance and throw site through a bare rethrow.
    /// </summary>
    /// <param name="stateFails">Whether failure is injected into cleanup-state observation rather than the diagnostic sink.</param>
    /// <returns>A task that completes after the regression assertions finish.</returns>
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

    /// <summary>
    /// Verifies observation writes one bounded report without changing the original exception.
    /// </summary>
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

    /// <summary>
    /// Verifies a failed console sink does not prevent the independent receipt attempt.
    /// </summary>
    [Fact]
    public void Observe_ConsoleFailure_StillAttemptsReceiptWithSameBoundedReport()
    {
        string? persisted = null;
        CleanupFailureObserver.Observe(Capture("synthetic-secret"), TimeSpan.Zero, () => 2,
            _ => throw new IOException("console-secret"), report => persisted = report);
        Assert.Contains("TaskCanceledException", persisted);
        Assert.DoesNotContain("synthetic-secret", persisted);
        Assert.InRange(persisted!.Length, 1, 2048);
    }

    /// <summary>
    /// Verifies receipt failure preserves the original failure and the independent console report.
    /// </summary>
    /// <returns>A task that completes after the regression assertions finish.</returns>
    [Fact]
    public async Task Observe_ReceiptFailure_PreservesOriginalFailureAndConsoleReport()
    {
        var original = new TaskCanceledException("synthetic-secret");
        string? console = null;
        var caught = await Assert.ThrowsAsync<TaskCanceledException>(async () =>
        {
            try { await ThrowOriginalAsync(original); }
            catch (Exception exception)
            {
                CleanupFailureObserver.Observe(exception, TimeSpan.Zero, () => 2,
                    report => console = report, _ => throw new IOException("receipt-secret"));
                throw;
            }
        });
        Assert.Same(original, caught);
        Assert.Contains(nameof(ThrowOriginalAsync), caught.StackTrace);
        Assert.Contains("TaskCanceledException", console);
        Assert.DoesNotContain("synthetic-secret", console);
    }

    /// <summary>
    /// Verifies cleanup receipts are bounded, private, correlated, and created exclusively.
    /// </summary>
    [Fact]
    public void Receipt_IsBoundedPrivateCorrelatedAndExclusive()
    {
        WithReceiptDirectory((workspace, environment) =>
        {
            var identifier = new string('b', 64);
            var canary = Guid.NewGuid().ToString("N");
            var report = CleanupFailureObserver.Format(Capture(CreateConnectionString(canary)), TimeSpan.Zero, 2);
            CleanupFailureObserver.WriteReceipt(report, identifier, environment);
            var path = Path.Combine(workspace, "artifacts", "ordinary-postgres-cleanup", $"cleanup-failure-{identifier}.json");
            var original = File.ReadAllText(path);
            using var receipt = System.Text.Json.JsonDocument.Parse(original);
            var root = receipt.RootElement;
            Assert.Equal(6, root.EnumerateObject().Count());
            Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
            Assert.Equal("123", root.GetProperty("run").GetString());
            Assert.Equal("1", root.GetProperty("attempt").GetString());
            Assert.Equal(new string('a', 40), root.GetProperty("sha").GetString());
            Assert.Equal(identifier, root.GetProperty("containerId").GetString());
            Assert.Equal(report, root.GetProperty("report").GetString());
            Assert.InRange(new FileInfo(path).Length, 1, 8192);
            Assert.DoesNotContain(canary, original);
            Assert.DoesNotContain(workspace, original);
            Assert.DoesNotContain("Host=", original);
            Assert.DoesNotContain("Password", original);
            Assert.Throws<IOException>(() => CleanupFailureObserver.WriteReceipt(report, identifier, environment));
            Assert.Equal(original, File.ReadAllText(path));
            Assert.Single(Directory.GetFiles(Path.GetDirectoryName(path)!));
        });
    }

    /// <summary>
    /// Verifies invalid hosted-run identity cannot create receipt artifacts.
    /// </summary>
    /// <param name="key">The hosted identity environment-variable name being invalidated.</param>
    /// <param name="value">The invalid hosted identity value supplied to the receipt writer.</param>
    [Theory]
    [InlineData("GITHUB_REPOSITORY", "foreign")]
    [InlineData("RUNNER_ENVIRONMENT", "self-hosted")]
    [InlineData("GITHUB_RUN_ID", "../private")]
    [InlineData("GITHUB_RUN_ATTEMPT", "0/1")]
    [InlineData("GITHUB_SHA", "private")]
    [InlineData("GITHUB_WORKSPACE", "relative")]
    public void Receipt_InvalidHostedIdentity_DoesNotCreateArtifacts(string key, string value)
    {
        WithReceiptDirectory((workspace, environment) =>
        {
            CleanupFailureObserver.WriteReceipt("postgres_cleanup_failure type=TaskCanceledException",
                new string('b', 64), name => name == key ? value : environment(name));
            Assert.False(Directory.Exists(Path.Combine(workspace, "artifacts")));
        });
    }

    /// <summary>
    /// Verifies an invalid container identity or report cannot create receipt artifacts.
    /// </summary>
    /// <param name="identifier">The candidate container identifier supplied to receipt validation.</param>
    /// <param name="report">The candidate bounded diagnostic report supplied to receipt validation.</param>
    [Theory]
    [InlineData("../private", "postgres_cleanup_failure type=TaskCanceledException")]
    [InlineData("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "private")]
    [InlineData("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "postgres_cleanup_failure \nprivate")]
    public void Receipt_InvalidContainerOrReport_DoesNotCreateArtifacts(string identifier, string report)
    {
        WithReceiptDirectory((workspace, environment) =>
        {
            CleanupFailureObserver.WriteReceipt(report, identifier, environment);
            CleanupFailureObserver.WriteReceipt("postgres_cleanup_failure " + new string('a', 2048),
                new string('b', 64), environment);
            Assert.False(Directory.Exists(Path.Combine(workspace, "artifacts")));
        });
    }

    /// <summary>
    /// Verifies a linked artifact directory is rejected without writing through it.
    /// </summary>
    [Fact]
    public void Receipt_LinkedArtifactDirectory_IsRejectedWithoutWritingTarget()
    {
        WithReceiptDirectory((workspace, environment) =>
        {
            var target = Path.Combine(workspace, "outside");
            Directory.CreateDirectory(target);
            var link = Path.Combine(workspace, "artifacts");
            Directory.CreateSymbolicLink(link, target);
            try
            {
                Assert.Throws<IOException>(() => CleanupFailureObserver.WriteReceipt(
                    "postgres_cleanup_failure type=TaskCanceledException", new string('b', 64), environment));
                Assert.Empty(Directory.GetFileSystemEntries(target));
            }
            finally { Directory.Delete(link); }
        });
    }

    private static void WithReceiptDirectory(Action<string, Func<string, string?>> action)
    {
        var workspace = Path.Combine(Path.GetTempPath(), $"auth-cleanup-receipt-{Guid.NewGuid():N}");
        Directory.CreateDirectory(workspace);
        try
        {
            string? EnvironmentValue(string name) => name switch
            {
                "GITHUB_REPOSITORY" => "MALIEV-Co-Ltd/Legacy.Maliev.AuthService",
                "RUNNER_ENVIRONMENT" => "github-hosted",
                "GITHUB_RUN_ID" => "123",
                "GITHUB_RUN_ATTEMPT" => "1",
                "GITHUB_SHA" => new string('a', 40),
                "GITHUB_WORKSPACE" => workspace,
                "GITHUB_ACTIONS" => "false",
                _ => null
            };
            action(workspace, EnvironmentValue);
        }
        finally { Directory.Delete(workspace, true); }
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
