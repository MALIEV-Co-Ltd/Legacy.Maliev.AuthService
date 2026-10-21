using System.Text.Json;
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

    [Theory]
    [InlineData("dispose-entered")]
    [InlineData("dispose-completed")]
    [InlineData("dispose-faulted")]
    public void ObservePhase_RetainsOnlyBoundedSafeFixtureEvidence(string phase)
    {
        WithReceiptDirectory(directory =>
        {
            var id = new string('a', 64);
            var started = new DateTime(2026, 10, 20, 0, 0, 0, DateTimeKind.Utc);
            var canary = Guid.NewGuid().ToString("N");
            var exception = Capture(CreateConnectionString(canary));
            exception.Data["Password"] = canary;
            CleanupFailureObserver.ObservePhase((id, started), phase, TimeSpan.FromMilliseconds(123),
                () => 2, phase == "dispose-faulted" ? exception : null, directory);
            var file = Assert.Single(Directory.GetFiles(directory));
            Assert.Equal($"fixture-{id}-{phase}.json", Path.GetFileName(file));
            using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.None);
            Assert.InRange(stream.Length, 1L, 4096L);
            using var document = JsonDocument.Parse(stream);
            var root = document.RootElement;
            Assert.Equal(new[] { "containerId", "elapsedMilliseconds", "failure", "fixtureStartedTime",
                "observedAtUtc", "ownedState", "phase", "schemaVersion" },
                root.EnumerateObject().Select(property => property.Name).OrderBy(name => name, StringComparer.Ordinal));
            Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
            Assert.Equal(id, root.GetProperty("containerId").GetString());
            Assert.Equal(started.ToString("O"), root.GetProperty("fixtureStartedTime").GetString());
            Assert.Equal(phase, root.GetProperty("phase").GetString());
            Assert.Equal(123, root.GetProperty("elapsedMilliseconds").GetInt32());
            Assert.Equal(2, root.GetProperty("ownedState").GetInt32());
            Assert.Equal(DateTimeKind.Utc, root.GetProperty("observedAtUtc").GetDateTime().Kind);
            if (phase == "dispose-faulted")
            {
                Assert.Contains("TaskCanceledException", root.GetProperty("failure").GetString());
                Assert.Contains("CleanupFailureObserverTests.Capture", root.GetProperty("failure").GetString());
            }
            else Assert.Equal(JsonValueKind.Null, root.GetProperty("failure").ValueKind);
            var raw = root.GetRawText();
            Assert.DoesNotContain(canary, raw);
            Assert.DoesNotContain("Password", raw);
            Assert.DoesNotContain("Host=", raw);
            Assert.DoesNotContain(".cs", raw);
        });
    }

    [Fact]
    public void CaptureIdentity_RejectsUnknownOrUntrustedMetadataWithoutThrowing()
    {
        var id = new string('b', 64);
        var started = DateTime.UtcNow;
        Assert.Equal<(string Id, DateTime StartedTime)?>((id, started),
            CleanupFailureObserver.CaptureIdentity(() => (id, started)));
        Assert.Null(CleanupFailureObserver.CaptureIdentity(() => ("../secret", started)));
        Assert.Null(CleanupFailureObserver.CaptureIdentity(() => (id, default)));
        Assert.Null(CleanupFailureObserver.CaptureIdentity(() => throw new InvalidOperationException("synthetic-secret")));
    }

    [Fact]
    public void HostedDirectory_RequiresExactOrdinaryHostedRepositoryContext()
    {
        var workspace = Path.GetTempPath();
        Assert.Equal(Path.Combine(workspace, "artifacts", "ordinary-postgres-cleanup"),
            CleanupFailureObserver.HostedDirectory("MALIEV-Co-Ltd/Legacy.Maliev.AuthService", "github-hosted", workspace));
        Assert.Null(CleanupFailureObserver.HostedDirectory("other/repository", "github-hosted", workspace));
        Assert.Null(CleanupFailureObserver.HostedDirectory("MALIEV-Co-Ltd/Legacy.Maliev.AuthService", "self-hosted", workspace));
        Assert.Null(CleanupFailureObserver.HostedDirectory("MALIEV-Co-Ltd/Legacy.Maliev.AuthService", "github-hosted", "relative"));
        Assert.Null(CleanupFailureObserver.HostedDirectory(null, null, null));
    }

    [Fact]
    public void ObservePhase_RejectsInvalidInputsAndNeverOverwritesExistingEvidence()
    {
        WithReceiptDirectory(directory =>
        {
            var identity = (new string('c', 64), DateTime.UtcNow);
            CleanupFailureObserver.ObservePhase(null, "dispose-entered", TimeSpan.Zero, () => 2, null, directory);
            CleanupFailureObserver.ObservePhase(("../escape", identity.Item2), "dispose-entered", TimeSpan.Zero, () => 2, null, directory);
            CleanupFailureObserver.ObservePhase(identity, "synthetic-secret", TimeSpan.Zero, () => 2, null, directory);
            CleanupFailureObserver.ObservePhase(identity, "dispose-entered", TimeSpan.Zero, () => 2, null, Path.Combine(directory, "missing"));
            Assert.Empty(Directory.GetFileSystemEntries(directory));
            CleanupFailureObserver.ObservePhase(identity, "dispose-entered", TimeSpan.Zero, () => 2, null, directory);
            var file = Assert.Single(Directory.GetFiles(directory));
            var before = File.ReadAllBytes(file);
            CleanupFailureObserver.ObservePhase(identity, "dispose-entered", TimeSpan.MaxValue, () => 9, null, directory);
            Assert.Equal(before, File.ReadAllBytes(file));
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ObservePhase_FailedStateOrSink_PreservesPrimaryException(bool sinkFails)
    {
        var directory = Directory.CreateTempSubdirectory("auth-cleanup-observer-");
        try
        {
            var identity = (new string('d', 64), DateTime.UtcNow);
            if (sinkFails)
                Directory.CreateDirectory(Path.Combine(directory.FullName, $"fixture-{identity.Item1}-dispose-faulted.json"));
            var original = new TaskCanceledException("synthetic-secret");
            var caught = await Assert.ThrowsAsync<TaskCanceledException>(async () =>
            {
                try { await ThrowOriginalAsync(original); }
                catch (Exception exception)
                {
                    CleanupFailureObserver.ObservePhase(identity, "dispose-faulted", TimeSpan.Zero,
                        () => throw new InvalidOperationException("state-secret"), exception, directory.FullName);
                    throw;
                }
            });
            Assert.Same(original, caught);
            Assert.Contains(nameof(ThrowOriginalAsync), caught.StackTrace);
            if (!sinkFails)
            {
                using var document = JsonDocument.Parse(File.ReadAllBytes(Assert.Single(Directory.GetFiles(directory.FullName))));
                Assert.Equal(JsonValueKind.Null, document.RootElement.GetProperty("ownedState").ValueKind);
                Assert.Contains("owned_state=unknown", document.RootElement.GetProperty("failure").GetString());
                Assert.Contains("TaskCanceledException", document.RootElement.GetProperty("failure").GetString());
                Assert.DoesNotContain("state-secret", document.RootElement.GetRawText());
            }
        }
        finally { directory.Delete(true); }
    }

    private static void WithReceiptDirectory(Action<string> action)
    {
        var directory = Directory.CreateTempSubdirectory("auth-cleanup-observer-");
        try { action(directory.FullName); }
        finally { directory.Delete(true); }
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
