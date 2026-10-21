using System.Diagnostics;
using System.Runtime.ExceptionServices;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>
/// Defines the shared PostgreSQL test collection so its owned database container is reused only within the collection.
/// </summary>
[CollectionDefinition(Name)]
public sealed class PostgresCollection : ICollectionFixture<PostgresFixture>
{
    /// <summary>
    /// Identifies the collection used to serialize tests sharing the PostgreSQL fixture.
    /// </summary>
    public const string Name = "PostgreSQL integration";
}

/// <summary>
/// Owns the bounded PostgreSQL integration container and creates a separate migrated database for each requested context.
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer postgres = new PostgreSqlBuilder("postgres:18-alpine")
        .WithLabel("MALIEV_TEST_RUN_ID",
            Environment.GetEnvironmentVariable("MALIEV_TEST_RUN_ID") is { Length: > 0 } runId
                ? runId : Guid.NewGuid().ToString("N"))
        .WithCreateParameterModifier(parameters =>
        {
            parameters.HostConfig ??= new();
            parameters.HostConfig.Memory = 512L * 1024 * 1024;
            parameters.HostConfig.NanoCPUs = 2_000_000_000L;
        })
        .Build();

    private readonly Lazy<Task> cleanup;

    /// <summary>
    /// Creates the single shared cleanup task that stops and removes this fixture's owned container.
    /// </summary>
    public PostgresFixture()
    {
        cleanup = CreateContainerCleanup(postgres.StopAsync, postgres.DisposeAsync);
    }

    internal static Lazy<Task> CreateContainerCleanup(Func<CancellationToken, Task> stop,
        Func<ValueTask> remove, TimeProvider? clock = null) =>
        new(() => StopThenRemoveAsync(stop, remove, clock ?? TimeProvider.System),
            LazyThreadSafetyMode.ExecutionAndPublication);

    private static async Task StopThenRemoveAsync(Func<CancellationToken, Task> stop,
        Func<ValueTask> remove, TimeProvider clock)
    {
        Exception? stopFailure = null;
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30), clock);
            await stop(deadline.Token);
        }
        catch (Exception exception) { stopFailure = exception; }
        finally
        {
            // Removal has its own existing client bound, not the cancelled stop token.
            try { await remove(); }
            catch (Exception removalFailure) when (stopFailure is not null)
            {
                throw new AggregateException("Owned PostgreSQL stop and removal failed.",
                    stopFailure, removalFailure);
            }
        }
        if (stopFailure is not null) ExceptionDispatchInfo.Capture(stopFailure).Throw();
    }

    /// <summary>
    /// Starts the owned container with the existing bounded startup cancellation window.
    /// </summary>
    /// <returns>A task that completes when PostgreSQL is ready for fixture databases.</returns>
    public async Task InitializeAsync()
    {
        using var startup = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        await postgres.StartAsync(startup.Token);
    }

    /// <summary>
    /// Awaits idempotent stop and removal, reporting cleanup failure without suppressing its exception.
    /// </summary>
    /// <returns>A task that completes after owned-container cleanup or propagates its failure.</returns>
    public async Task DisposeAsync()
    {
        var started = Stopwatch.GetTimestamp();
        try { await cleanup.Value; }
        catch (Exception exception)
        {
            CleanupFailureObserver.Observe(exception, Stopwatch.GetElapsedTime(started),
                () => (int)postgres.State, Console.Error.WriteLine,
                report => CleanupFailureObserver.WriteReceipt(report, postgres.Id, Environment.GetEnvironmentVariable));
            throw;
        }
    }

    /// <summary>
    /// Creates and migrates an independent customer Identity database, disposing the context if migration fails.
    /// </summary>
    /// <param name="registerPool">An optional callback that records the context connection for caller-owned pool cleanup.</param>
    /// <returns>The migrated customer context, whose disposal belongs to the caller.</returns>
    public async Task<CustomerIdentityDbContext> CreateCustomerContextAsync(Action<NpgsqlConnection>? registerPool = null)
    {
        var context = new CustomerIdentityDbContext(
            new DbContextOptionsBuilder<CustomerIdentityDbContext>()
                .UseNpgsql(await CreateDatabaseAsync())
                .Options);
        registerPool?.Invoke((NpgsqlConnection)context.Database.GetDbConnection());
        try
        {
            await context.Database.MigrateAsync();
            return context;
        }
        catch
        {
            await context.DisposeAsync();
            throw;
        }
    }

    /// <summary>
    /// Creates and migrates an independent employee Identity database, disposing the context if migration fails.
    /// </summary>
    /// <param name="registerPool">An optional callback that records the context connection for caller-owned pool cleanup.</param>
    /// <returns>The migrated employee context, whose disposal belongs to the caller.</returns>
    public async Task<EmployeeIdentityDbContext> CreateEmployeeContextAsync(Action<NpgsqlConnection>? registerPool = null)
    {
        var context = new EmployeeIdentityDbContext(
            new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
                .UseNpgsql(await CreateDatabaseAsync())
                .Options);
        registerPool?.Invoke((NpgsqlConnection)context.Database.GetDbConnection());
        try
        {
            await context.Database.MigrateAsync();
            return context;
        }
        catch
        {
            await context.DisposeAsync();
            throw;
        }
    }

    /// <summary>
    /// Creates and migrates an independent refresh-session database, disposing the context if migration fails.
    /// </summary>
    /// <param name="registerPool">An optional callback that records the context connection for caller-owned pool cleanup.</param>
    /// <returns>The migrated session-state context, whose disposal belongs to the caller.</returns>
    public async Task<RefreshSessionDbContext> CreateStateContextAsync(Action<NpgsqlConnection>? registerPool = null)
    {
        var context = new RefreshSessionDbContext(
            new DbContextOptionsBuilder<RefreshSessionDbContext>()
                .UseNpgsql(await CreateDatabaseAsync())
                .Options);
        registerPool?.Invoke((NpgsqlConnection)context.Database.GetDbConnection());
        try
        {
            await context.Database.MigrateAsync();
            return context;
        }
        catch
        {
            await context.DisposeAsync();
            throw;
        }
    }

    internal async Task<int> CountDatabaseBackendsAsync(string connectionString, int? backendProcessId = null)
    {
        var database = new NpgsqlConnectionStringBuilder(connectionString).Database;
        await using var connection = new NpgsqlConnection(
            new NpgsqlConnectionStringBuilder(postgres.GetConnectionString()) { Pooling = false }.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandTimeout = 5;
        command.CommandText = "SELECT count(*)::int FROM pg_stat_activity WHERE datname = @database";
        command.Parameters.AddWithValue("database", database!);
        if (backendProcessId is { } processId)
        {
            command.CommandText += " AND pid = @pid";
            command.Parameters.AddWithValue("pid", processId);
        }
        return (int)(await command.ExecuteScalarAsync())!;
    }

    internal async Task<string> CreateDatabaseAsync()
    {
        var database = $"auth_test_{Guid.NewGuid():N}";
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(postgres.GetConnectionString()) { Pooling = false }.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"CREATE DATABASE \"{database}\"";
        await command.ExecuteNonQueryAsync();
        var builder = new NpgsqlConnectionStringBuilder(postgres.GetConnectionString()) { Database = database, Pooling = false };
        return builder.ConnectionString;
    }
}
