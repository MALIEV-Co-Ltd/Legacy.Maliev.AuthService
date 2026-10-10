using System.Diagnostics;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.AuthService.Tests;

[CollectionDefinition(Name)]
public sealed class PostgresCollection : ICollectionFixture<PostgresFixture>
{
    public const string Name = "PostgreSQL integration";
}

public sealed class PostgresFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer postgres = new PostgreSqlBuilder("postgres:18-alpine").Build();

    public Task InitializeAsync() => postgres.StartAsync();

    public async Task DisposeAsync()
    {
        var started = Stopwatch.GetTimestamp();
        try { await postgres.DisposeAsync(); }
        catch (Exception exception)
        {
            CleanupFailureObserver.Observe(exception, Stopwatch.GetElapsedTime(started),
                () => (int)postgres.State, Console.Error.WriteLine);
            throw;
        }
    }

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

    internal async Task<int> CountDatabaseBackendsAsync(string connectionString)
    {
        var database = new NpgsqlConnectionStringBuilder(connectionString).Database;
        await using var connection = new NpgsqlConnection(
            new NpgsqlConnectionStringBuilder(postgres.GetConnectionString()) { Pooling = false }.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandTimeout = 5;
        command.CommandText = "SELECT count(*)::int FROM pg_stat_activity WHERE datname = @database";
        command.Parameters.AddWithValue("database", database!);
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
