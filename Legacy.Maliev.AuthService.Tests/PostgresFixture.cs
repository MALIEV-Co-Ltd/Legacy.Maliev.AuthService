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

    public async Task DisposeAsync() => await postgres.DisposeAsync();

    public async Task<CustomerIdentityDbContext> CreateCustomerContextAsync()
    {
        var context = new CustomerIdentityDbContext(
            new DbContextOptionsBuilder<CustomerIdentityDbContext>()
                .UseNpgsql(await CreateDatabaseAsync())
                .Options);
        await context.Database.MigrateAsync();
        return context;
    }

    public async Task<EmployeeIdentityDbContext> CreateEmployeeContextAsync()
    {
        var context = new EmployeeIdentityDbContext(
            new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
                .UseNpgsql(await CreateDatabaseAsync())
                .Options);
        await context.Database.MigrateAsync();
        return context;
    }

    public async Task<RefreshSessionDbContext> CreateStateContextAsync()
    {
        var context = new RefreshSessionDbContext(
            new DbContextOptionsBuilder<RefreshSessionDbContext>()
                .UseNpgsql(await CreateDatabaseAsync())
                .Options);
        await context.Database.MigrateAsync();
        return context;
    }

    private async Task<string> CreateDatabaseAsync()
    {
        var database = $"auth_test_{Guid.NewGuid():N}";
        await using var connection = new NpgsqlConnection(postgres.GetConnectionString());
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"CREATE DATABASE \"{database}\"";
        await command.ExecuteNonQueryAsync();
        var builder = new NpgsqlConnectionStringBuilder(postgres.GetConnectionString()) { Database = database };
        return builder.ConnectionString;
    }
}
