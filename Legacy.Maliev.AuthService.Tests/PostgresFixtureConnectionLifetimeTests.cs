using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>
/// Verifies fixture-created isolated identity contexts release their database connections.
/// </summary>
/// <param name="postgres">The shared fixture that owns the disposable PostgreSQL container.</param>
[Collection(PostgresCollection.Name)]
public sealed class PostgresFixtureConnectionLifetimeTests(PostgresFixture postgres)
{
    /// <summary>
    /// Verifies disposing an isolated context releases its PostgreSQL backend.
    /// </summary>
    /// <param name="kind">The identity or isolated-context kind selected by the test case.</param>
    /// <returns>A task that completes after the regression assertions finish.</returns>
    [Theory]
    [InlineData("customer")]
    [InlineData("employee")]
    [InlineData("state")]
    public async Task DisposedIsolatedContext_ReleasesItsDatabaseBackend(string kind)
    {
        DbContext context = kind switch
        {
            "customer" => await postgres.CreateCustomerContextAsync(),
            "employee" => await postgres.CreateEmployeeContextAsync(),
            _ => await postgres.CreateStateContextAsync(),
        };
        var connectionString = context.Database.GetConnectionString()!;
        try
        {
            await context.Database.OpenConnectionAsync();
            var connection = (NpgsqlConnection)context.Database.GetDbConnection();
            Assert.Equal(1, await postgres.CountDatabaseBackendsAsync(connectionString, connection.ProcessID));
        }
        finally { await context.DisposeAsync(); }

        var started = Stopwatch.StartNew();
        int remaining;
        do
        {
            remaining = await postgres.CountDatabaseBackendsAsync(connectionString);
            if (remaining == 0) break;
            await Task.Delay(50);
        } while (started.Elapsed < TimeSpan.FromSeconds(5));

        Assert.Equal(0, remaining);
    }
}
