using System.Diagnostics;
using Microsoft.EntityFrameworkCore;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class PostgresFixtureConnectionLifetimeTests(PostgresFixture postgres)
{
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
            Assert.Equal(1, await postgres.CountDatabaseBackendsAsync(connectionString));
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
