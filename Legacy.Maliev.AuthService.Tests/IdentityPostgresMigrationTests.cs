using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class IdentityPostgresMigrationTests : IAsyncLifetime
{
    private readonly PostgreSqlContainer customerPostgres =
        new PostgreSqlBuilder("postgres:18-alpine").Build();
    private readonly PostgreSqlContainer employeePostgres =
        new PostgreSqlBuilder("postgres:18-alpine").Build();

    [Fact]
    public async Task CustomerMigration_CreatesCompatibleIdentitySchema()
    {
        await using var context = new CustomerIdentityDbContext(
            new DbContextOptionsBuilder<CustomerIdentityDbContext>()
                .UseNpgsql(customerPostgres.GetConnectionString())
                .Options);

        await context.Database.MigrateAsync();

        var columns = await ReadColumnsAsync(context);
        Assert.Contains("Id", columns);
        Assert.Contains("PasswordHash", columns);
        Assert.Contains("DatabaseID", columns);
        Assert.Contains("FaxNumber", columns);
        Assert.Contains("MobileNumber", columns);
        Assert.Contains("NormalizedUserName", columns);
    }

    [Fact]
    public async Task EmployeeMigration_ExcludesCustomerOnlyColumns()
    {
        await using var context = new EmployeeIdentityDbContext(
            new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
                .UseNpgsql(employeePostgres.GetConnectionString())
                .Options);

        await context.Database.MigrateAsync();

        var columns = await ReadColumnsAsync(context);
        Assert.Contains("Id", columns);
        Assert.Contains("PasswordHash", columns);
        Assert.Contains("DatabaseID", columns);
        Assert.DoesNotContain("FaxNumber", columns);
        Assert.DoesNotContain("MobileNumber", columns);
    }

    public Task InitializeAsync() => Task.WhenAll(
        customerPostgres.StartAsync(),
        employeePostgres.StartAsync());

    public async Task DisposeAsync()
    {
        await customerPostgres.DisposeAsync();
        await employeePostgres.DisposeAsync();
    }

    private static Task<List<string>> ReadColumnsAsync(DbContext context) =>
        context.Database.SqlQueryRaw<string>(
                "SELECT column_name AS \"Value\" FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'AspNetUsers'")
            .ToListAsync();
}
