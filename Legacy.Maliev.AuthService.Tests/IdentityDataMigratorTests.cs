using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class IdentityDataMigratorTests : IAsyncLifetime
{
    private readonly PostgreSqlContainer postgres = new PostgreSqlBuilder("postgres:18-alpine").Build();

    [Fact]
    public void SourceConnection_RequiresExplicitReadOnlyIntent()
    {
        Assert.Throws<InvalidOperationException>(() =>
            IdentityDataMigrator.EnsureReadOnlySqlServerSource(
                "Server=legacy;Database=CustomerIdentity;User Id=copy;Password=not-a-secret;Encrypt=True"));

        IdentityDataMigrator.EnsureReadOnlySqlServerSource(
            "Server=legacy;Database=CustomerIdentity;User Id=copy;Password=not-a-secret;Encrypt=True;ApplicationIntent=ReadOnly");
    }

    [Fact]
    public async Task Copy_PreservesIdentityFields_IsIdempotent_AndValidatesFingerprint()
    {
        await using var target = new CustomerIdentityDbContext(
            new DbContextOptionsBuilder<CustomerIdentityDbContext>()
                .UseNpgsql(postgres.GetConnectionString())
                .Options);
        await target.Database.MigrateAsync();

        var rows = new[]
        {
            new LegacyIdentityRow
            {
                Id = "customer-1",
                UserName = "customer@example.com",
                NormalizedUserName = "CUSTOMER@EXAMPLE.COM",
                Email = "customer@example.com",
                NormalizedEmail = "CUSTOMER@EXAMPLE.COM",
                EmailConfirmed = true,
                PasswordHash = "AQAAAA-unchanged-password-hash",
                SecurityStamp = "security-stamp",
                ConcurrencyStamp = "concurrency-stamp",
                PhoneNumber = "+66810000000",
                PhoneNumberConfirmed = true,
                TwoFactorEnabled = false,
                DatabaseID = 42,
                FaxNumber = "02-000-0000",
                MobileNumber = "081-000-0000",
                LockoutEnabled = true,
                LockoutEnd = DateTimeOffset.Parse("2026-07-15T00:00:00+00:00").AddTicks(9),
                AccessFailedCount = 2
            }
        };

        var first = await IdentityDataMigrator.CopyAndValidateAsync(ToAsync(rows), target, includeCustomerFields: true);
        var second = await IdentityDataMigrator.CopyAndValidateAsync(ToAsync(rows), target, includeCustomerFields: true);

        Assert.Equal(1, first.SourceCount);
        Assert.Equal(first, second);
        var copied = await target.Users.AsNoTracking().SingleAsync();
        Assert.Equal(rows[0].Id, copied.Id);
        Assert.Equal(rows[0].PasswordHash, copied.PasswordHash);
        Assert.Equal(rows[0].DatabaseID, copied.DatabaseID);
        Assert.Equal(rows[0].FaxNumber, copied.FaxNumber);
        var sourceLockoutEnd = Assert.IsType<DateTimeOffset>(rows[0].LockoutEnd);
        Assert.Equal(
            sourceLockoutEnd.AddTicks(-(sourceLockoutEnd.Ticks % 10)),
            copied.LockoutEnd);
    }

    [Fact]
    public async Task Validate_RejectsDestinationDrift()
    {
        await using var target = new CustomerIdentityDbContext(
            new DbContextOptionsBuilder<CustomerIdentityDbContext>()
                .UseNpgsql(postgres.GetConnectionString())
                .Options);
        await target.Database.MigrateAsync();
        var source = new[] { new LegacyIdentityRow { Id = "source", PasswordHash = "preserve" } };
        target.Users.Add(new LegacyIdentityRow { Id = "different", PasswordHash = "drift" });
        await target.SaveChangesAsync();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            IdentityDataMigrator.ValidateAsync(ToAsync(source), target, includeCustomerFields: true));
    }

    public Task InitializeAsync() => postgres.StartAsync();

    public async Task DisposeAsync() => await postgres.DisposeAsync();

    private static async IAsyncEnumerable<LegacyIdentityRow> ToAsync(IEnumerable<LegacyIdentityRow> rows)
    {
        foreach (var row in rows)
        {
            yield return row;
            await Task.Yield();
        }
    }
}
