using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class CanonicalEmailOwnershipTests(PostgresFixture postgres)
{
    [Theory]
    [InlineData(false, "caf\u00e9@identity.test", "cafe\u0301@identity.test")]
    [InlineData(true, "caf\u00e9@identity.test", "cafe\u0301@identity.test")]
    [InlineData(false, "\u01fa@identity.test", "\u00c5\u0301@identity.test")]
    [InlineData(true, "\u01fa@identity.test", "\u00c5\u0301@identity.test")]
    [InlineData(false, "\u01fa@identity.test", "A\u030a\u0301@identity.test")]
    [InlineData(true, "\u01fa@identity.test", "A\u030a\u0301@identity.test")]
    public async Task HistoricalRawRepresentation_DeniesOtherOwnerWithoutChangingIdentity(
        bool employee, string suppliedEmail, string historicalEmail)
    {
        await using LegacyIdentityDbContext context = employee
            ? await postgres.CreateEmployeeContextAsync()
            : await postgres.CreateCustomerContextAsync();
        Assert.Equal("UTF8", await context.Database.SqlQuery<string>(
            $"SELECT current_setting('server_encoding') AS \"Value\"").SingleAsync());
        var retainedKey = historicalEmail.Trim().ToUpperInvariant();
        Assert.NotEqual(LegacyIdentityKeyOwnership.CanonicalKey(suppliedEmail), retainedKey);
        var historical = new LegacyIdentityRow
        {
            Id = "historical-identity",
            DatabaseID = 42,
            UserName = "historical-user",
            NormalizedUserName = "HISTORICAL-USER",
            Email = historicalEmail,
            NormalizedEmail = retainedKey,
            SecurityStamp = "retained-security-stamp",
            ConcurrencyStamp = "retained-concurrency-stamp",
            AccessFailedCount = 3,
            EmailConfirmed = true,
        };
        context.Users.Add(historical);
        await context.SaveChangesAsync();
        context.ChangeTracker.Clear();

        Assert.True(await LegacyIdentityKeyOwnership.HasOtherOwnerAsync(context, suppliedEmail, null, default));
        Assert.False(await LegacyIdentityKeyOwnership.HasOtherOwnerAsync(context, suppliedEmail, historical.Id, default));
        Assert.False(await LegacyIdentityKeyOwnership.HasOtherOwnerAsync(context, "unrelated@identity.test", null, default));
        Assert.False(await LegacyIdentityKeyOwnership.HasOtherOwnerAsync(context, "\uff43af\u00e9@identity.test", null, default));
        var unchanged = Assert.Single(await context.Users.AsNoTracking().ToListAsync());
        Assert.Equal(historicalEmail, unchanged.Email);
        Assert.Equal(retainedKey, unchanged.NormalizedEmail);
        Assert.Equal("retained-security-stamp", unchanged.SecurityStamp);
        Assert.Equal("retained-concurrency-stamp", unchanged.ConcurrencyStamp);
        Assert.Equal(3, unchanged.AccessFailedCount);
        Assert.True(unchanged.EmailConfirmed);
        await context.Users.ExecuteUpdateAsync(update => update.SetProperty(value => value.Email, (string?)null));
        Assert.True(await LegacyIdentityKeyOwnership.HasOtherOwnerAsync(context, suppliedEmail, null, default));
        Assert.Equal(retainedKey, (await context.Users.AsNoTracking().SingleAsync()).NormalizedEmail);
        await context.Users.ExecuteUpdateAsync(update => update.SetProperty(value => value.Email, suppliedEmail)
            .SetProperty(value => value.NormalizedEmail, (string?)null));
        Assert.True(await LegacyIdentityKeyOwnership.HasOtherOwnerAsync(context, suppliedEmail, null, default));
        Assert.Null((await context.Users.AsNoTracking().SingleAsync()).NormalizedEmail);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HistoricalUserName_DeniesCanonicalOtherOwnerWithoutCompatibilityFolding(bool employee)
    {
        await using LegacyIdentityDbContext context = employee
            ? await postgres.CreateEmployeeContextAsync()
            : await postgres.CreateCustomerContextAsync();
        context.Users.Add(new()
        {
            Id = "historical-username", UserName = "\u212a-user", NormalizedUserName = "\u212a-USER",
            Email = "other@identity.test", NormalizedEmail = "OTHER@IDENTITY.TEST",
            SecurityStamp = "retained-security", ConcurrencyStamp = "retained-concurrency",
        });
        await context.SaveChangesAsync();
        context.ChangeTracker.Clear();
        Assert.True(await LegacyIdentityKeyOwnership.HasOtherUserNameOwnerAsync(context, "k-user", null, default));
        Assert.False(await LegacyIdentityKeyOwnership.HasOtherUserNameOwnerAsync(context, "k-user", "historical-username", default));
        Assert.False(await LegacyIdentityKeyOwnership.HasOtherUserNameOwnerAsync(context, "\uff4b-user", null, default));
        var retained = Assert.Single(await context.Users.AsNoTracking().ToListAsync());
        Assert.Equal("\u212a-USER", retained.NormalizedUserName);
        Assert.Equal("retained-security", retained.SecurityStamp);
        Assert.Equal("retained-concurrency", retained.ConcurrencyStamp);
    }

    [Fact]
    public async Task CanonicalAliases_ContendOnOneTransactionLockAndReleaseAfterRollback()
    {
        await using var first = await postgres.CreateCustomerContextAsync();
        await using var second = new CustomerIdentityDbContext(
            new DbContextOptionsBuilder<CustomerIdentityDbContext>()
                .UseNpgsql(first.Database.GetConnectionString()).Options);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            LegacyIdentityKeyOwnership.LockAsync(first, "caf\u00e9@identity.test", default));
        await using var firstTransaction = await first.Database.BeginTransactionAsync();
        await using var secondTransaction = await second.Database.BeginTransactionAsync();
        await LegacyIdentityKeyOwnership.LockAsync(first, "cafe\u0301@identity.test", default);
        await LegacyIdentityKeyOwnership.LockUserNameAsync(first, "\u212a-user", default);
        var canonical = LegacyIdentityKeyOwnership.CanonicalKey("caf\u00e9@identity.test");
        Assert.False(await second.Database.SqlQuery<bool>(
            $"SELECT pg_try_advisory_xact_lock(hashtextextended({canonical}, 0)) AS \"Value\"").SingleAsync());
        var canonicalName = "identity-username:K-USER";
        Assert.False(await second.Database.SqlQuery<bool>(
            $"SELECT pg_try_advisory_xact_lock(hashtextextended({canonicalName}, 3)) AS \"Value\"").SingleAsync());
        await firstTransaction.RollbackAsync();
        Assert.True(await second.Database.SqlQuery<bool>(
            $"SELECT pg_try_advisory_xact_lock(hashtextextended({canonical}, 0)) AS \"Value\"").SingleAsync());
        Assert.True(await second.Database.SqlQuery<bool>(
            $"SELECT pg_try_advisory_xact_lock(hashtextextended({canonicalName}, 3)) AS \"Value\"").SingleAsync());
        await secondTransaction.RollbackAsync();
    }
}
