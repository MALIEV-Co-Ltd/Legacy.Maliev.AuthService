using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>
/// Verifies canonical email ownership and transaction locking against retained historical identity values.
/// </summary>
/// <param name="postgres">The shared fixture that owns the disposable PostgreSQL container.</param>
[Collection(PostgresCollection.Name)]
public sealed class CanonicalEmailOwnershipTests(PostgresFixture postgres) : IAsyncLifetime
{
    // Each test owns unique database pools. Clear only those pools after the
    // method's await-using contexts and concurrent operations have completed.
    private readonly List<NpgsqlConnection> ownedPools = [];

    /// <summary>
    /// Completes initialization without starting resources beyond the shared fixture.
    /// </summary>
    /// <returns>A task that completes when fixture initialization is finished.</returns>
    public Task InitializeAsync() => Task.CompletedTask;

    /// <summary>
    /// Clears only the database pools registered by these ownership regressions.
    /// </summary>
    /// <returns>A task that completes after fixture-owned resources are released.</returns>
    public Task DisposeAsync()
    {
        foreach (var connection in ownedPools) NpgsqlConnection.ClearPool(connection);
        ownedPools.Clear();
        return Task.CompletedTask;
    }

    private void RegisterPool(NpgsqlConnection connection) => ownedPools.Add(connection);

    /// <summary>
    /// Verifies a historical email representation cannot claim another canonical owner's identity.
    /// </summary>
    /// <param name="employee">Whether the case exercises employee rather than customer identity storage.</param>
    /// <param name="suppliedEmail">The submitted email representation used to challenge canonical ownership.</param>
    /// <param name="historicalEmail">The persisted historical email representation owned by another identity.</param>
    /// <returns>A task that completes after the regression assertions finish.</returns>
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
            ? await postgres.CreateEmployeeContextAsync(RegisterPool)
            : await postgres.CreateCustomerContextAsync(RegisterPool);
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

    /// <summary>
    /// Verifies historical user names cannot bypass canonical ownership through compatibility folding.
    /// </summary>
    /// <param name="employee">Whether the case exercises employee rather than customer identity storage.</param>
    /// <returns>A task that completes after the regression assertions finish.</returns>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HistoricalUserName_DeniesCanonicalOtherOwnerWithoutCompatibilityFolding(bool employee)
    {
        await using LegacyIdentityDbContext context = employee
            ? await postgres.CreateEmployeeContextAsync(RegisterPool)
            : await postgres.CreateCustomerContextAsync(RegisterPool);
        context.Users.Add(new()
        {
            Id = "historical-username",
            UserName = "\u212a-user",
            NormalizedUserName = "\u212a-USER",
            Email = "other@identity.test",
            NormalizedEmail = "OTHER@IDENTITY.TEST",
            SecurityStamp = "retained-security",
            ConcurrencyStamp = "retained-concurrency",
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

    /// <summary>
    /// Verifies canonical aliases share one transaction lock and rollback releases that lock.
    /// </summary>
    /// <returns>A task that completes after the regression assertions finish.</returns>
    [Fact]
    public async Task CanonicalAliases_ContendOnOneTransactionLockAndReleaseAfterRollback()
    {
        await using var first = await postgres.CreateCustomerContextAsync(RegisterPool);
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
