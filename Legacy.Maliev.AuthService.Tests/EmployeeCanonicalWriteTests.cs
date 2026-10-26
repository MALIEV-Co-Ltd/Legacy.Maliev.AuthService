using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>
/// Exercises new employee email canonicalization while preserving historical keys and per-test pool ownership.
/// </summary>
/// <param name="postgres">The collection-owned fixture that creates isolated PostgreSQL stores for each case.</param>
[Collection(PostgresCollection.Name)]
public sealed class EmployeeCanonicalWriteTests(PostgresFixture postgres) : IAsyncLifetime
{
    // Each test owns unique database pools. Clear only those pools after the
    // method's await-using contexts and concurrent operations have completed.
    private readonly List<NpgsqlConnection> ownedPools = [];

    /// <summary>
    /// Completes fixture initialization without allocating additional resources.
    /// </summary>
    /// <returns>A completed initialization task.</returns>
    public Task InitializeAsync() => Task.CompletedTask;

    /// <summary>
    /// Clears only the connection pools registered by this test instance after its operations complete.
    /// </summary>
    /// <returns>A completed task after the owned connection pools have been cleared.</returns>
    public Task DisposeAsync()
    {
        foreach (var connection in ownedPools) NpgsqlConnection.ClearPool(connection);
        ownedPools.Clear();
        return Task.CompletedTask;
    }

    private void RegisterPool(NpgsqlConnection connection) => ownedPools.Add(connection);

    /// <summary>
    /// Checks canonicalization of a new lookup key without changing the submitted email.
    /// </summary>
    /// <param name="email">The raw email submitted for identity creation.</param>
    /// <param name="canonical">The canonical normalized email expected for the new identity.</param>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Theory]
    [InlineData("cafe\u0301@identity.test", "CAF\u00c9@IDENTITY.TEST")]
    [InlineData("\u00c5\u0301@identity.test", "\u01fa@IDENTITY.TEST")]
    public async Task Creation_CanonicalizesOnlyNewKeyAndPreservesRawEmail(string email, string canonical)
    {
        await using var context = await postgres.CreateEmployeeContextAsync(RegisterPool);
        var service = NewService(context);
        Assert.NotNull(await service.CreateAsync(42, new("new-user", email, "abcdef", false, null), default));
        var stored = Assert.Single(await context.Users.AsNoTracking().ToListAsync());
        Assert.Equal(email, stored.Email);
        Assert.Equal(canonical, stored.NormalizedEmail);
        Assert.Equal("NEW-USER", stored.NormalizedUserName);
    }

    /// <summary>
    /// Checks that a historical canonical alias blocks creation without rewriting its retained key or stamps.
    /// </summary>
    /// <param name="historicalEmail">The retained email whose canonical alias must prevent another owner.</param>
    /// <param name="email">The raw email submitted for identity creation.</param>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Theory]
    [InlineData("cafe\u0301@identity.test", "caf\u00e9@identity.test")]
    [InlineData("\u00c5\u0301@identity.test", "\u01fa@identity.test")]
    public async Task HistoricalOtherOwner_DeniesCreateWithoutRewritingRetainedKey(string historicalEmail, string email)
    {
        await using var context = await postgres.CreateEmployeeContextAsync(RegisterPool);
        var historical = new LegacyIdentityRow
        {
            Id = "historical",
            DatabaseID = 7,
            UserName = "historical-user",
            NormalizedUserName = "HISTORICAL-USER",
            Email = historicalEmail,
            NormalizedEmail = historicalEmail.ToUpperInvariant(),
            SecurityStamp = "original-security",
            ConcurrencyStamp = "original-concurrency",
        };
        context.Users.Add(historical);
        await context.SaveChangesAsync();
        context.ChangeTracker.Clear();
        Assert.Null(await NewService(context).CreateAsync(42, new("different-user", email, "abcdef", false, null), default));
        var stored = Assert.Single(await context.Users.AsNoTracking().ToListAsync());
        Assert.Equal(historical.NormalizedEmail, stored.NormalizedEmail);
        Assert.Equal("original-security", stored.SecurityStamp);
        Assert.Equal("original-concurrency", stored.ConcurrencyStamp);
    }

    /// <summary>
    /// Checks that concurrent canonical aliases with distinct user names create only one owner.
    /// </summary>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Fact]
    public async Task ConcurrentCanonicalAliases_CreateOneOwnerAcrossDistinctUserNames()
    {
        await using var first = await postgres.CreateEmployeeContextAsync(RegisterPool);
        await using var second = new EmployeeIdentityDbContext(new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
            .UseNpgsql(first.Database.GetConnectionString()).Options);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var results = await Task.WhenAll(
            NewService(first).CreateAsync(42, new("first-user", "cafe\u0301@identity.test", "abcdef", false, null), deadline.Token),
            NewService(second).CreateAsync(43, new("second-user", "caf\u00e9@identity.test", "abcdef", false, null), deadline.Token));
        Assert.Single(results, value => value is not null);
        var stored = Assert.Single(await first.Users.AsNoTracking().ToListAsync(deadline.Token));
        Assert.Equal("CAF\u00c9@IDENTITY.TEST", stored.NormalizedEmail);
    }

    private static EmployeeIdentityAdminService NewService(EmployeeIdentityDbContext context) =>
        new(context, new PasswordHasher<LegacyIdentityRow>(), new EmployeeRecoveryOptions { Enabled = true });
}
