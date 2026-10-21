using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Time.Testing;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>
/// Exercises PostgreSQL-backed Google nonce binding, single-use consumption, and expiry.
/// </summary>
/// <param name="postgres">The collection fixture that creates an isolated nonce database.</param>
[Collection(PostgresCollection.Name)]
public sealed class GoogleIdentityNonceServiceTests(PostgresFixture postgres)
{
    private static readonly DateTimeOffset Now = new(2026, 7, 27, 0, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// Checks a nonce is consumable once and cannot be reused across service or application bindings.
    /// </summary>
    /// <returns>A task that completes when the regression assertions have finished.</returns>
    [Fact]
    public async Task IssueAndConsume_BindsApplicationAndService_AndAllowsOnlyOneUse()
    {
        await using var context = await postgres.CreateStateContextAsync();
        var service = CreateService(context, new FakeTimeProvider(Now));

        var issued = await service.IssueAsync("legacy-intranet", "intranet", default);

        Assert.InRange(issued.Nonce.Length, 43, 44);
        Assert.True(await service.ConsumeAsync(issued.Nonce, "legacy-intranet", "intranet", default));
        Assert.False(await service.ConsumeAsync(issued.Nonce, "legacy-intranet", "intranet", default));
        Assert.False(await service.ConsumeAsync(issued.Nonce, "other-service", "intranet", default));
        Assert.False(await service.ConsumeAsync(issued.Nonce, "legacy-intranet", "other-app", default));
    }

    /// <summary>
    /// Checks a nonce cannot be consumed after its configured lifetime expires.
    /// </summary>
    /// <returns>A task that completes when the regression assertions have finished.</returns>
    [Fact]
    public async Task Consume_ExpiredNonce_FailsClosed()
    {
        await using var context = await postgres.CreateStateContextAsync();
        var clock = new FakeTimeProvider(Now);
        var service = CreateService(context, clock);

        var issued = await service.IssueAsync("legacy-intranet", "intranet", default);
        clock.Advance(TimeSpan.FromMinutes(11));

        Assert.False(await service.ConsumeAsync(issued.Nonce, "legacy-intranet", "intranet", default));
    }

    private static GoogleIdentityNonceService CreateService(
        Legacy.Maliev.AuthService.Infrastructure.RefreshSessionDbContext context,
        FakeTimeProvider clock)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["GoogleIdentity:NonceLifetimeMinutes"] = "10",
            })
            .Build();
        return new(context, configuration, clock);
    }
}
