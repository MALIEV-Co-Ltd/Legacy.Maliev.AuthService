using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class EmployeeCanonicalWriteTests(PostgresFixture postgres)
{
    [Theory]
    [InlineData("cafe\u0301@identity.test", "CAF\u00c9@IDENTITY.TEST")]
    [InlineData("\u00c5\u0301@identity.test", "\u01fa@IDENTITY.TEST")]
    public async Task Creation_CanonicalizesOnlyNewKeyAndPreservesRawEmail(string email, string canonical)
    {
        await using var context = await postgres.CreateEmployeeContextAsync();
        var service = NewService(context);
        Assert.NotNull(await service.CreateAsync(42, new("new-user", email, "abcdef", false, null), default));
        var stored = Assert.Single(await context.Users.AsNoTracking().ToListAsync());
        Assert.Equal(email, stored.Email);
        Assert.Equal(canonical, stored.NormalizedEmail);
        Assert.Equal("NEW-USER", stored.NormalizedUserName);
    }

    [Theory]
    [InlineData("cafe\u0301@identity.test", "caf\u00e9@identity.test")]
    [InlineData("\u00c5\u0301@identity.test", "\u01fa@identity.test")]
    public async Task HistoricalOtherOwner_DeniesCreateWithoutRewritingRetainedKey(string historicalEmail, string email)
    {
        await using var context = await postgres.CreateEmployeeContextAsync();
        var historical = new LegacyIdentityRow
        {
            Id = "historical", DatabaseID = 7, UserName = "historical-user",
            NormalizedUserName = "HISTORICAL-USER", Email = historicalEmail,
            NormalizedEmail = historicalEmail.ToUpperInvariant(),
            SecurityStamp = "original-security", ConcurrencyStamp = "original-concurrency",
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

    [Fact]
    public async Task ConcurrentCanonicalAliases_CreateOneOwnerAcrossDistinctUserNames()
    {
        await using var first = await postgres.CreateEmployeeContextAsync();
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
