using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class CustomerCanonicalWriteTests(PostgresFixture postgres)
{
    [Fact]
    public async Task KeyedCreate_CanonicalKeyNeverChangesRawPayloadReceiptOrReplayOwnership()
    {
        await using var schema = await postgres.CreateCustomerContextAsync();
        var connection = new Npgsql.NpgsqlConnectionStringBuilder(schema.Database.GetConnectionString()) { MaxPoolSize = 1 };
        await using var context = new CustomerIdentityDbContext(new DbContextOptionsBuilder<CustomerIdentityDbContext>()
            .UseNpgsql(connection.ConnectionString).Options);
        var service = NewService(context);
        var request = new CreateCustomerIdentityRequest("customer-user", "cafe\u0301@identity.test", "abcdef", false, null, null, null);
        var key = Guid.NewGuid();
        Assert.Equal(CustomerIdentityCreateOutcome.Created,
            (await service.CreateOrReconcileAsync(42, "service:legacy-intranet", key, request, default)).Outcome);
        var receipt = await context.CreateOperations.AsNoTracking().SingleAsync();
        var originalHash = receipt.PayloadHash.ToArray();
        var originalSalt = receipt.PayloadSalt.ToArray();
        var independentRawHash = Rfc2898DeriveBytes.Pbkdf2(JsonSerializer.SerializeToUtf8Bytes(request),
            originalSalt, 210_000, HashAlgorithmName.SHA256, 32);
        Assert.Equal(independentRawHash, originalHash);
        Assert.Equal(CustomerIdentityCreateOutcome.Replayed,
            (await service.CreateOrReconcileAsync(42, "service:legacy-intranet", key, request, default)).Outcome);
        Assert.Equal(CustomerIdentityCreateOutcome.Conflict,
            (await service.CreateOrReconcileAsync(42, "service:legacy-intranet", key,
                request with { Email = "caf\u00e9@identity.test" }, default)).Outcome);
        Assert.Equal(CustomerIdentityCreateOutcome.Conflict,
            (await service.CreateOrReconcileAsync(42, "service:other", key, request, default)).Outcome);
        var after = await context.CreateOperations.AsNoTracking().SingleAsync();
        Assert.Equal(originalHash, after.PayloadHash);
        Assert.Equal(originalSalt, after.PayloadSalt);
        var user = Assert.Single(await context.Users.AsNoTracking().ToListAsync());
        Assert.Equal(request.Email, user.Email);
        Assert.Equal("CAF\u00c9@IDENTITY.TEST", user.NormalizedEmail);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConcurrentCanonicalAliases_CommitOneIdentityAndOnlyItsReceipt(bool keyed)
    {
        await using var first = await postgres.CreateCustomerContextAsync();
        await using var second = new CustomerIdentityDbContext(new DbContextOptionsBuilder<CustomerIdentityDbContext>()
            .UseNpgsql(first.Database.GetConnectionString()).Options);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var firstRequest = new CreateCustomerIdentityRequest("first-user", "cafe\u0301@identity.test", "abcdef", false, null, null, null);
        var secondRequest = firstRequest with { UserName = "second-user", Email = "caf\u00e9@identity.test" };
        if (keyed)
        {
            var results = await Task.WhenAll(
                NewService(first).CreateOrReconcileAsync(42, "service:legacy-intranet", Guid.NewGuid(), firstRequest, deadline.Token),
                NewService(second).CreateOrReconcileAsync(43, "service:legacy-intranet", Guid.NewGuid(), secondRequest, deadline.Token));
            Assert.Single(results.Where(value => value.Outcome == CustomerIdentityCreateOutcome.Created));
            Assert.Single(results.Where(value => value.Outcome == CustomerIdentityCreateOutcome.Conflict));
            Assert.Single(await first.CreateOperations.AsNoTracking().ToListAsync(deadline.Token));
        }
        else
        {
            var results = await Task.WhenAll(NewService(first).CreateAsync(42, firstRequest, deadline.Token),
                NewService(second).CreateAsync(43, secondRequest, deadline.Token));
            Assert.Single(results.Where(value => value is not null));
            Assert.Empty(await first.CreateOperations.AsNoTracking().ToListAsync(deadline.Token));
        }
        var stored = Assert.Single(await first.Users.AsNoTracking().ToListAsync(deadline.Token));
        Assert.Equal("CAF\u00c9@IDENTITY.TEST", stored.NormalizedEmail);
    }

    private static CustomerIdentityAdminService NewService(CustomerIdentityDbContext context) =>
        new(context, new PasswordHasher<LegacyIdentityRow>());

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConcurrentAdministrativeAndWebCreation_ShareEmailAndProfileOwnership(bool sameProfile)
    {
        await using var first = await postgres.CreateCustomerContextAsync();
        await using var second = new CustomerIdentityDbContext(new DbContextOptionsBuilder<CustomerIdentityDbContext>()
            .UseNpgsql(first.Database.GetConnectionString()).Options);
        await using var state = await postgres.CreateStateContextAsync();
        var self = new CustomerSelfService(second, state, new PasswordHasher<LegacyIdentityRow>(), TimeProvider.System);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var admin = NewService(first).CreateAsync(42,
            new("admin-user", sameProfile ? "admin@identity.test" : "\u212a@identity.test", "abcdef", false, null, null, null), deadline.Token);
        var web = self.RegisterAsync(new(sameProfile ? 42 : 43,
            sameProfile ? "web@identity.test" : "k@identity.test", "correct-password"), deadline.Token);
        await Task.WhenAll(admin, web);
        Assert.Equal(1, (await admin is not null ? 1 : 0) + ((await web).Succeeded ? 1 : 0));
        Assert.Single(await first.Users.AsNoTracking().ToListAsync(deadline.Token));
        Assert.Empty(await first.CreateOperations.AsNoTracking().ToListAsync(deadline.Token));
    }
}
