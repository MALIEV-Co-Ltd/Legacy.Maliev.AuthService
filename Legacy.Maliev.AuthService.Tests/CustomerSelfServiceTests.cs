using Legacy.Maliev.AuthService.Api.Authorization;
using Legacy.Maliev.AuthService.Api.Controllers;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Time.Testing;
using System.Reflection;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class CustomerSelfServiceTests(PostgresFixture postgres)
{
    [Fact]
    public void Controller_UsesAuthenticatedJsonPostsAndNeverPlacesPasswordOrTokenInRoutes()
    {
        var controller = typeof(CustomerSelfServiceController);
        Assert.NotEmpty(controller.GetCustomAttributes<AuthorizeAttribute>());
        var methods = controller.GetMethods(BindingFlags.Instance | BindingFlags.Public).Where(method => method.DeclaringType == controller).ToArray();
        Assert.All(methods, method => Assert.NotEmpty(method.GetCustomAttributes<HttpPostAttribute>()));
        Assert.All(methods, method => Assert.Contains(method.GetCustomAttributes<RequirePermissionAttribute>(), attribute => attribute.Permission == CustomerSelfServicePermissions.Use));
        Assert.DoesNotContain(
            methods.SelectMany(method => method.GetCustomAttributes<HttpPostAttribute>()),
            attribute => attribute.Template?.Contains("{password", StringComparison.OrdinalIgnoreCase) == true
                || attribute.Template?.Contains("{token", StringComparison.OrdinalIgnoreCase) == true);
    }
    [Fact]
    public async Task Register_NewCustomer_PersistsCompatiblePasswordHashWithoutReturningSecurityMaterial()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);

        var result = await fixture.Service.RegisterAsync(
            new RegisterCustomerIdentityRequest(42, "customer@example.com", "correct-password"), default);

        Assert.True(result.Succeeded);
        var stored = await fixture.Customers.Users.SingleAsync();
        Assert.Equal(42, stored.DatabaseID);
        Assert.False(stored.EmailConfirmed);
        Assert.Equal(PasswordVerificationResult.Success, fixture.Hasher.VerifyHashedPassword(stored, stored.PasswordHash!, "correct-password"));
        Assert.DoesNotContain("Password", typeof(CustomerSelfServiceResult).GetProperties().Select(property => property.Name));
    }

    [Fact]
    public async Task RequestConfirmation_KnownIdentity_ReturnsOpaqueTokenButStoresOnlyHash()
    {
        await using var fixture = await Fixture.CreateAsync(postgres); await fixture.SeedCustomerAsync();

        var challenge = await fixture.Service.RequestEmailConfirmationAsync(new CustomerActionRequest("customer@example.com"), default);

        Assert.True(challenge.Accepted); Assert.NotNull(challenge.Token);
        var stored = await fixture.State.IdentityActionTokens.SingleAsync();
        Assert.NotEqual(challenge.Token, stored.TokenHash);
        Assert.Equal(64, stored.TokenHash.Length);
        Assert.Equal("email-confirmation", stored.Purpose);
    }

    [Fact]
    public async Task CompletePasswordReset_ValidToken_ChangesPasswordAndRejectsReplay()
    {
        await using var fixture = await Fixture.CreateAsync(postgres); await fixture.SeedCustomerAsync();
        var challenge = await fixture.Service.RequestPasswordResetAsync(new CustomerActionRequest("customer@example.com"), default);

        var first = await fixture.Service.CompletePasswordResetAsync(new CompletePasswordResetRequest("customer@example.com", challenge.Token!, "new-password"), default);
        var replay = await fixture.Service.CompletePasswordResetAsync(new CompletePasswordResetRequest("customer@example.com", challenge.Token!, "another-password"), default);

        Assert.True(first); Assert.False(replay);
        var stored = await fixture.Customers.Users.SingleAsync();
        Assert.Equal(PasswordVerificationResult.Success, fixture.Hasher.VerifyHashedPassword(stored, stored.PasswordHash!, "new-password"));
    }

    [Fact]
    public async Task RequestPasswordReset_SecondChallengeSupersedesFirstChallenge()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedCustomerAsync();
        var first = await fixture.Service.RequestPasswordResetAsync(
            new CustomerActionRequest("customer@example.com"), default);
        var second = await fixture.Service.RequestPasswordResetAsync(
            new CustomerActionRequest("customer@example.com"), default);

        var staleResult = await fixture.Service.CompletePasswordResetAsync(
            new CompletePasswordResetRequest("customer@example.com", first.Token!, "stale-password"), default);
        var currentResult = await fixture.Service.CompletePasswordResetAsync(
            new CompletePasswordResetRequest("customer@example.com", second.Token!, "current-password"), default);

        Assert.False(staleResult);
        Assert.True(currentResult);
    }

    [Fact]
    public async Task ConfirmEmail_ExpiredToken_IsRejectedWithoutChangingIdentity()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 7, 15, 0, 0, 0, TimeSpan.Zero));
        await using var fixture = await Fixture.CreateAsync(postgres, clock); await fixture.SeedCustomerAsync();
        var challenge = await fixture.Service.RequestEmailConfirmationAsync(new CustomerActionRequest("customer@example.com"), default);
        clock.Advance(TimeSpan.FromHours(25));

        var confirmed = await fixture.Service.ConfirmEmailAsync(new CompleteCustomerActionRequest("customer@example.com", challenge.Token!), default);

        Assert.False(confirmed); Assert.False((await fixture.Customers.Users.SingleAsync()).EmailConfirmed);
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private Fixture(
            CustomerIdentityDbContext customers,
            RefreshSessionDbContext state,
            TimeProvider? timeProvider)
        {
            Customers = customers;
            State = state;
            Hasher = new PasswordHasher<LegacyIdentityRow>();
            Service = new CustomerSelfService(Customers, State, Hasher, timeProvider ?? TimeProvider.System);
        }
        public CustomerIdentityDbContext Customers { get; }
        public RefreshSessionDbContext State { get; }
        public PasswordHasher<LegacyIdentityRow> Hasher { get; }
        public CustomerSelfService Service { get; }
        public static async Task<Fixture> CreateAsync(PostgresFixture postgres, TimeProvider? timeProvider = null) =>
            new(
                await postgres.CreateCustomerContextAsync(),
                await postgres.CreateStateContextAsync(),
                timeProvider);
        public async Task SeedCustomerAsync()
        {
            var row = new LegacyIdentityRow { Id = "customer-id", DatabaseID = 42, UserName = "customer@example.com", NormalizedUserName = "CUSTOMER@EXAMPLE.COM", Email = "customer@example.com", NormalizedEmail = "CUSTOMER@EXAMPLE.COM", SecurityStamp = Guid.NewGuid().ToString(), ConcurrencyStamp = Guid.NewGuid().ToString(), LockoutEnabled = true };
            row.PasswordHash = Hasher.HashPassword(row, "old-password"); Customers.Users.Add(row); await Customers.SaveChangesAsync();
        }
        public async ValueTask DisposeAsync() { await Customers.DisposeAsync(); await State.DisposeAsync(); }
    }
}
