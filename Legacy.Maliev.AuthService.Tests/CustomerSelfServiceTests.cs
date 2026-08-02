using Legacy.Maliev.AuthService.Api.Authorization;
using Legacy.Maliev.AuthService.Api.Controllers;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
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
        var customerCredentialMethods = new[]
        {
            nameof(CustomerSelfServiceController.ChangeEmail),
            nameof(CustomerSelfServiceController.ChangePassword),
        };
        Assert.All(
            methods.Where(method => customerCredentialMethods.Contains(method.Name, StringComparer.Ordinal)),
            method => Assert.Equal("LegacyCustomer", method.GetCustomAttribute<AuthorizeAttribute>()?.Policy));
        Assert.All(
            methods.Where(method => customerCredentialMethods.Contains(method.Name, StringComparer.Ordinal)),
            method => Assert.Equal(
                "credential-change",
                method.GetCustomAttribute<EnableRateLimitingAttribute>()?.PolicyName));
        Assert.All(
            methods.Where(method => !customerCredentialMethods.Contains(method.Name, StringComparer.Ordinal)),
            method => Assert.Contains(
                method.GetCustomAttributes<RequirePermissionAttribute>(),
                attribute => attribute.Permission == CustomerSelfServicePermissions.Use));
        Assert.DoesNotContain(
            methods.SelectMany(method => method.GetCustomAttributes<HttpPostAttribute>()),
            attribute => attribute.Template?.Contains("{password", StringComparison.OrdinalIgnoreCase) == true
                || attribute.Template?.Contains("{token", StringComparison.OrdinalIgnoreCase) == true);
        Assert.Equal(
            "email-change/validate",
            controller.GetMethod(nameof(CustomerSelfServiceController.ValidateEmailChange))?.GetCustomAttribute<HttpPostAttribute>()?.Template);
        Assert.Equal(
            "email-change/complete",
            controller.GetMethod(nameof(CustomerSelfServiceController.CompleteEmailChange))?.GetCustomAttribute<HttpPostAttribute>()?.Template);
        Assert.Equal(
            "email-confirmation/recover",
            controller.GetMethod(nameof(CustomerSelfServiceController.RecoverEmailConfirmation))?.GetCustomAttribute<HttpPostAttribute>()?.Template);
        Assert.Equal(
            "initial-password/complete",
            controller.GetMethod(nameof(CustomerSelfServiceController.CompleteInitialPassword))?.GetCustomAttribute<HttpPostAttribute>()?.Template);
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
    public async Task InitialPassword_ValidChallenge_ReplacesTemporaryPasswordAndRejectsReplay()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedCustomerAsync(
            password: LegacyIssuedCredential,
            emailConfirmed: true);
        var securityStamp = (await fixture.Customers.Users.AsNoTracking().SingleAsync()).SecurityStamp!;
        var challenge = await fixture.Service.IssueInitialPasswordChallengeAsync(
            "customer-id",
            "customer@example.com",
            securityStamp,
            default);

        var first = await fixture.Service.CompleteInitialPasswordAsync(
            new CompleteInitialPasswordRequest(
                "customer@example.com",
                challenge!,
                CustomerManagedCredential),
            default);
        var replay = await fixture.Service.CompleteInitialPasswordAsync(
            new CompleteInitialPasswordRequest(
                "customer@example.com",
                challenge!,
                "another-password"),
            default);

        Assert.True(first);
        Assert.False(replay);
        var stored = await fixture.Customers.Users.AsNoTracking().SingleAsync();
        Assert.Equal(
            PasswordVerificationResult.Success,
            fixture.Hasher.VerifyHashedPassword(
                stored,
                stored.PasswordHash!,
                CustomerManagedCredential));
        Assert.Equal(0, stored.AccessFailedCount);
        Assert.Null(stored.LockoutEnd);
    }

    [Fact]
    public async Task EmailConfirmationRecovery_ConsumesLoginGrantAndIssuesSingleFreshConfirmation()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedCustomerAsync(emailConfirmed: false);
        var securityStamp = (await fixture.Customers.Users.AsNoTracking().SingleAsync()).SecurityStamp!;
        var recovery = await fixture.Service.IssueEmailConfirmationRecoveryAsync(
            "customer-id",
            "customer@example.com",
            securityStamp,
            default);

        var first = await fixture.Service.RecoverEmailConfirmationAsync(
            new CompleteCustomerActionRequest("customer@example.com", recovery!),
            default);
        var replay = await fixture.Service.RecoverEmailConfirmationAsync(
            new CompleteCustomerActionRequest("customer@example.com", recovery!),
            default);

        Assert.True(first.Accepted);
        Assert.NotNull(first.Token);
        Assert.False(replay.Accepted);
        Assert.Null(replay.Token);
        Assert.Equal(
            2,
            await fixture.State.IdentityActionTokens.CountAsync());
        Assert.Contains(
            await fixture.State.IdentityActionTokens.AsNoTracking().ToListAsync(),
            token => token.Purpose == "email-confirmation"
                && token.TokenHash != first.Token);
    }

    [Fact]
    public async Task EmailConfirmationRecovery_ExpiredOrWrongEmailFailsWithoutIssuingConfirmation()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 7, 15, 0, 0, 0, TimeSpan.Zero));
        await using var fixture = await Fixture.CreateAsync(postgres, clock);
        await fixture.SeedCustomerAsync(emailConfirmed: false);
        var securityStamp = (await fixture.Customers.Users.AsNoTracking().SingleAsync()).SecurityStamp!;
        var recovery = await fixture.Service.IssueEmailConfirmationRecoveryAsync(
            "customer-id",
            "customer@example.com",
            securityStamp,
            default);

        var wrongEmail = await fixture.Service.RecoverEmailConfirmationAsync(
            new CompleteCustomerActionRequest("other@example.com", recovery!),
            default);
        clock.Advance(TimeSpan.FromMinutes(16));
        var expired = await fixture.Service.RecoverEmailConfirmationAsync(
            new CompleteCustomerActionRequest("customer@example.com", recovery!),
            default);

        Assert.False(wrongEmail.Accepted);
        Assert.False(expired.Accepted);
        Assert.DoesNotContain(
            await fixture.State.IdentityActionTokens.AsNoTracking().ToListAsync(),
            token => token.Purpose == "email-confirmation");
    }

    [Fact]
    public async Task InitialPassword_SecurityStampRotationInvalidatesOutstandingChallenge()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedCustomerAsync(
            password: LegacyIssuedCredential,
            emailConfirmed: true);
        var row = await fixture.Customers.Users.SingleAsync();
        var challenge = await fixture.Service.IssueInitialPasswordChallengeAsync(
            row.Id,
            row.Email!,
            row.SecurityStamp!,
            default);
        row.SecurityStamp = Guid.NewGuid().ToString();
        await fixture.Customers.SaveChangesAsync();

        var completed = await fixture.Service.CompleteInitialPasswordAsync(
            new CompleteInitialPasswordRequest(
                row.Email!,
                challenge!,
                CustomerManagedCredential),
            default);

        Assert.False(completed);
        var stored = await fixture.Customers.Users.AsNoTracking().SingleAsync();
        Assert.Equal(
            PasswordVerificationResult.Failed,
            fixture.Hasher.VerifyHashedPassword(
                stored,
                stored.PasswordHash!,
                CustomerManagedCredential));
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

    [Fact]
    public async Task ChangePassword_VerifiesCurrentPasswordRotatesSecurityStampAndRevokesRefreshSessions()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedCustomerAsync();
        await fixture.SeedRefreshSessionAsync();
        var before = (await fixture.Customers.Users.AsNoTracking().SingleAsync()).SecurityStamp;

        var rejected = await fixture.Service.ChangePasswordAsync(
            "customer-id",
            new ChangeCustomerPasswordRequest("wrong-password", "new-password"),
            default);
        var changed = await fixture.Service.ChangePasswordAsync(
            "customer-id",
            new ChangeCustomerPasswordRequest("old-password", "new-password"),
            default);

        Assert.False(rejected);
        Assert.True(changed);
        var stored = await fixture.Customers.Users.AsNoTracking().SingleAsync();
        Assert.NotEqual(before, stored.SecurityStamp);
        Assert.Equal(
            PasswordVerificationResult.Success,
            fixture.Hasher.VerifyHashedPassword(stored, stored.PasswordHash!, "new-password"));
        Assert.NotNull((await fixture.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
    }

    [Fact]
    public async Task ChangeEmail_VerifiesPasswordLeavesIdentityPendingUntilConfirmationAndThenRejectsReplay()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedCustomerAsync();
        await fixture.SeedCustomerAsync(
            id: "other-id",
            databaseId: 43,
            email: "other@example.com");
        await fixture.SeedRefreshSessionAsync();

        var wrongPassword = await fixture.Service.ChangeEmailAsync(
            "customer-id",
            new ChangeCustomerEmailRequest("wrong-password", "new@example.com"),
            default);
        var duplicate = await fixture.Service.ChangeEmailAsync(
            "customer-id",
            new ChangeCustomerEmailRequest("old-password", "other@example.com"),
            default);
        var changed = await fixture.Service.ChangeEmailAsync(
            "customer-id",
            new ChangeCustomerEmailRequest("old-password", "new@example.com"),
            default);

        Assert.Null(wrongPassword);
        Assert.Null(duplicate);
        Assert.NotNull(changed?.Token);
        var stored = await fixture.Customers.Users.AsNoTracking().SingleAsync(value => value.Id == "customer-id");
        Assert.Equal("customer@example.com", stored.Email);
        Assert.Equal("customer@example.com", stored.UserName);
        Assert.False(stored.EmailConfirmed);
        Assert.Null((await fixture.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
        var action = await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync();
        Assert.Equal("email-change", action.Purpose);
        Assert.Equal("new@example.com", action.TargetEmail);
        Assert.Null(await fixture.Service.ValidateEmailChangeAsync(
            new CompleteCustomerActionRequest("customer@example.com", changed!.Token!),
            default));
        var validation = await fixture.Service.ValidateEmailChangeAsync(
            new CompleteCustomerActionRequest("new@example.com", changed.Token!),
            default);
        Assert.NotNull(validation);
        Assert.Equal(42, validation!.DatabaseId);
        Assert.Equal("customer@example.com", validation.CurrentEmail);
        Assert.Equal("new@example.com", validation.NewEmail);
        Assert.True(await fixture.Service.CompleteEmailChangeAsync(
            new CompleteCustomerActionRequest("new@example.com", changed!.Token!),
            default));
        Assert.False(await fixture.Service.CompleteEmailChangeAsync(
            new CompleteCustomerActionRequest("new@example.com", changed.Token!),
            default));
        stored = await fixture.Customers.Users.AsNoTracking().SingleAsync(value => value.Id == "customer-id");
        Assert.Equal("new@example.com", stored.Email);
        Assert.Equal("new@example.com", stored.UserName);
        Assert.True(stored.EmailConfirmed);
        Assert.NotNull((await fixture.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
    }

    [Fact]
    public async Task PasswordReset_EmailMismatchDoesNotConsumeChallenge()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedCustomerAsync();
        var challenge = await fixture.Service.RequestPasswordResetAsync(
            new CustomerActionRequest("customer@example.com"), default);

        Assert.False(await fixture.Service.CompletePasswordResetAsync(
            new CompletePasswordResetRequest("other@example.com", challenge.Token!, "new-password"), default));
        Assert.True(await fixture.Service.CompletePasswordResetAsync(
            new CompletePasswordResetRequest("customer@example.com", challenge.Token!, "new-password"), default));
    }

    [Fact]
    public async Task ChangeEmail_ExpiredChallengeLeavesIdentityAndProfileReadyForRetry()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 7, 15, 0, 0, 0, TimeSpan.Zero));
        await using var fixture = await Fixture.CreateAsync(postgres, clock);
        await fixture.SeedCustomerAsync();
        var challenge = await fixture.Service.ChangeEmailAsync(
            "customer-id",
            new ChangeCustomerEmailRequest("old-password", "new@example.com"),
            default);

        clock.Advance(TimeSpan.FromHours(25));

        Assert.Null(await fixture.Service.ValidateEmailChangeAsync(
            new CompleteCustomerActionRequest("new@example.com", challenge!.Token!), default));
        Assert.False(await fixture.Service.CompleteEmailChangeAsync(
            new CompleteCustomerActionRequest("new@example.com", challenge.Token!), default));
        Assert.Equal("customer@example.com", (await fixture.Customers.Users.AsNoTracking().SingleAsync()).Email);
    }

    private static string LegacyIssuedCredential =>
        string.Concat("Abcd", "EFgh", "2345", "!@$%", "JKLM");

    private static string CustomerManagedCredential =>
        string.Concat("customer-managed", "-credential-", "B8!");

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
        public async Task SeedCustomerAsync(
            string id = "customer-id",
            int databaseId = 42,
            string email = "customer@example.com",
            string password = "old-password",
            bool emailConfirmed = false)
        {
            var normalized = email.ToUpperInvariant();
            var row = new LegacyIdentityRow { Id = id, DatabaseID = databaseId, UserName = email, NormalizedUserName = normalized, Email = email, NormalizedEmail = normalized, EmailConfirmed = emailConfirmed, SecurityStamp = Guid.NewGuid().ToString(), ConcurrencyStamp = Guid.NewGuid().ToString(), LockoutEnabled = true };
            row.PasswordHash = Hasher.HashPassword(row, password); Customers.Users.Add(row); await Customers.SaveChangesAsync();
        }
        public async Task SeedRefreshSessionAsync()
        {
            State.RefreshSessions.Add(new()
            {
                Id = Guid.NewGuid(),
                FamilyId = Guid.NewGuid(),
                IdentityId = "customer-id",
                IdentityKind = Legacy.Maliev.AuthService.Domain.IdentityKind.Customer,
                TokenHash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Guid.NewGuid().ToByteArray())),
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
            });
            await State.SaveChangesAsync();
        }
        public async ValueTask DisposeAsync() { await Customers.DisposeAsync(); await State.DisposeAsync(); }
    }
}
