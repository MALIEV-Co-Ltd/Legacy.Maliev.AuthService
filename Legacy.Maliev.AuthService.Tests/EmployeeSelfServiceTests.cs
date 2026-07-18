using Legacy.Maliev.AuthService.Api.Authorization;
using Legacy.Maliev.AuthService.Api.Controllers;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
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
public sealed class EmployeeSelfServiceTests(PostgresFixture postgres)
{
    [Fact]
    public void Controller_UsesAuthenticatedJsonPostsAndEmployeeSpecificPermission()
    {
        var controller = typeof(EmployeeSelfServiceController);
        Assert.NotEmpty(controller.GetCustomAttributes<AuthorizeAttribute>());
        Assert.Equal("auth/v1/employee-self-service", controller.GetCustomAttribute<RouteAttribute>()?.Template);

        var methods = controller.GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .Where(method => method.DeclaringType == controller)
            .ToArray();
        Assert.All(methods, method => Assert.NotEmpty(method.GetCustomAttributes<HttpPostAttribute>()));
        Assert.All(methods, method => Assert.Contains(
            method.GetCustomAttributes<RequirePermissionAttribute>(),
            attribute => attribute.Permission == EmployeeSelfServicePermissions.Use));
        Assert.DoesNotContain(
            methods.SelectMany(method => method.GetCustomAttributes<HttpPostAttribute>()),
            attribute => attribute.Template?.Contains("{password", StringComparison.OrdinalIgnoreCase) == true
                || attribute.Template?.Contains("{token", StringComparison.OrdinalIgnoreCase) == true);
    }

    [Fact]
    public async Task RequestPasswordReset_KnownEmployee_ReturnsOpaqueTokenAndStoresEmployeeScopedHash()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();

        var challenge = await fixture.Service.RequestPasswordResetAsync(
            new EmployeeActionRequest("employee@example.com"), default);

        Assert.True(challenge.Accepted);
        Assert.NotNull(challenge.Token);
        var stored = await fixture.State.IdentityActionTokens.SingleAsync();
        Assert.NotEqual(challenge.Token, stored.TokenHash);
        Assert.Equal(64, stored.TokenHash.Length);
        Assert.Equal("employee-password-reset", stored.Purpose);
    }

    [Fact]
    public async Task RequestPasswordReset_UnknownEmployee_IsEnumerationSafeAndStoresNothing()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);

        var challenge = await fixture.Service.RequestPasswordResetAsync(
            new EmployeeActionRequest("missing@example.com"), default);

        Assert.True(challenge.Accepted);
        Assert.Null(challenge.Token);
        Assert.Empty(await fixture.State.IdentityActionTokens.ToListAsync());
    }

    [Fact]
    public async Task CompletePasswordReset_ValidTokenChangesPasswordRejectsReplayAndRevokesEmployeeSessions()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        await fixture.SeedRefreshSessionAsync();
        var challenge = await fixture.Service.RequestPasswordResetAsync(
            new EmployeeActionRequest("employee@example.com"), default);

        var first = await fixture.Service.CompletePasswordResetAsync(
            new CompleteEmployeePasswordResetRequest(
                "employee@example.com", challenge.Token!, "new-password"), default);
        var replay = await fixture.Service.CompletePasswordResetAsync(
            new CompleteEmployeePasswordResetRequest(
                "employee@example.com", challenge.Token!, "another-password"), default);

        Assert.True(first);
        Assert.False(replay);
        var stored = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        Assert.Equal(
            PasswordVerificationResult.Success,
            fixture.Hasher.VerifyHashedPassword(stored, stored.PasswordHash!, "new-password"));
        Assert.NotNull((await fixture.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
    }

    [Fact]
    public async Task ConfirmEmail_ExpiredTokenIsRejectedWithoutChangingEmployee()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 7, 18, 0, 0, 0, TimeSpan.Zero));
        await using var fixture = await Fixture.CreateAsync(postgres, clock);
        await fixture.SeedEmployeeAsync(emailConfirmed: false);
        var challenge = await fixture.Service.RequestEmailConfirmationAsync(
            new EmployeeActionRequest("employee@example.com"), default);
        clock.Advance(TimeSpan.FromHours(25));

        var confirmed = await fixture.Service.ConfirmEmailAsync(
            new CompleteEmployeeActionRequest("employee@example.com", challenge.Token!), default);

        Assert.False(confirmed);
        Assert.False((await fixture.Employees.Users.AsNoTracking().SingleAsync()).EmailConfirmed);
    }

    [Fact]
    public async Task RequestPasswordReset_SecondChallengeSupersedesFirstChallenge()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        var first = await fixture.Service.RequestPasswordResetAsync(
            new EmployeeActionRequest("employee@example.com"), default);
        var second = await fixture.Service.RequestPasswordResetAsync(
            new EmployeeActionRequest("employee@example.com"), default);

        var staleResult = await fixture.Service.CompletePasswordResetAsync(
            new CompleteEmployeePasswordResetRequest(
                "employee@example.com", first.Token!, "stale-password"), default);
        var currentResult = await fixture.Service.CompletePasswordResetAsync(
            new CompleteEmployeePasswordResetRequest(
                "employee@example.com", second.Token!, "current-password"), default);

        Assert.False(staleResult);
        Assert.True(currentResult);
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private Fixture(
            EmployeeIdentityDbContext employees,
            RefreshSessionDbContext state,
            TimeProvider? timeProvider)
        {
            Employees = employees;
            State = state;
            Hasher = new PasswordHasher<LegacyIdentityRow>();
            Service = new EmployeeSelfService(
                Employees,
                State,
                Hasher,
                timeProvider ?? TimeProvider.System);
        }

        public EmployeeIdentityDbContext Employees { get; }
        public RefreshSessionDbContext State { get; }
        public PasswordHasher<LegacyIdentityRow> Hasher { get; }
        public EmployeeSelfService Service { get; }

        public static async Task<Fixture> CreateAsync(
            PostgresFixture postgres,
            TimeProvider? timeProvider = null) =>
            new(
                await postgres.CreateEmployeeContextAsync(),
                await postgres.CreateStateContextAsync(),
                timeProvider);

        public async Task SeedEmployeeAsync(bool emailConfirmed = true)
        {
            const string email = "employee@example.com";
            var normalized = email.ToUpperInvariant();
            var row = new LegacyIdentityRow
            {
                Id = "employee-id",
                DatabaseID = 7,
                UserName = email,
                NormalizedUserName = normalized,
                Email = email,
                NormalizedEmail = normalized,
                EmailConfirmed = emailConfirmed,
                SecurityStamp = Guid.NewGuid().ToString(),
                ConcurrencyStamp = Guid.NewGuid().ToString(),
                LockoutEnabled = true,
            };
            row.PasswordHash = Hasher.HashPassword(row, "old-password");
            Employees.Users.Add(row);
            await Employees.SaveChangesAsync();
        }

        public async Task SeedRefreshSessionAsync()
        {
            State.RefreshSessions.Add(new()
            {
                Id = Guid.NewGuid(),
                FamilyId = Guid.NewGuid(),
                IdentityId = "employee-id",
                IdentityKind = IdentityKind.Employee,
                TokenHash = Convert.ToHexStringLower(
                    System.Security.Cryptography.SHA256.HashData(Guid.NewGuid().ToByteArray())),
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
            });
            await State.SaveChangesAsync();
        }

        public async ValueTask DisposeAsync()
        {
            await Employees.DisposeAsync();
            await State.DisposeAsync();
        }
    }
}
