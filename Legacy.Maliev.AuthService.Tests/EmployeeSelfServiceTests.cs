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
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Time.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using System.Reflection;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class EmployeeSelfServiceTests(PostgresFixture postgres)
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task CanonicalWriterRecovery_BindsExactStoredKeyWithoutChangingHistoricalHashFrame(
        bool historicalKey, bool confirmation)
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync(emailConfirmed: !confirmation);
        var row = await fixture.Employees.Users.SingleAsync();
        const string raw = "cafe\u0301@identity.test";
        const string canonical = "CAF\u00c9@IDENTITY.TEST";
        row.Email = raw;
        row.NormalizedEmail = historicalKey ? raw.ToUpperInvariant() : canonical;
        var bound = row.NormalizedEmail;
        var stamp = row.SecurityStamp;
        await fixture.Employees.SaveChangesAsync();
        var challenge = confirmation
            ? await fixture.Service.RequestEmailConfirmationAsync(new(raw), "service:legacy-intranet", default)
            : await fixture.Service.RequestPasswordResetAsync(new(raw), "service:legacy-intranet", default);
        Assert.NotNull(challenge.Token);
        var action = await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync();
        Assert.Equal(bound, action.BoundNormalizedEmail);
        Assert.Equal(stamp, action.BoundSecurityStamp);
        var expectedHash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes($"{challenge.Token}:{stamp}:{bound}")));
        Assert.Equal(expectedHash, action.TokenHash);
        var completed = confirmation
            ? await fixture.Service.ConfirmEmailAsync(new(raw, challenge.Token!), "service:legacy-intranet", default)
            : await fixture.Service.CompletePasswordResetAsync(new(raw, challenge.Token!, "updated-password"), "service:legacy-intranet", default);
        Assert.True(completed);
        var receipt = await fixture.Employees.RecoveryEffects.AsNoTracking().SingleAsync();
        Assert.Equal(bound, receipt.NormalizedEmail);
        Assert.Equal(stamp, receipt.BeforeSecurityStamp);
        Assert.Equal(expectedHash, (await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync()).TokenHash);
        Assert.Equal(bound, (await fixture.Employees.Users.AsNoTracking().SingleAsync()).NormalizedEmail);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CanonicalWriterRecovery_HistoricalCommittedReceiptFinalizesWithoutRehashingBinding(bool confirmation)
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync(emailConfirmed: !confirmation);
        var row = await fixture.Employees.Users.SingleAsync();
        const string raw = "cafe\u0301@identity.test";
        row.Email = raw;
        row.NormalizedEmail = raw.ToUpperInvariant();
        await fixture.Employees.SaveChangesAsync();
        var challenge = confirmation
            ? await fixture.Service.RequestEmailConfirmationAsync(new(raw), "service:legacy-intranet", default)
            : await fixture.Service.RequestPasswordResetAsync(new(raw), "service:legacy-intranet", default);
        var original = await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync();
        var fault = new FinalizationAfterEffectFailureInterceptor();
        await using var faultyState = new RefreshSessionDbContext(new DbContextOptionsBuilder<RefreshSessionDbContext>()
            .UseNpgsql(fixture.State.Database.GetConnectionString()).AddInterceptors(fault).Options);
        var faulty = new EmployeeSelfService(fixture.Employees, faultyState, fixture.Hasher, TimeProvider.System,
            new EmployeeRecoveryOptions { Enabled = true });
        async Task<bool> CompleteAsync(EmployeeSelfService service) => confirmation
            ? await service.ConfirmEmailAsync(new(raw, challenge.Token!), "service:legacy-intranet", default)
            : await service.CompletePasswordResetAsync(new(raw, challenge.Token!, "applied-password"), "service:legacy-intranet", default);
        await Assert.ThrowsAsync<EmployeeRecoveryUnavailableException>(() => CompleteAsync(faulty));
        Assert.True(fault.Triggered);
        var committed = await fixture.Employees.RecoveryEffects.AsNoTracking().SingleAsync();
        var afterEffect = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        Assert.Equal(original.BoundNormalizedEmail, committed.NormalizedEmail);
        Assert.Null(committed.FinalizedAcknowledgedAt);
        Assert.True(await CompleteAsync(fixture.Service));
        var finalized = await fixture.Employees.RecoveryEffects.AsNoTracking().SingleAsync();
        Assert.Equal(committed.NormalizedEmail, finalized.NormalizedEmail);
        Assert.Equal(committed.BeforeSecurityStamp, finalized.BeforeSecurityStamp);
        Assert.Equal(committed.AfterSecurityStamp, finalized.AfterSecurityStamp);
        Assert.Equal(committed.PasswordPayloadHash, finalized.PasswordPayloadHash);
        Assert.NotNull(finalized.FinalizedAcknowledgedAt);
        var after = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        Assert.Equal(afterEffect.PasswordHash, after.PasswordHash);
        Assert.Equal(afterEffect.SecurityStamp, after.SecurityStamp);
        Assert.Equal(afterEffect.ConcurrencyStamp, after.ConcurrencyStamp);
        Assert.Equal(original.TokenHash, (await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync()).TokenHash);
    }

    [Fact]
    public async Task CompletePasswordReset_MissingAuthenticatedOwner_DoesNotApplyIdentityEffect()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        var before = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        var challenge = await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default);
        var controller = new EmployeeSelfServiceController(fixture.Service);
        var result = await controller.CompletePasswordReset(new("employee@example.com", challenge.Token!, "forbidden-password"), default);
        Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal(before.PasswordHash, (await fixture.Employees.Users.AsNoTracking().SingleAsync()).PasswordHash);
        Assert.Null((await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
    }

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
            new EmployeeActionRequest("employee@example.com"), "service:legacy-intranet", default);

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
            new EmployeeActionRequest("missing@example.com"), "service:legacy-intranet", default);

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
            new EmployeeActionRequest("employee@example.com"), "service:legacy-intranet", default);

        var first = await fixture.Service.CompletePasswordResetAsync(
            new CompleteEmployeePasswordResetRequest(
                "employee@example.com", challenge.Token!, "new-password"), "service:legacy-intranet", default);
        var replay = await fixture.Service.CompletePasswordResetAsync(
            new CompleteEmployeePasswordResetRequest(
                "employee@example.com", challenge.Token!, "another-password"), "service:legacy-intranet", default);

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
            new EmployeeActionRequest("employee@example.com"), "service:legacy-intranet", default);
        clock.Advance(TimeSpan.FromHours(25));

        var confirmed = await fixture.Service.ConfirmEmailAsync(
            new CompleteEmployeeActionRequest("employee@example.com", challenge.Token!), "service:legacy-intranet", default);

        Assert.False(confirmed);
        Assert.False((await fixture.Employees.Users.AsNoTracking().SingleAsync()).EmailConfirmed);
    }

    [Fact]
    public async Task RequestPasswordReset_SecondChallengeSupersedesFirstChallenge()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        var first = await fixture.Service.RequestPasswordResetAsync(
            new EmployeeActionRequest("employee@example.com"), "service:legacy-intranet", default);
        var second = await fixture.Service.RequestPasswordResetAsync(
            new EmployeeActionRequest("employee@example.com"), "service:legacy-intranet", default);

        var staleResult = await fixture.Service.CompletePasswordResetAsync(
            new CompleteEmployeePasswordResetRequest(
                "employee@example.com", first.Token!, "stale-password"), "service:legacy-intranet", default);
        var currentResult = await fixture.Service.CompletePasswordResetAsync(
            new CompleteEmployeePasswordResetRequest(
                "employee@example.com", second.Token!, "current-password"), "service:legacy-intranet", default);

        Assert.False(staleResult);
        Assert.True(currentResult);
    }

    [Theory]
    [InlineData(false, "stamp")]
    [InlineData(true, "stamp")]
    [InlineData(false, "email")]
    [InlineData(true, "email")]
    [InlineData(false, "admin")]
    [InlineData(true, "admin")]
    public async Task CompleteChallenge_ChangedIdentityStateRejectsOldLinkAndAllowsFreshLink(bool confirmation, string change)
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync(emailConfirmed: !confirmation);
        var old = confirmation
            ? await fixture.Service.RequestEmailConfirmationAsync(new("employee@example.com"), "service:legacy-intranet", default)
            : await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default);
        var row = await fixture.Employees.Users.SingleAsync();
        if (change == "admin")
        {
            await using var adminContext = new EmployeeIdentityDbContext(
                new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
                    .UseNpgsql(fixture.Employees.Database.GetConnectionString()).Options);
            var admin = new EmployeeIdentityAdminService(adminContext, fixture.Hasher, new EmployeeRecoveryOptions { Enabled = true });
            Assert.True(await admin.UpdateAsync(7, new(
                row.UserName!, row.Email!, !confirmation, null, false, false, null, true), default));
        }
        else if (change == "stamp")
        {
            row.SecurityStamp = Guid.NewGuid().ToString();
        }
        else
        {
            row.Email = "changed@example.com";
            row.NormalizedEmail = "CHANGED@EXAMPLE.COM";
        }
        await fixture.Employees.SaveChangesAsync();
        var passwordHash = row.PasswordHash;
        var stamp = (await fixture.Employees.Users.AsNoTracking().SingleAsync()).SecurityStamp;
        var rejected = confirmation
            ? await fixture.Service.ConfirmEmailAsync(new(row.Email!, old.Token!), "service:legacy-intranet", default)
            : await fixture.Service.CompletePasswordResetAsync(new(row.Email!, old.Token!, "stale-password"), "service:legacy-intranet", default);
        Assert.False(rejected);
        var unchanged = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        Assert.Equal(passwordHash, unchanged.PasswordHash);
        Assert.Equal(stamp, unchanged.SecurityStamp);
        Assert.Equal(!confirmation, unchanged.EmailConfirmed);
        Assert.Null((await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);

        var fresh = confirmation
            ? await fixture.Service.RequestEmailConfirmationAsync(new(row.Email!), "service:legacy-intranet", default)
            : await fixture.Service.RequestPasswordResetAsync(new(row.Email!), "service:legacy-intranet", default);
        var accepted = confirmation
            ? await fixture.Service.ConfirmEmailAsync(new(row.Email!, fresh.Token!), "service:legacy-intranet", default)
            : await fixture.Service.CompletePasswordResetAsync(new(row.Email!, fresh.Token!, "fresh-password"), "service:legacy-intranet", default);
        Assert.True(accepted);
        Assert.False(confirmation
            ? await fixture.Service.ConfirmEmailAsync(new(row.Email!, fresh.Token!), "service:legacy-intranet", default)
            : await fixture.Service.CompletePasswordResetAsync(new(row.Email!, fresh.Token!, "replayed-password"), "service:legacy-intranet", default));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CompleteChallenge_PreviouslyIssuedUnboundLinkFailsClosed(bool confirmation)
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync(emailConfirmed: !confirmation);
        const string oldToken = "legacy-opaque-token";
        fixture.State.IdentityActionTokens.Add(new()
        {
            Id = Guid.NewGuid(),
            IdentityId = "employee-id",
            Purpose = confirmation ? "employee-email-confirmation" : "employee-password-reset",
            TokenHash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(oldToken))),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(24),
        });
        await fixture.State.SaveChangesAsync();
        Assert.False(confirmation
            ? await fixture.Service.ConfirmEmailAsync(new("employee@example.com", oldToken), "service:legacy-intranet", default)
            : await fixture.Service.CompletePasswordResetAsync(new("employee@example.com", oldToken, "new-password"), "service:legacy-intranet", default));
        Assert.Null((await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
    }

    [Fact]
    public async Task CompletePasswordReset_ConcurrentRequestsHaveOnlyOneWinner()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        var challenge = await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default);
        await using var employee2 = new EmployeeIdentityDbContext(new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
            .UseNpgsql(fixture.Employees.Database.GetConnectionString()).Options);
        await using var state2 = new RefreshSessionDbContext(new DbContextOptionsBuilder<RefreshSessionDbContext>()
            .UseNpgsql(fixture.State.Database.GetConnectionString()).Options);
        var service2 = new EmployeeSelfService(employee2, state2, fixture.Hasher, TimeProvider.System, new EmployeeRecoveryOptions { Enabled = true });
        var results = await Task.WhenAll(
            fixture.Service.CompletePasswordResetAsync(new("employee@example.com", challenge.Token!, "winner-one"), "service:legacy-intranet", default),
            service2.CompletePasswordResetAsync(new("employee@example.com", challenge.Token!, "winner-two"), "service:legacy-intranet", default));
        Assert.Single(results, result => result);
        var stored = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        var winner = results[0] ? "winner-one" : "winner-two";
        Assert.Equal(PasswordVerificationResult.Success, fixture.Hasher.VerifyHashedPassword(stored, stored.PasswordHash!, winner));
    }

    [Theory]
    [InlineData(false, null)]
    [InlineData(false, "")]
    [InlineData(false, "   ")]
    [InlineData(true, null)]
    [InlineData(true, "   ")]
    public async Task RequestChallenge_MigratedMissingStampInitializesAndAllowsRecovery(bool confirmation, string? stamp)
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync(emailConfirmed: !confirmation);
        var row = await fixture.Employees.Users.SingleAsync();
        row.SecurityStamp = stamp;
        await fixture.Employees.SaveChangesAsync();
        var challenge = confirmation
            ? await fixture.Service.RequestEmailConfirmationAsync(new("employee@example.com"), "service:legacy-intranet", default)
            : await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default);
        Assert.NotNull(challenge.Token);
        Assert.False(string.IsNullOrWhiteSpace((await fixture.Employees.Users.AsNoTracking().SingleAsync()).SecurityStamp));
        Assert.True(confirmation
            ? await fixture.Service.ConfirmEmailAsync(new("employee@example.com", challenge.Token!), "service:legacy-intranet", default)
            : await fixture.Service.CompletePasswordResetAsync(new("employee@example.com", challenge.Token!, "fresh-password"), "service:legacy-intranet", default));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RequestChallenge_ConcurrentBootstrapOrAdminWinsWithoutBeingOverwritten(bool adminWins)
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        var row = await fixture.Employees.Users.SingleAsync();
        row.SecurityStamp = null;
        await fixture.Employees.SaveChangesAsync();
        string? winningStamp = null;
        var barrier = new BootstrapInterceptor(async () =>
        {
            if (adminWins)
            {
                var admin = new EmployeeIdentityAdminService(fixture.Employees, fixture.Hasher, new EmployeeRecoveryOptions { Enabled = true });
                Assert.True(await admin.UpdateAsync(7, new("employee@example.com", "employee@example.com", true,
                    null, false, false, null, true), default));
            }
            else
            {
                Assert.NotNull((await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default)).Token);
            }
            winningStamp = (await fixture.Employees.Users.AsNoTracking().SingleAsync()).SecurityStamp;
        });
        await using var racingContext = new EmployeeIdentityDbContext(new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
            .UseNpgsql(fixture.Employees.Database.GetConnectionString()).AddInterceptors(barrier).Options);
        await using var racingState = new RefreshSessionDbContext(new DbContextOptionsBuilder<RefreshSessionDbContext>()
            .UseNpgsql(fixture.State.Database.GetConnectionString()).Options);
        var racingService = new EmployeeSelfService(racingContext, racingState, fixture.Hasher, TimeProvider.System, new EmployeeRecoveryOptions { Enabled = true });
        var result = await racingService.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default);
        Assert.True(barrier.Triggered);
        Assert.True(result.Accepted);
        Assert.True(result.Token is null);
        Assert.Equal(winningStamp, (await fixture.Employees.Users.AsNoTracking().SingleAsync()).SecurityStamp);
        Assert.NotNull((await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default)).Token);
    }

    [Fact]
    public async Task CompletePasswordReset_IdentitySaveFailureIsNotSuccessAndFreshRequestCanRecover()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        var before = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        var challenge = await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default);
        await using var failingContext = new EmployeeIdentityDbContext(new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
            .UseNpgsql(fixture.Employees.Database.GetConnectionString()).AddInterceptors(new FailSaveInterceptor()).Options);
        var failing = new EmployeeSelfService(failingContext, fixture.State, fixture.Hasher, TimeProvider.System, new EmployeeRecoveryOptions { Enabled = true });
        await Assert.ThrowsAsync<EmployeeRecoveryUnavailableException>(() => failing.CompletePasswordResetAsync(
            new("employee@example.com", challenge.Token!, "not-persisted"), "service:legacy-intranet", default));
        var after = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        Assert.Equal(before.PasswordHash, after.PasswordHash);
        Assert.Equal(before.SecurityStamp, after.SecurityStamp);
        Assert.Null((await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
        Assert.True(await fixture.Service.CompletePasswordResetAsync(new("employee@example.com", challenge.Token!, "not-persisted"), "service:legacy-intranet", default));
        var fresh = await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default);
        Assert.True(await fixture.Service.CompletePasswordResetAsync(new("employee@example.com", fresh.Token!, "recovered"), "service:legacy-intranet", default));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Atomicity_AdminAfterRecoveryRead_PreventsStaleIdentityMutation(bool confirmation)
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync(emailConfirmed: !confirmation);
        await fixture.SeedRefreshSessionAsync();
        var challenge = confirmation
            ? await fixture.Service.RequestEmailConfirmationAsync(new("employee@example.com"), "service:legacy-intranet", default)
            : await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        LegacyIdentityRow? adminWinner = null;
        var barrier = new StateUpdateInterceptor("identity_action_tokens", async () =>
        {
            await using var adminContext = new EmployeeIdentityDbContext(
                new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
                    .UseNpgsql(fixture.Employees.Database.GetConnectionString()).Options);
            var admin = new EmployeeIdentityAdminService(adminContext, fixture.Hasher, new EmployeeRecoveryOptions { Enabled = true });
            Assert.True(await admin.UpdateAsync(7, new("employee@example.com", "employee@example.com",
                !confirmation, null, false, false, null, true), timeout.Token));
            adminWinner = await adminContext.Users.AsNoTracking().SingleAsync(timeout.Token);
        });
        await using var recoveryEmployees = new EmployeeIdentityDbContext(
            new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
                .UseNpgsql(fixture.Employees.Database.GetConnectionString()).Options);
        await using var recoveryState = new RefreshSessionDbContext(
            new DbContextOptionsBuilder<RefreshSessionDbContext>()
                .UseNpgsql(fixture.State.Database.GetConnectionString()).AddInterceptors(barrier).Options);
        var controller = CreateController(
            new EmployeeSelfService(recoveryEmployees, recoveryState, fixture.Hasher, TimeProvider.System, new EmployeeRecoveryOptions { Enabled = true }));

        var outcome = await CompleteAsync(controller, confirmation, challenge.Token!, "stale-password", timeout.Token);
        var replay = await CompleteAsync(CreateController(fixture.Service), confirmation, challenge.Token!, "stale-password", timeout.Token);
        var persisted = await fixture.Employees.Users.AsNoTracking().SingleAsync(timeout.Token);
        var session = await fixture.State.RefreshSessions.AsNoTracking().SingleAsync(timeout.Token);

        Assert.True(barrier.Triggered);
        Assert.NotNull(adminWinner);
        Assert.Multiple(
            () => Assert.IsType<BadRequestObjectResult>(outcome),
            () => Assert.Equal(adminWinner.SecurityStamp, persisted.SecurityStamp),
            () => Assert.Equal(adminWinner.ConcurrencyStamp, persisted.ConcurrencyStamp),
            () => Assert.Equal(adminWinner.PasswordHash, persisted.PasswordHash),
            () => Assert.Equal(adminWinner.EmailConfirmed, persisted.EmailConfirmed),
            () => Assert.Null(session.RevokedAt),
            () => Assert.IsType<BadRequestObjectResult>(replay));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Atomicity_IdentitySaveFailure_UnappliedChallengeCanRetryThenRejectReplay(bool confirmation)
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync(emailConfirmed: !confirmation);
        await fixture.SeedRefreshSessionAsync();
        var before = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        var challenge = confirmation
            ? await fixture.Service.RequestEmailConfirmationAsync(new("employee@example.com"), "service:legacy-intranet", default)
            : await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var fault = new FailSaveInterceptor();
        await using var failingEmployees = new EmployeeIdentityDbContext(
            new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
                .UseNpgsql(fixture.Employees.Database.GetConnectionString()).AddInterceptors(fault).Options);
        var failingController = CreateController(
            new EmployeeSelfService(failingEmployees, fixture.State, fixture.Hasher, TimeProvider.System, new EmployeeRecoveryOptions { Enabled = true }));
        IActionResult? firstResult = null;
        _ = await Record.ExceptionAsync(async () =>
        {
            firstResult = await CompleteAsync(failingController, confirmation, challenge.Token!, "recovered-password", timeout.Token);
        });
        var unapplied = await fixture.Employees.Users.AsNoTracking().SingleAsync(timeout.Token);
        var actionAfterFailure = await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync(timeout.Token);
        var retry = await CompleteAsync(CreateController(fixture.Service), confirmation, challenge.Token!, "recovered-password", timeout.Token);
        var replay = await CompleteAsync(CreateController(fixture.Service), confirmation, challenge.Token!, "recovered-password", timeout.Token);
        var persisted = await fixture.Employees.Users.AsNoTracking().SingleAsync(timeout.Token);
        var session = await fixture.State.RefreshSessions.AsNoTracking().SingleAsync(timeout.Token);

        Assert.Equal(before.PasswordHash, unapplied.PasswordHash);
        Assert.Equal(before.SecurityStamp, unapplied.SecurityStamp);
        Assert.Equal(before.EmailConfirmed, unapplied.EmailConfirmed);
        Assert.True(fault.Triggered);
        Assert.False(firstResult is NoContentResult);
        Assert.Multiple(
            () => Assert.Null(actionAfterFailure.ConsumedAt),
            () => Assert.IsType<NoContentResult>(retry),
            () => Assert.IsType<BadRequestObjectResult>(replay),
            () => Assert.NotEqual(before.SecurityStamp, persisted.SecurityStamp),
            () => Assert.Equal(confirmation || before.EmailConfirmed, persisted.EmailConfirmed),
            () => Assert.Equal(PasswordVerificationResult.Success, fixture.Hasher.VerifyHashedPassword(
                persisted, persisted.PasswordHash!, confirmation ? "old-password" : "recovered-password")),
            () => Assert.Equal(confirmation, session.RevokedAt is null));
    }

    [Fact]
    public async Task Atomicity_RevocationFailure_RetryFinalizesWithoutReapplyingIdentityEffect()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        await fixture.SeedRefreshSessionAsync();
        var challenge = await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var fault = new StateUpdateInterceptor("refresh_sessions", () =>
            Task.FromException(new InvalidOperationException("Synthetic employee refresh finalization failure.")));
        await using var failingState = new RefreshSessionDbContext(
            new DbContextOptionsBuilder<RefreshSessionDbContext>()
                .UseNpgsql(fixture.State.Database.GetConnectionString()).AddInterceptors(fault).Options);
        var failingController = CreateController(
            new EmployeeSelfService(fixture.Employees, failingState, fixture.Hasher, TimeProvider.System, new EmployeeRecoveryOptions { Enabled = true }));
        IActionResult? firstResult = null;
        _ = await Record.ExceptionAsync(async () =>
        {
            firstResult = await failingController.CompletePasswordReset(new("employee@example.com", challenge.Token!, "applied-password"), timeout.Token);
        });
        Assert.True(fault.Triggered);
        Assert.False(firstResult is NoContentResult);
        var committed = await fixture.Employees.Users.AsNoTracking().SingleAsync(timeout.Token);
        Assert.Equal(PasswordVerificationResult.Success,
            fixture.Hasher.VerifyHashedPassword(committed, committed.PasswordHash!, "applied-password"));
        Assert.Null((await fixture.State.RefreshSessions.AsNoTracking().SingleAsync(timeout.Token)).RevokedAt);
        var controller = CreateController(fixture.Service);
        Assert.IsType<BadRequestObjectResult>(await controller.CompletePasswordReset(
            new("employee@example.com", challenge.Token!, "different-password"), timeout.Token));
        Assert.IsType<BadRequestObjectResult>(await controller.CompletePasswordReset(
            new("other@example.com", challenge.Token!, "applied-password"), timeout.Token));
        Assert.IsType<BadRequestObjectResult>(await controller.ConfirmEmail(
            new("employee@example.com", challenge.Token!), timeout.Token));
        var retry = await controller.CompletePasswordReset(new("employee@example.com", challenge.Token!, "applied-password"), timeout.Token);
        var replay = await controller.CompletePasswordReset(new("employee@example.com", challenge.Token!, "applied-password"), timeout.Token);
        var persisted = await fixture.Employees.Users.AsNoTracking().SingleAsync(timeout.Token);
        var session = await fixture.State.RefreshSessions.AsNoTracking().SingleAsync(timeout.Token);

        Assert.Multiple(
            () => Assert.IsType<NoContentResult>(retry),
            () => Assert.IsType<BadRequestObjectResult>(replay),
            () => Assert.NotNull(session.RevokedAt),
            () => Assert.Equal(committed.PasswordHash, persisted.PasswordHash),
            () => Assert.Equal(committed.SecurityStamp, persisted.SecurityStamp),
            () => Assert.Equal(committed.ConcurrencyStamp, persisted.ConcurrencyStamp));
    }

    [Fact]
    public async Task Worker_CommittedResetFinalizesOnlyOldAndNullEpochs_WithoutReapplyingIdentity()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        await fixture.SeedRefreshSessionAsync();
        var challenge = await PendingResetAsync(fixture);
        var applied = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        var receipt = await fixture.Employees.RecoveryEffects.AsNoTracking().SingleAsync();
        fixture.State.RefreshSessions.Add(new()
        {
            Id = Guid.NewGuid(),
            FamilyId = Guid.NewGuid(),
            IdentityId = applied.Id,
            IdentityKind = IdentityKind.Employee,
            SecurityStamp = receipt.BeforeSecurityStamp,
            TokenHash = new string('a', 64),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
        });
        fixture.State.RefreshSessions.Add(new()
        {
            Id = Guid.NewGuid(),
            FamilyId = Guid.NewGuid(),
            IdentityId = applied.Id,
            IdentityKind = IdentityKind.Employee,
            SecurityStamp = receipt.AfterSecurityStamp,
            TokenHash = new string('b', 64),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
        });
        fixture.State.RefreshSessions.Add(new()
        {
            Id = Guid.NewGuid(),
            FamilyId = Guid.NewGuid(),
            IdentityId = applied.Id,
            IdentityKind = IdentityKind.Employee,
            SecurityStamp = "later-admin-generation",
            TokenHash = new string('c', 64),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
        });
        await fixture.State.SaveChangesAsync();
        Assert.Equal(1, await fixture.Service.ReconcileOutstandingAsync(default));
        Assert.Equal(0, await fixture.Service.ReconcileOutstandingAsync(default));
        var final = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        Assert.Equal(applied.PasswordHash, final.PasswordHash);
        Assert.Equal(applied.SecurityStamp, final.SecurityStamp);
        Assert.Equal(applied.ConcurrencyStamp, final.ConcurrencyStamp);
        var sessions = await fixture.State.RefreshSessions.AsNoTracking().ToListAsync();
        Assert.All(sessions.Where(x => x.SecurityStamp is null || x.SecurityStamp == receipt.BeforeSecurityStamp), x => Assert.NotNull(x.RevokedAt));
        Assert.All(sessions.Where(x => x.SecurityStamp == receipt.AfterSecurityStamp || x.SecurityStamp == "later-admin-generation"), x => Assert.Null(x.RevokedAt));
        Assert.NotNull((await fixture.Employees.RecoveryEffects.AsNoTracking().SingleAsync()).FinalizedAcknowledgedAt);
        Assert.False(await fixture.Service.CompletePasswordResetAsync(new("employee@example.com", challenge.Token!, "applied-password"), "service:legacy-intranet", default));
    }

    [Fact]
    public async Task Worker_UncommittedChallengeNeverAppliesPassword_AndCancellationLeavesPendingReceipt()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        var before = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default);
        Assert.Equal(0, await fixture.Service.ReconcileOutstandingAsync(default));
        Assert.Equal(before.PasswordHash, (await fixture.Employees.Users.AsNoTracking().SingleAsync()).PasswordHash);
        await PendingResetAsync(fixture);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Service.ReconcileOutstandingAsync(cancellation.Token));
        Assert.Null((await fixture.Employees.RecoveryEffects.AsNoTracking().SingleAsync()).FinalizedAcknowledgedAt);
        Assert.Equal(1, await fixture.Service.ReconcileOutstandingAsync(default));
    }

    [Fact]
    public async Task Worker_FaultRetainsCommittedReceipt_AndFinalizesWithoutAcquiringIdentityRowLock()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        await fixture.SeedRefreshSessionAsync();
        await PendingResetAsync(fixture);
        var fault = new StateUpdateInterceptor("refresh_sessions", () => Task.FromException(new InvalidOperationException("Synthetic worker write failure.")));
        await using var faultyState = new RefreshSessionDbContext(new DbContextOptionsBuilder<RefreshSessionDbContext>()
            .UseNpgsql(fixture.State.Database.GetConnectionString()).AddInterceptors(fault).Options);
        var service = new EmployeeSelfService(fixture.Employees, faultyState, fixture.Hasher, TimeProvider.System, new EmployeeRecoveryOptions { Enabled = true });
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.ReconcileOutstandingAsync(default));
        Assert.True(fault.Triggered);
        Assert.Null((await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
        Assert.Null((await fixture.Employees.RecoveryEffects.AsNoTracking().SingleAsync()).FinalizedAcknowledgedAt);
        await using var lockContext = new EmployeeIdentityDbContext(new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
            .UseNpgsql(fixture.Employees.Database.GetConnectionString()).Options);
        await using var transaction = await lockContext.Database.BeginTransactionAsync();
        await lockContext.Database.ExecuteSqlRawAsync("SELECT 1 FROM \"AspNetUsers\" WHERE \"Id\"='employee-id' FOR UPDATE");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        Assert.Equal(1, await fixture.Service.ReconcileOutstandingAsync(deadline.Token));
        Assert.NotNull((await fixture.State.RefreshSessions.AsNoTracking().SingleAsync(deadline.Token)).RevokedAt);
    }

    [Fact]
    public async Task Worker_WrongImmutableActionBindingCannotFinalizeOrAcknowledgeEffect()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        await fixture.SeedRefreshSessionAsync();
        await PendingResetAsync(fixture);
        await fixture.State.IdentityActionTokens.ExecuteUpdateAsync(s => s.SetProperty(x => x.OwnerSubject, "service:other"));
        await Assert.ThrowsAsync<EmployeeRecoveryUnavailableException>(() => fixture.Service.ReconcileOutstandingAsync(default));
        Assert.Null((await fixture.Employees.RecoveryEffects.AsNoTracking().SingleAsync()).FinalizedAcknowledgedAt);
        Assert.Null((await fixture.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
        Assert.Null((await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync()).FinalizedAt);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Admin_PendingReceiptMapsGeneric503_ThenWorkerAllowsMutation(bool delete)
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        await PendingResetAsync(fixture);
        var controller = new EmployeeIdentitiesController(new EmployeeIdentityAdminService(fixture.Employees, fixture.Hasher, new EmployeeRecoveryOptions { Enabled = true }), new AuthorizationEmployeeProfileStub());
        var result = delete ? await controller.Delete(7, default)
            : await controller.Update(7, new("employee@example.com", "employee@example.com", true, null, false, false, null, true), default);
        Assert.Equal(503, Assert.IsType<ObjectResult>(result).StatusCode);
        Assert.Equal(1, await fixture.Service.ReconcileOutstandingAsync(default));
        var retry = delete ? await controller.Delete(7, default)
            : await controller.Update(7, new("employee@example.com", "employee@example.com", true, null, false, false, null, true), default);
        Assert.IsType<NoContentResult>(retry);
    }

    [Fact]
    public async Task Issuance_ReconcilesCommittedEffectBeforeSupersedingChallenge()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        await fixture.SeedRefreshSessionAsync();
        var original = await PendingResetAsync(fixture);
        var next = await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default);
        Assert.NotNull(next.Token);
        var actions = await fixture.State.IdentityActionTokens.AsNoTracking().ToListAsync();
        Assert.Single(actions, x => x.FinalizedAt is not null && x.EffectActionId == x.Id);
        Assert.Single(actions, x => x.ConsumedAt is null);
        Assert.NotNull((await fixture.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
        Assert.NotNull((await fixture.Employees.RecoveryEffects.AsNoTracking().SingleAsync()).FinalizedAcknowledgedAt);
        Assert.False(await fixture.Service.CompletePasswordResetAsync(new("employee@example.com", original.Token!, "applied-password"), "service:legacy-intranet", default));
    }

    [Theory]
    [InlineData("employee-column")]
    [InlineData("employee-index")]
    [InlineData("employee-permissive-check")]
    [InlineData("state-column")]
    [InlineData("state-index")]
    [InlineData("state-partial-index")]
    [InlineData("state-check")]
    public async Task Readiness_PhysicalDriftFailsClosedDespiteAppliedMigrationHistory(string drift)
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await EmployeeRecoverySchema.EnsureAsync(fixture.Employees, fixture.State, default);
        switch (drift)
        {
            case "employee-column": await fixture.Employees.Database.ExecuteSqlRawAsync("ALTER TABLE \"EmployeeRecoveryEffects\" ALTER COLUMN \"OwnerSubject\" TYPE text"); break;
            case "employee-index": await fixture.Employees.Database.ExecuteSqlRawAsync("DROP INDEX \"IX_EmployeeRecoveryEffects_TokenSha256_Purpose\""); break;
            case "employee-permissive-check":
                await fixture.Employees.Database.ExecuteSqlRawAsync("ALTER TABLE \"EmployeeRecoveryEffects\" DROP CONSTRAINT \"CK_EmployeeRecoveryEffects_Binding\"");
                await fixture.Employees.Database.ExecuteSqlRawAsync("ALTER TABLE \"EmployeeRecoveryEffects\" ADD CONSTRAINT \"CK_EmployeeRecoveryEffects_Binding\" CHECK ((length(\"TokenSha256\") = 64 AND length(\"OwnerSubject\") > 0 AND length(\"BeforeSecurityStamp\") > 0 AND length(\"AfterSecurityStamp\") > 0) OR 1=1)"); break;
            case "state-column": await fixture.State.Database.ExecuteSqlRawAsync("ALTER TABLE identity_action_tokens ALTER COLUMN \"OwnerSubject\" TYPE text"); break;
            case "state-index": await fixture.State.Database.ExecuteSqlRawAsync("DROP INDEX \"IX_identity_action_tokens_OriginalTokenSha256_Purpose\""); break;
            case "state-partial-index":
                await fixture.State.Database.ExecuteSqlRawAsync("DROP INDEX \"IX_identity_action_tokens_OriginalTokenSha256_Purpose\"");
                await fixture.State.Database.ExecuteSqlRawAsync("CREATE UNIQUE INDEX \"IX_identity_action_tokens_OriginalTokenSha256_Purpose\" ON identity_action_tokens (\"OriginalTokenSha256\", \"Purpose\") WHERE false"); break;
            case "state-check": await fixture.State.Database.ExecuteSqlRawAsync("ALTER TABLE identity_action_tokens DROP CONSTRAINT \"CK_identity_action_tokens_employee_binding\""); break;
        }
        Assert.NotEmpty(await fixture.Employees.Database.GetAppliedMigrationsAsync());
        Assert.NotEmpty(await fixture.State.Database.GetAppliedMigrationsAsync());
        await Assert.ThrowsAsync<EmployeeRecoveryUnavailableException>(() => EmployeeRecoverySchema.EnsureAsync(fixture.Employees, fixture.State, default));
    }

    [Theory]
    [InlineData("legacy-finalized")]
    [InlineData("missing-effect")]
    [InlineData("empty-epoch")]
    public async Task DatabaseConstraints_RejectIncompleteEmployeeBindingAndFinalization(string invalid)
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        var id = Guid.NewGuid();
        fixture.State.IdentityActionTokens.Add(new()
        {
            Id = id,
            IdentityId = "employee-id",
            Purpose = "employee-password-reset",
            TokenHash = new string('a', 64),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(24),
            RecoveryVersion = invalid == "legacy-finalized" ? null : 1,
            OriginalTokenSha256 = new string('b', 64),
            OwnerSubject = "service:legacy-intranet",
            BoundNormalizedEmail = "EMPLOYEE@EXAMPLE.COM",
            BoundSecurityStamp = invalid == "empty-epoch" ? "" : "before-stamp",
            ConsumedAt = invalid == "empty-epoch" ? null : DateTimeOffset.UtcNow,
            FinalizedAt = invalid == "empty-epoch" ? null : DateTimeOffset.UtcNow,
            EffectActionId = invalid == "missing-effect" || invalid == "empty-epoch" ? null : id,
        });
        await Assert.ThrowsAsync<DbUpdateException>(() => fixture.State.SaveChangesAsync());
    }

    [Fact]
    public async Task Recovery_DisabledOptInCannotIssueOrCompleteOrMutateAdmin()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        var service = new EmployeeSelfService(fixture.Employees, fixture.State, fixture.Hasher, TimeProvider.System);
        await Assert.ThrowsAsync<EmployeeRecoveryUnavailableException>(() => service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default));
        await Assert.ThrowsAsync<EmployeeRecoveryUnavailableException>(() => service.CompletePasswordResetAsync(new("employee@example.com", "opaque", "password"), "service:legacy-intranet", default));
        var admin = new EmployeeIdentityAdminService(fixture.Employees, fixture.Hasher);
        await Assert.ThrowsAsync<EmployeeRecoveryUnavailableException>(() => admin.DeleteAsync(7, default));
        Assert.Empty(await fixture.State.IdentityActionTokens.ToListAsync());
        Assert.Single(await fixture.Employees.Users.ToListAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Expiry_WhileWaitingForIdentityLockRejectsUnappliedActionWithoutEffect(bool confirmation)
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 9, 30, 0, 0, 0, TimeSpan.Zero));
        await using var fixture = await Fixture.CreateAsync(postgres, clock);
        await fixture.SeedEmployeeAsync(emailConfirmed: !confirmation);
        await fixture.SeedRefreshSessionAsync();
        var before = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        var challenge = confirmation
            ? await fixture.Service.RequestEmailConfirmationAsync(new("employee@example.com"), "service:legacy-intranet", default)
            : await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var lockOwner = new EmployeeIdentityDbContext(new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
            .UseNpgsql(fixture.Employees.Database.GetConnectionString()).Options);
        await using var heldLock = await lockOwner.Database.BeginTransactionAsync(deadline.Token);
        await lockOwner.Database.ExecuteSqlRawAsync("SELECT 1 FROM \"AspNetUsers\" WHERE \"Id\"='employee-id' FOR UPDATE", deadline.Token);
        var boundary = new IdentityLockAttemptInterceptor();
        await using var waitingIdentity = new EmployeeIdentityDbContext(new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
            .UseNpgsql(fixture.Employees.Database.GetConnectionString()).AddInterceptors(boundary).Options);
        var controller = CreateController(new EmployeeSelfService(waitingIdentity, fixture.State, fixture.Hasher, clock, new EmployeeRecoveryOptions { Enabled = true }));
        var operation = CompleteAsync(controller, confirmation, challenge.Token!, "expired-password", deadline.Token);
        await boundary.Entered.Task.WaitAsync(deadline.Token);
        Assert.False(operation.IsCompleted);
        // The real database lock prevents the row read from completing. No sleep or fabricated timing gate.
        clock.Advance(TimeSpan.FromHours(25));
        await heldLock.CommitAsync(deadline.Token);
        var result = await operation.WaitAsync(deadline.Token);
        var after = await fixture.Employees.Users.AsNoTracking().SingleAsync(deadline.Token);
        var receipts = await fixture.Employees.RecoveryEffects.AsNoTracking().ToListAsync(deadline.Token);
        var action = await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync(deadline.Token);
        var session = await fixture.State.RefreshSessions.AsNoTracking().SingleAsync(deadline.Token);
        Assert.Multiple(
            () => Assert.IsType<BadRequestObjectResult>(result),
            () => Assert.Equal(before.PasswordHash, after.PasswordHash),
            () => Assert.Equal(before.SecurityStamp, after.SecurityStamp),
            () => Assert.Equal(before.ConcurrencyStamp, after.ConcurrencyStamp),
            () => Assert.Equal(before.EmailConfirmed, after.EmailConfirmed),
            () => Assert.Empty(receipts),
            () => Assert.Null(action.ConsumedAt),
            () => Assert.Null(session.RevokedAt));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Expiry_CommittedReceiptStillFinalizesAfterOriginalChallengeExpiry(bool confirmation)
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 9, 30, 0, 0, 0, TimeSpan.Zero));
        await using var fixture = await Fixture.CreateAsync(postgres, clock);
        await fixture.SeedEmployeeAsync(emailConfirmed: !confirmation);
        await fixture.SeedRefreshSessionAsync();
        var challenge = confirmation
            ? await fixture.Service.RequestEmailConfirmationAsync(new("employee@example.com"), "service:legacy-intranet", default)
            : await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default);
        var fault = new FinalizationAfterEffectFailureInterceptor();
        await using var faultyState = new RefreshSessionDbContext(new DbContextOptionsBuilder<RefreshSessionDbContext>()
            .UseNpgsql(fixture.State.Database.GetConnectionString()).AddInterceptors(fault).Options);
        var first = await CompleteAsync(CreateController(new EmployeeSelfService(fixture.Employees, faultyState, fixture.Hasher, clock,
            new EmployeeRecoveryOptions { Enabled = true })), confirmation, challenge.Token!, "applied-password", default);
        Assert.Equal(503, Assert.IsType<ObjectResult>(first).StatusCode);
        Assert.True(fault.Triggered);
        var applied = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        Assert.Null((await fixture.Employees.RecoveryEffects.AsNoTracking().SingleAsync()).FinalizedAcknowledgedAt);
        clock.Advance(TimeSpan.FromHours(25));
        Assert.IsType<NoContentResult>(await CompleteAsync(CreateController(fixture.Service), confirmation, challenge.Token!, "applied-password", default));
        var final = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        Assert.Equal(applied.PasswordHash, final.PasswordHash);
        Assert.Equal(applied.SecurityStamp, final.SecurityStamp);
        Assert.Equal(applied.ConcurrencyStamp, final.ConcurrencyStamp);
        Assert.NotNull((await fixture.Employees.RecoveryEffects.AsNoTracking().SingleAsync()).FinalizedAcknowledgedAt);
        Assert.NotNull((await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync()).FinalizedAt);
        Assert.Equal(!confirmation, (await fixture.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt is not null);
        Assert.IsType<BadRequestObjectResult>(await CompleteAsync(CreateController(fixture.Service), confirmation, challenge.Token!, "applied-password", default));
    }

    [Fact]
    public async Task Expiry_RolledBackTransientSaveRetryUsesFreshClockAndDoesNotApplyExpiredAction()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 9, 30, 0, 0, 0, TimeSpan.Zero));
        await using var fixture = await Fixture.CreateAsync(postgres, clock);
        await fixture.SeedEmployeeAsync();
        await fixture.SeedRefreshSessionAsync();
        var before = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        var challenge = await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default);
        var fault = new ExpiringTransientSaveInterceptor(clock);
        await using var identity = new EmployeeIdentityDbContext(new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
            .UseNpgsql(fixture.Employees.Database.GetConnectionString(), x => x.EnableRetryOnFailure(1, TimeSpan.Zero, null)).AddInterceptors(fault).Options);
        await using var auth = new RefreshSessionDbContext(new DbContextOptionsBuilder<RefreshSessionDbContext>()
            .UseNpgsql(fixture.State.Database.GetConnectionString(), x => x.EnableRetryOnFailure(1, TimeSpan.Zero, null)).Options);
        var service = new EmployeeSelfService(identity, auth, fixture.Hasher, clock, new EmployeeRecoveryOptions { Enabled = true });
        Assert.False(await service.CompletePasswordResetAsync(new("employee@example.com", challenge.Token!, "uncommitted-password"), "service:legacy-intranet", default));
        Assert.True(fault.Triggered);
        var after = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        Assert.Equal(before.PasswordHash, after.PasswordHash);
        Assert.Equal(before.SecurityStamp, after.SecurityStamp);
        Assert.Equal(before.ConcurrencyStamp, after.ConcurrencyStamp);
        Assert.Empty(await fixture.Employees.RecoveryEffects.ToListAsync());
        Assert.Null((await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
        Assert.Null((await fixture.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
    }

    private sealed class IdentityLockAttemptInterceptor : DbCommandInterceptor
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override ValueTask<InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(System.Data.Common.DbCommand command,
            CommandEventData eventData, InterceptionResult<System.Data.Common.DbDataReader> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("AspNetUsers", StringComparison.Ordinal) && command.CommandText.Contains("FOR UPDATE", StringComparison.Ordinal)) Entered.TrySetResult();
            return ValueTask.FromResult(result);
        }
    }

    private sealed class FinalizationAfterEffectFailureInterceptor : DbCommandInterceptor
    {
        public bool Triggered { get; private set; }
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(System.Data.Common.DbCommand command, CommandEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (!Triggered && command.CommandText.StartsWith("UPDATE", StringComparison.Ordinal) && command.CommandText.Contains("FinalizedAt", StringComparison.Ordinal))
            {
                Triggered = true;
                throw new InvalidOperationException("Synthetic post-effect finalization failure.");
            }
            return ValueTask.FromResult(result);
        }
    }

    private sealed class ExpiringTransientSaveInterceptor(FakeTimeProvider clock) : SaveChangesInterceptor
    {
        public bool Triggered { get; private set; }
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (!Triggered)
            {
                Triggered = true;
                clock.Advance(TimeSpan.FromHours(25));
                throw new TimeoutException("Synthetic precommit transient failure after expiry.");
            }
            return ValueTask.FromResult(result);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Recovery_UnknownCommitFreshProbeDoesNotRepeatPasswordOrStampEffect(bool authCommit)
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        await fixture.SeedRefreshSessionAsync();
        var challenge = await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default);
        var fault = new UnknownCommitInterceptor();
        var employeeBuilder = new DbContextOptionsBuilder<EmployeeIdentityDbContext>().UseNpgsql(fixture.Employees.Database.GetConnectionString(), x => x.EnableRetryOnFailure(1, TimeSpan.Zero, null));
        var stateBuilder = new DbContextOptionsBuilder<RefreshSessionDbContext>().UseNpgsql(fixture.State.Database.GetConnectionString(), x => x.EnableRetryOnFailure(1, TimeSpan.Zero, null));
        if (authCommit) stateBuilder.AddInterceptors(fault); else employeeBuilder.AddInterceptors(fault);
        await using var employeeContext = new EmployeeIdentityDbContext(employeeBuilder.Options);
        await using var stateContext = new RefreshSessionDbContext(stateBuilder.Options);
        var service = new EmployeeSelfService(employeeContext, stateContext, fixture.Hasher, TimeProvider.System, new EmployeeRecoveryOptions { Enabled = true });
        Assert.True(await service.CompletePasswordResetAsync(new("employee@example.com", challenge.Token!, "committed-password"), "service:legacy-intranet", default));
        Assert.True(fault.Triggered);
        var receipt = await fixture.Employees.RecoveryEffects.AsNoTracking().SingleAsync();
        var identity = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        Assert.Equal(receipt.PasswordPayloadHash, identity.PasswordHash);
        Assert.Equal(receipt.AfterSecurityStamp, identity.SecurityStamp);
        Assert.Equal(receipt.AfterConcurrencyStamp, identity.ConcurrencyStamp);
        Assert.NotNull(receipt.FinalizedAcknowledgedAt);
        Assert.NotNull((await fixture.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
        Assert.False(await fixture.Service.CompletePasswordResetAsync(new("employee@example.com", challenge.Token!, "committed-password"), "service:legacy-intranet", default));
    }

    private sealed class UnknownCommitInterceptor : DbTransactionInterceptor
    {
        public bool Triggered { get; private set; }
        public override Task TransactionCommittedAsync(System.Data.Common.DbTransaction transaction, TransactionEndEventData eventData, CancellationToken cancellationToken = default)
        {
            if (!Triggered)
            {
                Triggered = true;
                throw new TimeoutException("Synthetic uncertain commit acknowledgement.");
            }
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task HostedWorker_DeliversCommittedReceiptAndStopsCleanly()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        await fixture.SeedRefreshSessionAsync();
        await PendingResetAsync(fixture);
        var signal = new WorkerAcknowledgementInterceptor();
        await using var provider = WorkerProvider(fixture, identityInterceptor: signal);
        using var worker = new EmployeeRecoveryWorker(provider.GetRequiredService<IServiceScopeFactory>(), new EmployeeRecoveryOptions { Enabled = true }, NullLogger<EmployeeRecoveryWorker>.Instance);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await worker.StartAsync(deadline.Token);
        await signal.Completed.Task.WaitAsync(deadline.Token);
        await worker.StopAsync(deadline.Token);
        Assert.NotNull((await fixture.Employees.RecoveryEffects.AsNoTracking().SingleAsync(deadline.Token)).FinalizedAcknowledgedAt);
        Assert.NotNull((await fixture.State.RefreshSessions.AsNoTracking().SingleAsync(deadline.Token)).RevokedAt);
    }

    [Fact]
    public async Task HostedWorker_CancellationDuringFinalizationRetainsReceiptAndChallengeForNextWorker()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        await fixture.SeedRefreshSessionAsync();
        await PendingResetAsync(fixture);
        var block = new WorkerCancellationInterceptor();
        await using var provider = WorkerProvider(fixture, stateInterceptor: block);
        using var worker = new EmployeeRecoveryWorker(provider.GetRequiredService<IServiceScopeFactory>(), new EmployeeRecoveryOptions { Enabled = true }, NullLogger<EmployeeRecoveryWorker>.Instance);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await worker.StartAsync(deadline.Token);
        await block.Entered.Task.WaitAsync(deadline.Token);
        await worker.StopAsync(deadline.Token);
        Assert.Null((await fixture.Employees.RecoveryEffects.AsNoTracking().SingleAsync(deadline.Token)).FinalizedAcknowledgedAt);
        Assert.Null((await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync(deadline.Token)).ConsumedAt);
        Assert.Null((await fixture.State.RefreshSessions.AsNoTracking().SingleAsync(deadline.Token)).RevokedAt);
        Assert.Equal(1, await fixture.Service.ReconcileOutstandingAsync(deadline.Token));
    }

    [Fact]
    public async Task HostedWorker_DisabledOptInLeavesCommittedReceiptPending()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        await PendingResetAsync(fixture);
        await using var provider = new ServiceCollection().BuildServiceProvider();
        using var worker = new EmployeeRecoveryWorker(provider.GetRequiredService<IServiceScopeFactory>(), new EmployeeRecoveryOptions(), NullLogger<EmployeeRecoveryWorker>.Instance);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await worker.StartAsync(deadline.Token);
        await worker.StopAsync(deadline.Token);
        Assert.Null((await fixture.Employees.RecoveryEffects.AsNoTracking().SingleAsync(deadline.Token)).FinalizedAcknowledgedAt);
        Assert.Null((await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync(deadline.Token)).ConsumedAt);
    }

    private static ServiceProvider WorkerProvider(Fixture fixture, IInterceptor? identityInterceptor = null, IInterceptor? stateInterceptor = null)
    {
        var employeeOptions = new DbContextOptionsBuilder<EmployeeIdentityDbContext>().UseNpgsql(fixture.Employees.Database.GetConnectionString());
        var stateOptions = new DbContextOptionsBuilder<RefreshSessionDbContext>().UseNpgsql(fixture.State.Database.GetConnectionString());
        if (identityInterceptor is not null) employeeOptions.AddInterceptors(identityInterceptor);
        if (stateInterceptor is not null) stateOptions.AddInterceptors(stateInterceptor);
        return new ServiceCollection()
            .AddScoped(_ => new EmployeeIdentityDbContext(employeeOptions.Options))
            .AddScoped(_ => new RefreshSessionDbContext(stateOptions.Options))
            .AddSingleton<IPasswordHasher<LegacyIdentityRow>>(fixture.Hasher)
            .AddSingleton(TimeProvider.System)
            .AddSingleton(new EmployeeRecoveryOptions { Enabled = true })
            .AddScoped<EmployeeSelfService>().BuildServiceProvider();
    }

    private sealed class WorkerAcknowledgementInterceptor : DbCommandInterceptor
    {
        public TaskCompletionSource Completed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override ValueTask<int> NonQueryExecutedAsync(System.Data.Common.DbCommand command, CommandExecutedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.StartsWith("UPDATE", StringComparison.Ordinal) && command.CommandText.Contains("EmployeeRecoveryEffects", StringComparison.Ordinal)) Completed.TrySetResult();
            return ValueTask.FromResult(result);
        }
    }

    private sealed class WorkerCancellationInterceptor : DbCommandInterceptor
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(System.Data.Common.DbCommand command, CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.StartsWith("UPDATE", StringComparison.Ordinal) && command.CommandText.Contains("refresh_sessions", StringComparison.Ordinal))
            {
                Entered.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            return result;
        }
    }

    private static async Task<EmployeeActionChallenge> PendingResetAsync(Fixture fixture)
    {
        var challenge = await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), "service:legacy-intranet", default);
        var fault = new StateUpdateInterceptor("refresh_sessions", () => Task.FromException(new InvalidOperationException("Synthetic finalization failure.")));
        await using var failingState = new RefreshSessionDbContext(new DbContextOptionsBuilder<RefreshSessionDbContext>()
            .UseNpgsql(fixture.State.Database.GetConnectionString()).AddInterceptors(fault).Options);
        var controller = CreateController(new EmployeeSelfService(fixture.Employees, failingState, fixture.Hasher, TimeProvider.System, new EmployeeRecoveryOptions { Enabled = true }));
        var result = await controller.CompletePasswordReset(new("employee@example.com", challenge.Token!, "applied-password"), default);
        Assert.True(fault.Triggered);
        Assert.Equal(503, Assert.IsType<ObjectResult>(result).StatusCode);
        Assert.Null((await fixture.Employees.RecoveryEffects.AsNoTracking().SingleAsync()).FinalizedAcknowledgedAt);
        return challenge;
    }

    private static EmployeeSelfServiceController CreateController(EmployeeSelfService service) => new(service)
    {
        ControllerContext = new ControllerContext
        {
            HttpContext = new Microsoft.AspNetCore.Http.DefaultHttpContext
            {
                User = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
                    [new System.Security.Claims.Claim("sub", "service:legacy-intranet")], "fixture")),
            },
        },
    };

    private static Task<IActionResult> CompleteAsync(
        EmployeeSelfServiceController controller, bool confirmation, string token, string password, CancellationToken cancellationToken) =>
        confirmation
            ? controller.ConfirmEmail(new("employee@example.com", token), cancellationToken)
            : controller.CompletePasswordReset(new("employee@example.com", token, password), cancellationToken);

    private sealed class StateUpdateInterceptor(string table, Func<Task> beforeUpdate) : DbCommandInterceptor
    {
        public bool Triggered { get; private set; }

        public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            System.Data.Common.DbCommand command, CommandEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (!Triggered && command.CommandText.StartsWith("UPDATE", StringComparison.Ordinal)
                && command.CommandText.Contains(table, StringComparison.Ordinal))
            {
                Triggered = true;
                await beforeUpdate().WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
            }
            return result;
        }
    }

    private sealed class BootstrapInterceptor(Func<Task> competingWrite) : DbCommandInterceptor
    {
        public bool Triggered { get; private set; }
        public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            System.Data.Common.DbCommand command, CommandEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (!Triggered && command.CommandText.StartsWith("UPDATE", StringComparison.Ordinal)
                && command.CommandText.Contains("SecurityStamp", StringComparison.Ordinal))
            {
                Triggered = true;
                await competingWrite();
            }
            return result;
        }
    }

    private sealed class FailSaveInterceptor : SaveChangesInterceptor
    {
        public bool Triggered { get; private set; }

        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            Triggered = true;
            throw new InvalidOperationException("Synthetic employee identity persistence failure.");
        }
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
                timeProvider ?? TimeProvider.System, new EmployeeRecoveryOptions { Enabled = true });
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
            var employeeConnection = Employees.Database.GetConnectionString();
            var stateConnection = State.Database.GetConnectionString();
            await Employees.DisposeAsync();
            await State.DisposeAsync();
            // Each test owns unique disposable databases. Release their idle pools rather
            // than accumulating one server connection per database across the full suite.
            using var employeePool = new Npgsql.NpgsqlConnection(employeeConnection);
            using var statePool = new Npgsql.NpgsqlConnection(stateConnection);
            Npgsql.NpgsqlConnection.ClearPool(employeePool);
            Npgsql.NpgsqlConnection.ClearPool(statePool);
        }
    }
}
