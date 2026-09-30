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
            ? await fixture.Service.RequestEmailConfirmationAsync(new("employee@example.com"), default)
            : await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), default);
        var row = await fixture.Employees.Users.SingleAsync();
        if (change == "admin")
        {
            await using var adminContext = new EmployeeIdentityDbContext(
                new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
                    .UseNpgsql(fixture.Employees.Database.GetConnectionString()).Options);
            var admin = new EmployeeIdentityAdminService(adminContext, fixture.Hasher);
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
            ? await fixture.Service.ConfirmEmailAsync(new(row.Email!, old.Token!), default)
            : await fixture.Service.CompletePasswordResetAsync(new(row.Email!, old.Token!, "stale-password"), default);
        Assert.False(rejected);
        var unchanged = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        Assert.Equal(passwordHash, unchanged.PasswordHash);
        Assert.Equal(stamp, unchanged.SecurityStamp);
        Assert.Equal(!confirmation, unchanged.EmailConfirmed);
        Assert.Null((await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);

        var fresh = confirmation
            ? await fixture.Service.RequestEmailConfirmationAsync(new(row.Email!), default)
            : await fixture.Service.RequestPasswordResetAsync(new(row.Email!), default);
        var accepted = confirmation
            ? await fixture.Service.ConfirmEmailAsync(new(row.Email!, fresh.Token!), default)
            : await fixture.Service.CompletePasswordResetAsync(new(row.Email!, fresh.Token!, "fresh-password"), default);
        Assert.True(accepted);
        Assert.False(confirmation
            ? await fixture.Service.ConfirmEmailAsync(new(row.Email!, fresh.Token!), default)
            : await fixture.Service.CompletePasswordResetAsync(new(row.Email!, fresh.Token!, "replayed-password"), default));
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
            ? await fixture.Service.ConfirmEmailAsync(new("employee@example.com", oldToken), default)
            : await fixture.Service.CompletePasswordResetAsync(new("employee@example.com", oldToken, "new-password"), default));
        Assert.Null((await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
    }

    [Fact]
    public async Task CompletePasswordReset_ConcurrentRequestsHaveOnlyOneWinner()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        var challenge = await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), default);
        await using var employee2 = new EmployeeIdentityDbContext(new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
            .UseNpgsql(fixture.Employees.Database.GetConnectionString()).Options);
        await using var state2 = new RefreshSessionDbContext(new DbContextOptionsBuilder<RefreshSessionDbContext>()
            .UseNpgsql(fixture.State.Database.GetConnectionString()).Options);
        var service2 = new EmployeeSelfService(employee2, state2, fixture.Hasher, TimeProvider.System);
        var results = await Task.WhenAll(
            fixture.Service.CompletePasswordResetAsync(new("employee@example.com", challenge.Token!, "winner-one"), default),
            service2.CompletePasswordResetAsync(new("employee@example.com", challenge.Token!, "winner-two"), default));
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
            ? await fixture.Service.RequestEmailConfirmationAsync(new("employee@example.com"), default)
            : await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), default);
        Assert.NotNull(challenge.Token);
        Assert.False(string.IsNullOrWhiteSpace((await fixture.Employees.Users.AsNoTracking().SingleAsync()).SecurityStamp));
        Assert.True(confirmation
            ? await fixture.Service.ConfirmEmailAsync(new("employee@example.com", challenge.Token!), default)
            : await fixture.Service.CompletePasswordResetAsync(new("employee@example.com", challenge.Token!, "fresh-password"), default));
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
                var admin = new EmployeeIdentityAdminService(fixture.Employees, fixture.Hasher);
                Assert.True(await admin.UpdateAsync(7, new("employee@example.com", "employee@example.com", true,
                    null, false, false, null, true), default));
            }
            else
            {
                Assert.NotNull((await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), default)).Token);
            }
            winningStamp = (await fixture.Employees.Users.AsNoTracking().SingleAsync()).SecurityStamp;
        });
        await using var racingContext = new EmployeeIdentityDbContext(new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
            .UseNpgsql(fixture.Employees.Database.GetConnectionString()).AddInterceptors(barrier).Options);
        await using var racingState = new RefreshSessionDbContext(new DbContextOptionsBuilder<RefreshSessionDbContext>()
            .UseNpgsql(fixture.State.Database.GetConnectionString()).Options);
        var racingService = new EmployeeSelfService(racingContext, racingState, fixture.Hasher, TimeProvider.System);
        var result = await racingService.RequestPasswordResetAsync(new("employee@example.com"), default);
        Assert.True(barrier.Triggered);
        Assert.True(result.Accepted);
        Assert.True(result.Token is null);
        Assert.Equal(winningStamp, (await fixture.Employees.Users.AsNoTracking().SingleAsync()).SecurityStamp);
        Assert.NotNull((await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), default)).Token);
    }

    [Fact]
    public async Task CompletePasswordReset_IdentitySaveFailureIsNotSuccessAndFreshRequestCanRecover()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await fixture.SeedEmployeeAsync();
        var before = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        var challenge = await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), default);
        await using var failingContext = new EmployeeIdentityDbContext(new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
            .UseNpgsql(fixture.Employees.Database.GetConnectionString()).AddInterceptors(new FailSaveInterceptor()).Options);
        var failing = new EmployeeSelfService(failingContext, fixture.State, fixture.Hasher, TimeProvider.System);
        await Assert.ThrowsAsync<InvalidOperationException>(() => failing.CompletePasswordResetAsync(
            new("employee@example.com", challenge.Token!, "not-persisted"), default));
        var after = await fixture.Employees.Users.AsNoTracking().SingleAsync();
        Assert.Equal(before.PasswordHash, after.PasswordHash);
        Assert.Equal(before.SecurityStamp, after.SecurityStamp);
        Assert.NotNull((await fixture.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
        Assert.False(await fixture.Service.CompletePasswordResetAsync(new("employee@example.com", challenge.Token!, "replay"), default));
        var fresh = await fixture.Service.RequestPasswordResetAsync(new("employee@example.com"), default);
        Assert.True(await fixture.Service.CompletePasswordResetAsync(new("employee@example.com", fresh.Token!, "recovered"), default));
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
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Synthetic employee identity persistence failure.");
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
