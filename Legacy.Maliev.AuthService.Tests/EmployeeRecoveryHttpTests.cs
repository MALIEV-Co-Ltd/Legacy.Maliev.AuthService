using Legacy.Maliev.AuthService.Api.Authorization;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>Real HTTP/model binding/JWT middleware against isolated PostgreSQL stores and actual recovery services.</summary>
[Collection(PostgresCollection.Name)]
public sealed class EmployeeRecoveryHttpTests(PostgresFixture postgres)
{
    private const string Root = "/auth/v1/employee-self-service/";

    [Theory]
    [InlineData("employee@example.com", true)]
    [InlineData("\"employee@office\"@example.com", true)]
    [InlineData("Employee <employee@example.com>", false)]
    [InlineData(" employee@example.com ", false)]
    [InlineData("invalid-address", false)]
    [InlineData("", false)]
    [InlineData("overlong", false)]
    [InlineData("maximum", true)]
    [InlineData("employee\r\n@example.com", false)]
    [InlineData("employee\t@example.com", false)]
    public async Task RecoveryEmail_SyntaxMatchesHistoricalBareAddressPredicate(string email, bool accepted)
    {
        if (email == "overlong") email = new string('a', 310) + "@maliev.test";
        if (email == "maximum") email = new string('a', 308) + "@maliev.test";
        if (email.StartsWith('"'))
        {
            Assert.Equal(email, new System.Net.Mail.MailAddress(email).Address);
            Assert.False(new System.ComponentModel.DataAnnotations.EmailAddressAttribute().IsValid(email));
        }
        await using var stores = await Stores.CreateAsync(postgres);
        // The DTO bound is 320; persisted legacy identity email is separately bounded to 256.
        if (accepted && email.Length <= 256)
            await stores.Employees.Users.ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.Email, email)
                .SetProperty(row => row.NormalizedEmail, email.ToUpperInvariant()));
        using var factory = new RecoveryFactory(stores, production: true);
        using var owner = factory.Client(factory.Token());
        var before = await RecoverySnapshotAsync(stores);
        using var request = await owner.PostAsJsonAsync(Root + "password-reset/request", new EmployeeActionRequest(email));
        Assert.Equal(accepted ? HttpStatusCode.OK : HttpStatusCode.BadRequest, request.StatusCode);
        if (!accepted)
        {
            Assert.Equal(before, await RecoverySnapshotAsync(stores));
            return;
        }
        var reset = (await request.Content.ReadFromJsonAsync<EmployeeActionChallenge>())!;
        if (email.Length == 320)
        {
            Assert.True(reset.Accepted);
            Assert.Null(reset.Token); // Admission accepts the bound; an absent account stays enumeration-safe.
            Assert.Equal(before, await RecoverySnapshotAsync(stores));
            return;
        }
        Assert.False(string.IsNullOrWhiteSpace(reset.Token));
        using var completion = await owner.PostAsJsonAsync(Root + "password-reset/complete",
            new CompleteEmployeePasswordResetRequest(email, reset.Token!, "replacement-password"));
        Assert.Equal(HttpStatusCode.NoContent, completion.StatusCode);
        using var confirmation = await owner.PostAsJsonAsync(Root + "email-confirmation/request", new EmployeeActionRequest(email));
        Assert.Equal(HttpStatusCode.OK, confirmation.StatusCode);
        var challenge = (await confirmation.Content.ReadFromJsonAsync<EmployeeActionChallenge>())!;
        Assert.False(string.IsNullOrWhiteSpace(challenge.Token));
        using var confirmed = await owner.PostAsJsonAsync(Root + "email-confirmation/complete",
            new CompleteEmployeeActionRequest(email, challenge.Token!));
        Assert.Equal(HttpStatusCode.NoContent, confirmed.StatusCode);
    }

    [Theory]
    [InlineData("email-confirmation")]
    [InlineData("password-reset")]
    public async Task RecoveryEmail_InvalidAdmissionPreservesRealChallengeAndStoredState(string purpose)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        using var factory = new RecoveryFactory(stores, production: true);
        using var owner = factory.Client(factory.Token());
        string?[] invalid = [null, "", "   ", "Employee <employee@example.com>", " employee@example.com ",
            "invalid-address", "employee\r\n@example.com", "employee\t@example.com", new string('a', 310) + "@maliev.test"];
        var initial = await RecoverySnapshotAsync(stores);
        foreach (var email in invalid)
        {
            using var rejected = await owner.PostAsJsonAsync(Root + purpose + "/request", new EmployeeActionRequest(email!));
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
            Assert.Equal(initial, await RecoverySnapshotAsync(stores));
        }
        using var issued = await owner.PostAsJsonAsync(Root + purpose + "/request", new EmployeeActionRequest("employee@example.com"));
        Assert.Equal(HttpStatusCode.OK, issued.StatusCode);
        var challenge = (await issued.Content.ReadFromJsonAsync<EmployeeActionChallenge>())!;
        Assert.False(string.IsNullOrWhiteSpace(challenge.Token));
        var before = await RecoverySnapshotAsync(stores);
        foreach (var email in invalid)
        {
            object payload = purpose == "email-confirmation"
                ? new CompleteEmployeeActionRequest(email!, challenge.Token!)
                : new CompleteEmployeePasswordResetRequest(email!, challenge.Token!, "replacement-password");
            using var rejected = await owner.PostAsJsonAsync(Root + purpose + "/complete", payload);
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
            var body = await rejected.Content.ReadAsStringAsync();
            Assert.DoesNotContain(challenge.Token!, body);
            Assert.DoesNotContain("replacement-password", body);
            Assert.Equal(before, await RecoverySnapshotAsync(stores));
        }
        object valid = purpose == "email-confirmation"
            ? new CompleteEmployeeActionRequest("employee@example.com", challenge.Token!)
            : new CompleteEmployeePasswordResetRequest("employee@example.com", challenge.Token!, "replacement-password");
        using var completed = await owner.PostAsJsonAsync(Root + purpose + "/complete", valid);
        Assert.Equal(HttpStatusCode.NoContent, completed.StatusCode);
        using var replay = await owner.PostAsJsonAsync(Root + purpose + "/complete", valid);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task ResetPasswordPolicy_NewEffectRejectsInvalidPasswordWithoutConsumingChallenge_ValidBoundaryAppliesOnce(int boundary)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await stores.Employees.Users.ExecuteUpdateAsync(setters => setters
            .SetProperty(row => row.AccessFailedCount, 2)
            .SetProperty(row => row.LockoutEnd, DateTimeOffset.UtcNow.AddMinutes(5)));
        await SeedOldSessionAsync(stores);
        using var factory = new RecoveryFactory(stores, production: true);
        using var owner = factory.Client(factory.Token());
        using var issuance = await owner.PostAsJsonAsync(Root + "password-reset/request", new EmployeeActionRequest("employee@example.com"));
        Assert.Equal(HttpStatusCode.OK, issuance.StatusCode);
        var challenge = (await issuance.Content.ReadFromJsonAsync<EmployeeActionChallenge>())!;
        var before = await RecoverySnapshotAsync(stores);
        foreach (var password in new string?[] { "aaaaaaaa", "abcde", "", null, "abcdef" + new string('a', 1019) })
        {
            using var rejected = await owner.PostAsJsonAsync(Root + "password-reset/complete",
                new CompleteEmployeePasswordResetRequest("employee@example.com", challenge.Token!, password!));
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
            var body = await rejected.Content.ReadAsStringAsync();
            Assert.DoesNotContain(challenge.Token!, body);
            Assert.DoesNotContain("employee@example.com", body);
            if (!string.IsNullOrEmpty(password)) Assert.DoesNotContain(password, body);
            Assert.Equal(before, await RecoverySnapshotAsync(stores));
        }
        var valid = boundary switch { 0 => "abcdef", 1 => "abcdef" + new string('a', 1018), _ => "😀abcd" };
        using var accepted = await owner.PostAsJsonAsync(Root + "password-reset/complete",
            new CompleteEmployeePasswordResetRequest("employee@example.com", challenge.Token!, valid));
        Assert.Equal(HttpStatusCode.NoContent, accepted.StatusCode);
        var row = await stores.Employees.Users.AsNoTracking().SingleAsync();
        Assert.Equal(PasswordVerificationResult.Success, new PasswordHasher<LegacyIdentityRow>().VerifyHashedPassword(row, row.PasswordHash!, valid));
        Assert.NotEqual("original-security-stamp", row.SecurityStamp);
        Assert.Equal(0, row.AccessFailedCount);
        Assert.Null(row.LockoutEnd);
        Assert.NotNull((await stores.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
        var action = await stores.State.IdentityActionTokens.AsNoTracking().SingleAsync();
        var receipt = await stores.Employees.RecoveryEffects.AsNoTracking().SingleAsync();
        Assert.NotNull(action.ConsumedAt);
        Assert.Equal(receipt.ActionId, action.EffectActionId);
        Assert.Equal(row.SecurityStamp, receipt.AfterSecurityStamp);
        Assert.Equal(row.PasswordHash, receipt.PasswordPayloadHash);
        var completed = await RecoverySnapshotAsync(stores);
        using var replay = await owner.PostAsJsonAsync(Root + "password-reset/complete",
            new CompleteEmployeePasswordResetRequest("employee@example.com", challenge.Token!, valid));
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.Equal(completed, await RecoverySnapshotAsync(stores));
    }

    [Fact]
    public async Task ResetPasswordPolicy_PreviouslyCommittedWeakReceiptFinalizesWithoutRewritingIdentity()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await SeedOldSessionAsync(stores);
        using var factory = new RecoveryFactory(stores, production: true);
        using var owner = factory.Client(factory.Token());
        using var issuance = await owner.PostAsJsonAsync(Root + "password-reset/request", new EmployeeActionRequest("employee@example.com"));
        Assert.Equal(HttpStatusCode.OK, issuance.StatusCode);
        var challenge = (await issuance.Content.ReadFromJsonAsync<EmployeeActionChallenge>())!;
        var action = await stores.State.IdentityActionTokens.AsNoTracking().SingleAsync();
        // Independently constructed Identity V2 PBKDF2-SHA1/1000 vector, salt bytes 00..0f, password aaaaaaaa.
        const string legacyHash = "AAABAgMEBQYHCAkKCwwNDg91ZESw9Z1BEnaDrIvRk7bmBCAdxYXr4aE11Ui5+tlLJQ==";
        await stores.Employees.Users.ExecuteUpdateAsync(setters => setters
            .SetProperty(row => row.PasswordHash, legacyHash)
            .SetProperty(row => row.SecurityStamp, "legacy-reset-applied-stamp")
            .SetProperty(row => row.ConcurrencyStamp, "legacy-reset-applied-concurrency"));
        stores.Employees.RecoveryEffects.Add(new EmployeeRecoveryEffect
        {
            ActionId = action.Id,
            TokenSha256 = action.OriginalTokenSha256!,
            Purpose = action.Purpose,
            OwnerSubject = action.OwnerSubject!,
            IdentityId = action.IdentityId,
            NormalizedEmail = action.BoundNormalizedEmail!,
            BeforeSecurityStamp = action.BoundSecurityStamp!,
            AfterSecurityStamp = "legacy-reset-applied-stamp",
            AfterConcurrencyStamp = "legacy-reset-applied-concurrency",
            PasswordPayloadHash = legacyHash,
            AppliedAt = DateTimeOffset.UtcNow,
        });
        await stores.Employees.SaveChangesAsync();
        var before = await RecoverySnapshotAsync(stores);
        using var changed = await owner.PostAsJsonAsync(Root + "password-reset/complete",
            new CompleteEmployeePasswordResetRequest("employee@example.com", challenge.Token!, "changed-password"));
        Assert.Equal(HttpStatusCode.BadRequest, changed.StatusCode);
        Assert.Equal(before, await RecoverySnapshotAsync(stores));
        var identityBefore = JsonSerializer.Serialize(await stores.Employees.Users.AsNoTracking().SingleAsync());
        using var retry = await owner.PostAsJsonAsync(Root + "password-reset/complete",
            new CompleteEmployeePasswordResetRequest("employee@example.com", challenge.Token!, "aaaaaaaa"));
        Assert.Equal(HttpStatusCode.NoContent, retry.StatusCode);
        Assert.Equal(identityBefore, JsonSerializer.Serialize(await stores.Employees.Users.AsNoTracking().SingleAsync()));
        Assert.NotNull((await stores.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
        Assert.NotNull((await stores.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
        Assert.NotNull((await stores.Employees.RecoveryEffects.AsNoTracking().SingleAsync()).FinalizedAcknowledgedAt);
        var completed = await RecoverySnapshotAsync(stores);
        using var replay = await owner.PostAsJsonAsync(Root + "password-reset/complete",
            new CompleteEmployeePasswordResetRequest("employee@example.com", challenge.Token!, "aaaaaaaa"));
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.Equal(completed, await RecoverySnapshotAsync(stores));
    }

    private static async Task SeedOldSessionAsync(Stores stores)
    {
        var row = await stores.Employees.Users.AsNoTracking().SingleAsync();
        stores.State.RefreshSessions.Add(new RefreshSession
        {
            Id = Guid.NewGuid(),
            FamilyId = Guid.NewGuid(),
            IdentityId = row.Id,
            IdentityKind = IdentityKind.Employee,
            SecurityStamp = row.SecurityStamp,
            TokenHash = Convert.ToHexString(SHA256.HashData("reset-policy-old-session"u8.ToArray())).ToLowerInvariant(),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
        });
        await stores.State.SaveChangesAsync();
    }

    private static async Task<string> RecoverySnapshotAsync(Stores stores) => JsonSerializer.Serialize(new
    {
        Employees = await stores.Employees.Users.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
        Customers = await stores.Customers.Users.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
        Effects = await stores.Employees.RecoveryEffects.AsNoTracking().OrderBy(row => row.ActionId).ToListAsync(),
        Actions = await stores.State.IdentityActionTokens.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
        Sessions = await stores.State.RefreshSessions.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
    });

    [Theory]
    [InlineData("missing-sub", HttpStatusCode.Forbidden)]
    [InlineData("duplicate-sub", HttpStatusCode.Unauthorized)]
    [InlineData("empty-sub", HttpStatusCode.Forbidden)]
    [InlineData("wrong-owner", HttpStatusCode.BadRequest)]
    [InlineData("no-permission", HttpStatusCode.Forbidden)]
    [InlineData("bad-signature", HttpStatusCode.Unauthorized)]
    [InlineData("expired", HttpStatusCode.Unauthorized)]
    public async Task Complete_ResetInvalidValidatedCallerNeverMutatesIdentity(string caller, HttpStatusCode expected)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        using var factory = new RecoveryFactory(stores);
        using var owner = factory.Client(factory.Token());
        using var challengeResponse = await owner.PostAsJsonAsync(Root + "password-reset/request", new EmployeeActionRequest("employee@example.com"));
        Assert.Equal(HttpStatusCode.OK, challengeResponse.StatusCode);
        var challenge = (await challengeResponse.Content.ReadFromJsonAsync<EmployeeActionChallenge>())!;
        using var invalid = factory.Client(factory.Token(caller));
        using var result = await invalid.PostAsJsonAsync(Root + "password-reset/complete", new CompleteEmployeePasswordResetRequest("employee@example.com", challenge.Token!, "new-password"));
        Assert.Equal(expected, result.StatusCode);
        Assert.Empty(await stores.Employees.RecoveryEffects.ToListAsync());
        Assert.Equal("original-security-stamp", (await stores.Employees.Users.AsNoTracking().SingleAsync()).SecurityStamp);
        Assert.Null((await stores.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
        using var success = await owner.PostAsJsonAsync(Root + "password-reset/complete", new CompleteEmployeePasswordResetRequest("employee@example.com", challenge.Token!, "new-password"));
        Assert.Equal(HttpStatusCode.NoContent, success.StatusCode);
    }

    [Fact]
    public async Task Complete_PendingResetWrongPayloadEmailPurposeOwnerFails_OriginalRetryFinalizes_ThenReplayFails()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var fault = new FinalizationFault();
        using var factory = new RecoveryFactory(stores, fault: fault);
        using var owner = factory.Client(factory.Token());
        using var issuance = await owner.PostAsJsonAsync(Root + "password-reset/request", new EmployeeActionRequest("employee@example.com"));
        var challenge = (await issuance.Content.ReadFromJsonAsync<EmployeeActionChallenge>())!;
        using var first = await owner.PostAsJsonAsync(Root + "password-reset/complete", new CompleteEmployeePasswordResetRequest("employee@example.com", challenge.Token!, "applied-password"));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, first.StatusCode);
        var body = await first.Content.ReadAsStringAsync();
        Assert.DoesNotContain("Synthetic", body);
        Assert.DoesNotContain(challenge.Token!, body);
        Assert.DoesNotContain("applied-password", body);
        Assert.True(fault.Triggered);
        var applied = await stores.Employees.Users.AsNoTracking().SingleAsync();
        using var wrongPayload = await owner.PostAsJsonAsync(Root + "password-reset/complete", new CompleteEmployeePasswordResetRequest("employee@example.com", challenge.Token!, "wrong-password"));
        using var wrongEmail = await owner.PostAsJsonAsync(Root + "password-reset/complete", new CompleteEmployeePasswordResetRequest("other@example.com", challenge.Token!, "applied-password"));
        using var wrongPurpose = await owner.PostAsJsonAsync(Root + "email-confirmation/complete", new CompleteEmployeeActionRequest("employee@example.com", challenge.Token!));
        using var other = factory.Client(factory.Token("wrong-owner"));
        using var wrongOwner = await other.PostAsJsonAsync(Root + "password-reset/complete", new CompleteEmployeePasswordResetRequest("employee@example.com", challenge.Token!, "applied-password"));
        Assert.All(new[] { wrongPayload, wrongEmail, wrongPurpose, wrongOwner }, x => Assert.Equal(HttpStatusCode.BadRequest, x.StatusCode));
        using var retry = await owner.PostAsJsonAsync(Root + "password-reset/complete", new CompleteEmployeePasswordResetRequest("employee@example.com", challenge.Token!, "applied-password"));
        Assert.Equal(HttpStatusCode.NoContent, retry.StatusCode);
        var after = await stores.Employees.Users.AsNoTracking().SingleAsync();
        Assert.Equal(applied.PasswordHash, after.PasswordHash);
        Assert.Equal(applied.SecurityStamp, after.SecurityStamp);
        Assert.Equal(applied.ConcurrencyStamp, after.ConcurrencyStamp);
        using var replay = await owner.PostAsJsonAsync(Root + "password-reset/complete", new CompleteEmployeePasswordResetRequest("employee@example.com", challenge.Token!, "applied-password"));
        using var finalizedWrongPayload = await owner.PostAsJsonAsync(Root + "password-reset/complete", new CompleteEmployeePasswordResetRequest("employee@example.com", challenge.Token!, "other-password"));
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, finalizedWrongPayload.StatusCode);
        Assert.Single(await stores.Employees.RecoveryEffects.ToListAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Issuance_DisabledOrPhysicalSchemaUnavailableMapsGeneric503(bool physicalDrift)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        if (physicalDrift) await stores.Employees.Database.ExecuteSqlRawAsync("DROP INDEX \"IX_EmployeeRecoveryEffects_TokenSha256_Purpose\"");
        using var factory = new RecoveryFactory(stores, enabled: physicalDrift);
        using var client = factory.Client(factory.Token());
        using var response = await client.PostAsJsonAsync(Root + "password-reset/request", new EmployeeActionRequest("employee@example.com"));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("Npgsql", body);
        Assert.DoesNotContain("EmployeeRecoveryEffects", body);
        Assert.Empty(await stores.State.IdentityActionTokens.ToListAsync());
        using var readiness = await client.GetAsync("/auth/readiness");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, readiness.StatusCode);
    }

    private sealed class FinalizationFault : DbCommandInterceptor
    {
        public bool Triggered { get; private set; }
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(System.Data.Common.DbCommand command, CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (!Triggered && command.CommandText.StartsWith("UPDATE", StringComparison.Ordinal) && command.CommandText.Contains("refresh_sessions", StringComparison.Ordinal))
            {
                Triggered = true;
                throw new InvalidOperationException("Synthetic HTTP finalization failure.");
            }
            return ValueTask.FromResult(result);
        }
    }

    private sealed class RecoveryFactory(Stores stores, bool enabled = true, FinalizationFault? fault = null, bool production = false) : WebApplicationFactory<Program>
    {
        private readonly RSA signing = RSA.Create(2048);

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment(production ? "Production" : "Testing");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:CustomerIdentity"] = stores.Customers.Database.GetConnectionString(),
                ["ConnectionStrings:EmployeeIdentity"] = stores.Employees.Database.GetConnectionString(),
                ["ConnectionStrings:RefreshSessions"] = stores.State.Database.GetConnectionString(),
                ["EmployeeRecovery:Enabled"] = enabled.ToString(),
                ["Jwt:Issuer"] = "https://recovery.test",
                ["Jwt:Audience"] = "recovery-test",
                ["Jwt:PrivateKeyPem"] = signing.ExportPkcs8PrivateKeyPem(),
                ["Jwt:KeyId"] = "recovery-test",
                ["Jwt:AccessTokenLifetimeSeconds"] = "900",
            }));
            builder.ConfigureTestServices(services =>
            {
                // Worker behavior is separately tested; deterministic HTTP fault windows must not race an unrelated timer.
                foreach (var descriptor in services.Where(x => x.ServiceType == typeof(IHostedService) && x.ImplementationType == typeof(EmployeeRecoveryWorker)).ToArray()) services.Remove(descriptor);
                if (fault is not null) services.AddDbContext<RefreshSessionDbContext>(options => options.AddInterceptors(fault));
            });
        }

        public HttpClient Client(string token)
        {
            var client = CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return client;
        }

        public string Token(string caller = "owner")
        {
            var claims = new List<Claim> { new("identity_kind", "service") };
            if (caller != "missing-sub") claims.Add(new("sub", caller == "wrong-owner" ? "service:other" : caller == "empty-sub" ? "" : "service:legacy-intranet"));
            if (caller == "duplicate-sub") claims.Add(new("sub", "service:other"));
            if (caller != "no-permission") claims.Add(new("permissions", EmployeeSelfServicePermissions.Use));
            using var otherKey = caller == "bad-signature" ? RSA.Create(2048) : null;
            var now = DateTime.UtcNow;
            var token = new JwtSecurityToken("https://recovery.test", "recovery-test", claims, now.AddMinutes(-10), caller == "expired" ? now.AddMinutes(-5) : now.AddMinutes(10),
                new SigningCredentials(new RsaSecurityKey(otherKey ?? signing) { KeyId = "recovery-test" }, SecurityAlgorithms.RsaSha256));
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing) signing.Dispose();
        }
    }

    private sealed class Stores(EmployeeIdentityDbContext employees, RefreshSessionDbContext state, CustomerIdentityDbContext customers) : IAsyncDisposable
    {
        public EmployeeIdentityDbContext Employees { get; } = employees;
        public RefreshSessionDbContext State { get; } = state;
        public CustomerIdentityDbContext Customers { get; } = customers;

        public static async Task<Stores> CreateAsync(PostgresFixture postgres)
        {
            var stores = new Stores(await postgres.CreateEmployeeContextAsync(), await postgres.CreateStateContextAsync(), await postgres.CreateCustomerContextAsync());
            var admin = new EmployeeIdentityAdminService(stores.Employees, new Microsoft.AspNetCore.Identity.PasswordHasher<LegacyIdentityRow>());
            await admin.CreateAsync(7, new("employee@example.com", "employee@example.com", "original-password", false, null), default);
            await stores.Employees.Users.ExecuteUpdateAsync(s => s.SetProperty(x => x.SecurityStamp, "original-security-stamp"));
            return stores;
        }

        public async ValueTask DisposeAsync()
        {
            foreach (var context in new DbContext[] { Employees, State, Customers })
            {
                var connection = context.Database.GetConnectionString();
                await context.DisposeAsync();
                using var pool = new Npgsql.NpgsqlConnection(connection);
                Npgsql.NpgsqlConnection.ClearPool(pool);
            }
        }
    }
}
