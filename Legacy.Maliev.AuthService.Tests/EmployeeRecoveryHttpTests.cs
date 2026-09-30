using Legacy.Maliev.AuthService.Api.Authorization;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Hosting;
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

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>Real HTTP/model binding/JWT middleware against isolated PostgreSQL stores and actual recovery services.</summary>
[Collection(PostgresCollection.Name)]
public sealed class EmployeeRecoveryHttpTests(PostgresFixture postgres)
{
    private const string Root = "/auth/v1/employee-self-service/";

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

    private sealed class RecoveryFactory(Stores stores, bool enabled = true, FinalizationFault? fault = null) : WebApplicationFactory<Program>
    {
        private readonly RSA signing = RSA.Create(2048);

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
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
