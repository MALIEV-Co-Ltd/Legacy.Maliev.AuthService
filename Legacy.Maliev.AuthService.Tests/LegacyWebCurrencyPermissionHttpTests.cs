using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class LegacyWebCurrencyPermissionHttpTests(PostgresFixture postgres)
{
    [Fact]
    public async Task NormalLogin_SourceOwnedWebReadGrant_IsSignedAndDoesNotMutateConfiguration()
    {
        await using var employees = await postgres.CreateEmployeeContextAsync();
        await using var customers = await postgres.CreateCustomerContextAsync();
        await using var sessions = await postgres.CreateStateContextAsync();
        await using var app = new Factory(employees, customers, sessions);
        using var client = app.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var token = await app.LoginAsync(client, "legacy-web");
        var principal = app.Validate(token);

        Assert.Equal("service:legacy-web", principal.FindFirst("sub")?.Value);
        Assert.Equal("service", principal.FindFirst("identity_kind")?.Value);
        Assert.Equal(["legacy-contact.messages.create", LegacyAccessTokenPermissions.CatalogCurrenciesRead],
            principal.FindAll("permissions").Select(claim => claim.Value));
        Assert.DoesNotContain(principal.Claims, claim => claim.Type.Contains("secret", StringComparison.OrdinalIgnoreCase)
            || claim.Type.Contains("refresh", StringComparison.OrdinalIgnoreCase));
        var configured = app.Services.GetRequiredService<IOptions<ServiceClientOptions>>().Value.Clients["legacy-web"].Permissions;
        Assert.Equal(["legacy-contact.messages.create"], configured);
    }

    [Theory]
    [InlineData("legacy-other")]
    [InlineData("legacy-web-other")]
    public async Task NormalLogin_OtherRegisteredMachine_DoesNotReceiveImplicitCurrencyGrant(string clientId)
    {
        await using var employees = await postgres.CreateEmployeeContextAsync();
        await using var customers = await postgres.CreateCustomerContextAsync();
        await using var sessions = await postgres.CreateStateContextAsync();
        await using var app = new Factory(employees, customers, sessions);
        using var client = app.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var principal = app.Validate(await app.LoginAsync(client, clientId));
        Assert.Equal("service:" + clientId, principal.FindFirst("sub")?.Value);
        Assert.Equal(["legacy-contact.messages.create"], principal.FindAll("permissions").Select(claim => claim.Value));
    }

    [Fact]
    public async Task NormalLogin_BadOrUnknownCredential_RefusesWithoutGrantOrToken()
    {
        await using var employees = await postgres.CreateEmployeeContextAsync();
        await using var customers = await postgres.CreateCustomerContextAsync();
        await using var sessions = await postgres.CreateStateContextAsync();
        await using var app = new Factory(employees, customers, sessions);
        using var client = app.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        string? title = null;
        foreach (var request in new[]
        {
            new ServiceLoginRequest("legacy-web", Convert.ToHexString(RandomNumberGenerator.GetBytes(24))),
            new ServiceLoginRequest("unregistered-web", app.Secret("legacy-web")),
            new ServiceLoginRequest("LEGACY-WEB", app.Secret("legacy-web")),
        })
        {
            using var response = await client.PostAsJsonAsync("/auth/v1/service/login", request);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            var body = await response.Content.ReadAsStringAsync();
            Assert.DoesNotContain(request.ClientSecret, body, StringComparison.Ordinal);
            using var json = JsonDocument.Parse(body);
            Assert.False(json.RootElement.TryGetProperty("accessToken", out _));
            var currentTitle = json.RootElement.GetProperty("title").GetString();
            Assert.NotNull(currentTitle);
            if (title is not null) Assert.Equal(title, currentTitle);
            title = currentTitle;
        }
    }

    [Fact]
    public async Task NormalIssuedToken_WrongAudienceOrVerificationKey_IsRejected()
    {
        await using var employees = await postgres.CreateEmployeeContextAsync();
        await using var customers = await postgres.CreateCustomerContextAsync();
        await using var sessions = await postgres.CreateStateContextAsync();
        await using var app = new Factory(employees, customers, sessions);
        using var client = app.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var token = await app.LoginAsync(client, "legacy-web");
        Assert.Throws<SecurityTokenInvalidAudienceException>(() => app.Validate(token, "wrong-audience"));
        using var wrongKey = RSA.Create(2048);
        Assert.ThrowsAny<SecurityTokenException>(() => app.Validate(token, key: new RsaSecurityKey(wrongKey)));
    }

    [Fact]
    public async Task NormalIssuedToken_ExpiredServerObservation_IsRejectedWithoutSleep()
    {
        await using var employees = await postgres.CreateEmployeeContextAsync();
        await using var customers = await postgres.CreateCustomerContextAsync();
        await using var sessions = await postgres.CreateStateContextAsync();
        await using var app = new Factory(employees, customers, sessions, DateTimeOffset.UtcNow.AddHours(-1));
        using var client = app.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var token = await app.LoginAsync(client, "legacy-web");
        Assert.Throws<SecurityTokenExpiredException>(() => app.Validate(token));
    }

    private sealed class Factory(EmployeeIdentityDbContext employees, CustomerIdentityDbContext customers,
        RefreshSessionDbContext sessions, DateTimeOffset? issuedAt = null) : WebApplicationFactory<Program>
    {
        private const string Issuer = "https://registered-web-grant.test";
        private const string Audience = "registered-web-catalog";
        private readonly RSA signer = RSA.Create(2048);
        private readonly Dictionary<string, string> credentials = new(StringComparer.Ordinal)
        {
            ["legacy-web"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)),
            ["legacy-other"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)),
            ["legacy-web-other"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)),
        };

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            var configuration = new Dictionary<string, string?>
            {
                ["ConnectionStrings:EmployeeIdentity"] = employees.Database.GetConnectionString(),
                ["ConnectionStrings:CustomerIdentity"] = customers.Database.GetConnectionString(),
                ["ConnectionStrings:RefreshSessions"] = sessions.Database.GetConnectionString(),
                ["Jwt:Issuer"] = Issuer,
                ["Jwt:Audience"] = Audience,
                ["Jwt:PrivateKeyPem"] = signer.ExportPkcs8PrivateKeyPem(),
                ["Jwt:KeyId"] = "disposable-web-grant",
            };
            foreach (var credential in credentials)
            {
                configuration[$"ServiceClients:Clients:{credential.Key}:SecretSha256"] = ServiceClientCredential.HashSecret(credential.Value);
                // The source registry supplies currency-read; the fixture never assigns that grant.
                configuration[$"ServiceClients:Clients:{credential.Key}:Permissions:0"] = "legacy-contact.messages.create";
            }
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(configuration));
            if (issuedAt is not null)
            {
                builder.ConfigureTestServices(services =>
                {
                    services.RemoveAll<TimeProvider>();
                    services.AddSingleton<TimeProvider>(new FakeTimeProvider(issuedAt.Value));
                });
            }
        }

        public string Secret(string clientId) => credentials[clientId];

        public async Task<string> LoginAsync(HttpClient client, string clientId)
        {
            using var response = await client.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest(clientId, Secret(clientId)));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var issued = Assert.IsType<ServiceTokenResponse>(await response.Content.ReadFromJsonAsync<ServiceTokenResponse>());
            Assert.Equal("Bearer", issued.TokenType);
            Assert.InRange(issued.ExpiresIn, 300, 1800);
            var body = await response.Content.ReadAsStringAsync();
            Assert.DoesNotContain(Secret(clientId), body, StringComparison.Ordinal);
            Assert.DoesNotContain("refreshToken", body, StringComparison.OrdinalIgnoreCase);
            return issued.AccessToken;
        }

        public ClaimsPrincipal Validate(string token, string? audience = null, SecurityKey? key = null) =>
            new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = Issuer,
                ValidateAudience = true,
                ValidAudience = audience ?? Audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key ?? new RsaSecurityKey(signer),
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            }, out _);

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing) signer.Dispose();
        }

        public override async ValueTask DisposeAsync()
        {
            var pools = new List<NpgsqlConnection>
            {
                (NpgsqlConnection)employees.Database.GetDbConnection(),
                (NpgsqlConnection)customers.Database.GetDbConnection(),
                (NpgsqlConnection)sessions.Database.GetDbConnection(),
            };
            try
            {
                await using var scope = Services.CreateAsyncScope();
                var contexts = new DbContext[]
                {
                    scope.ServiceProvider.GetRequiredService<EmployeeIdentityDbContext>(),
                    scope.ServiceProvider.GetRequiredService<CustomerIdentityDbContext>(),
                    scope.ServiceProvider.GetRequiredService<RefreshSessionDbContext>(),
                };
                foreach (var context in contexts)
                {
                    pools.Add((NpgsqlConnection)context.Database.GetDbConnection());
                    await context.Database.OpenConnectionAsync();
                    await context.Database.CloseConnectionAsync();
                }
            }
            finally
            {
                try { await base.DisposeAsync(); }
                finally
                {
                    signer.Dispose();
                    foreach (var pool in pools) NpgsqlConnection.ClearPool(pool);
                }
            }
        }
    }
}
