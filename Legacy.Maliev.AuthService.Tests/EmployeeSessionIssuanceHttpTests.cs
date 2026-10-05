using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class EmployeeSessionIssuanceHttpTests(PostgresFixture postgres)
{
    [Theory]
    [InlineData(IdentityKind.Employee, false)]
    [InlineData(IdentityKind.Employee, true)]
    [InlineData(IdentityKind.Customer, false)]
    [InlineData(IdentityKind.Customer, true)]
    public async Task NormalLoginAndRefresh_PersistedActorRole_ReachesNormalRoleAuthorization(IdentityKind kind, bool refresh)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        var tokens = await LoginAsync(client, kind);
        var original = ReadJwt(tokens.AccessToken, factory);
        if (refresh)
        {
            using var response = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(tokens.RefreshToken));
            tokens = await ReadTokensAsync(response);
        }
        var token = ReadJwt(tokens.AccessToken, factory);
        var expectedRole = kind == IdentityKind.Employee ? "Employee" : "Customer";
        var oppositeRole = kind == IdentityKind.Employee ? "Customer" : "Employee";
        await using var consumer = await CreateDefaultsConsumerAsync(factory);
        using var consumerClient = consumer.GetTestClient();
        consumerClient.DefaultRequestHeaders.Authorization = new("Bearer", tokens.AccessToken);
        using var accepted = await consumerClient.GetAsync("/" + expectedRole);
        using var refused = await consumerClient.GetAsync("/" + oppositeRole);
        Assert.Equal(HttpStatusCode.NoContent, accepted.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.Equal(expectedRole, Assert.Single(token.Claims, claim => claim.Type == ClaimTypes.Role).Value);
        Assert.Equal(expectedRole, Assert.Single(token.Claims, claim => claim.Type == "role").Value);
        Assert.Equal(kind.ToString().ToLowerInvariant(), Assert.Single(token.Claims, claim => claim.Type == "identity_kind").Value);
        Assert.Equal(original.Claims.Where(claim => claim.Type == "permissions").Select(claim => claim.Value),
            token.Claims.Where(claim => claim.Type == "permissions").Select(claim => claim.Value));
        var parameters = factory.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters;
        var principal = new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(tokens.AccessToken, parameters, out _);
        Assert.Equal(ClaimTypes.Role, Assert.IsType<ClaimsIdentity>(principal.Identity).RoleClaimType);
        await using var scope = factory.Services.CreateAsyncScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        Assert.True((await authorization.AuthorizeAsync(principal, null,
            new[] { new RolesAuthorizationRequirement([expectedRole]) })).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(principal, null,
            new[] { new RolesAuthorizationRequirement([oppositeRole]) })).Succeeded);
        var persisted = await stores.State.RefreshSessions.AsNoTracking().SingleAsync(row => row.TokenHash == Hash(tokens.RefreshToken));
        Assert.Equal(kind, persisted.IdentityKind);
        Assert.Equal(kind == IdentityKind.Employee ? "issuance-employee" : "issuance-customer", persisted.IdentityId);
        if (kind == IdentityKind.Employee)
            Assert.Equal(persisted.Id.ToString("D"), Assert.Single(token.Claims, claim => claim.Type == "sid").Value);
        else
            Assert.DoesNotContain(token.Claims, claim => claim.Type is "sid" or "permissions");
    }

    [Fact]
    public async Task NormalServiceExchange_DoesNotBecomeAnInteractiveActor()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest("issuance-test", Factory.ServiceSecret));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var token = (await response.Content.ReadFromJsonAsync<ServiceTokenResponse>())!;
        var parameters = factory.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters;
        var principal = new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(token.AccessToken, parameters, out _);
        Assert.DoesNotContain(principal.Claims, claim => claim.Type is ClaimTypes.Role or "role" or "sid");
        await using var consumer = await CreateDefaultsConsumerAsync(factory);
        using var consumerClient = consumer.GetTestClient();
        consumerClient.DefaultRequestHeaders.Authorization = new("Bearer", token.AccessToken);
        using var denied = await consumerClient.GetAsync("/Employee");
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        await using var scope = factory.Services.CreateAsyncScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        Assert.False((await authorization.AuthorizeAsync(principal, null,
            new[] { new RolesAuthorizationRequirement(["Employee", "Customer"]) })).Succeeded);
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NormalScopedIssuers_DoNotBecomeInteractiveActors(bool capability)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        await using var scope = factory.Services.CreateAsyncScope();
        var now = DateTimeOffset.UtcNow;
        var issued = capability
            ? scope.ServiceProvider.GetRequiredService<IQuotationInvoiceCapabilityTokenIssuer>()
                .IssueQuotationInvoiceCapability("issuance-employee", 1, Guid.NewGuid(), now, 60)
            : scope.ServiceProvider.GetRequiredService<IInvoiceDelegationTokenIssuer>()
                .IssueInvoiceDelegation("issuance-employee", 1, Guid.NewGuid(), now);
        var parameters = factory.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters.Clone();
        parameters.ValidAudience = capability ? QuotationInvoiceCapabilityContract.Audience : InvoiceDelegationContract.Audience;
        var principal = new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(issued.Value, parameters, out _);
        Assert.DoesNotContain(principal.Claims, claim => claim.Type is ClaimTypes.Role or "role" or "sid");
        await using var consumer = await CreateDefaultsConsumerAsync(factory, parameters.ValidAudience);
        using var consumerClient = consumer.GetTestClient();
        consumerClient.DefaultRequestHeaders.Authorization = new("Bearer", issued.Value);
        using var denied = await consumerClient.GetAsync("/Employee");
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        Assert.False((await authorization.AuthorizeAsync(principal, null,
            new[] { new RolesAuthorizationRequirement(["Employee", "Customer"]) })).Succeeded);
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    private static async Task<WebApplication> CreateDefaultsConsumerAsync(Factory factory, string audience = "issuance-test")
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Production" });
        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Jwt:Issuer"] = "https://issuance.test",
            ["Jwt:Audience"] = audience,
            ["Jwt:PublicKey"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(factory.PublicKey)),
        });
        builder.AddJwtAuthentication();
        builder.Services.AddAuthorization();
        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/Employee", () => Results.NoContent()).RequireAuthorization(policy => policy.RequireRole("Employee"));
        app.MapGet("/Customer", () => Results.NoContent()).RequireAuthorization(policy => policy.RequireRole("Customer"));
        await app.StartAsync();
        return app;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EmployeePasswordAndRefresh_BindExactPersistedRow(bool refresh)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        var tokens = await LoginAsync(client, IdentityKind.Employee);
        var original = await stores.State.RefreshSessions.AsNoTracking().SingleAsync();
        if (refresh)
        {
            using var response = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(tokens.RefreshToken));
            tokens = await ReadTokensAsync(response);
        }
        var jwt = ReadJwt(tokens.AccessToken, factory);
        var sid = Assert.Single(jwt.Claims, claim => claim.Type == "sid").Value;
        Assert.True(Guid.TryParseExact(sid, "D", out var id));
        Assert.NotEqual(Guid.Empty, id);
        Assert.Equal(id.ToString("D"), sid);
        var exact = await AssertStoredBindingAsync(tokens, stores, id, factory);
        if (refresh)
        {
            Assert.NotEqual(original.Id, exact.Id);
            var rotated = await stores.State.RefreshSessions.AsNoTracking().SingleAsync(row => row.Id == original.Id);
            Assert.NotNull(rotated.RotatedAt);
            Assert.Equal(exact.Id, rotated.ReplacedById);
            Assert.Equal(rotated.FamilyId, exact.FamilyId);
            Assert.Equal(2, await stores.State.RefreshSessions.CountAsync());
        }
        else Assert.Equal(original.Id, exact.Id);
        Assert.Contains(jwt.Claims, claim => claim.Type == "permissions" && claim.Value == "legacy.quotation-requests.read");
        Assert.Contains(jwt.Claims, claim => claim.Type == "permissions" && claim.Value == "legacy.quotation-requests.update");
    }

    [Fact]
    public async Task EmployeeGoogleExchange_BindsExactPersistedRow()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var scope = factory.Services.CreateScope();
        var nonce = await scope.ServiceProvider.GetRequiredService<IGoogleIdentityNonceService>()
            .IssueAsync("legacy-intranet", "intranet", default);
        var result = await scope.ServiceProvider.GetRequiredService<GoogleAuthenticationService>()
            .ExchangeAsync(new GoogleExchangeRequest(new string('g', 128), "intranet", nonce.Nonce), "legacy-intranet", default);
        Assert.True(result.Succeeded);
        var tokens = Assert.IsType<TokenResponse>(result.Tokens);
        var sid = Assert.Single(ReadJwt(tokens.AccessToken, factory).Claims, claim => claim.Type == "sid").Value;
        Assert.True(Guid.TryParseExact(sid, "D", out var id));
        Assert.NotEqual(Guid.Empty, id);
        Assert.Equal(id.ToString("D"), sid);
        await AssertStoredBindingAsync(tokens, stores, id, factory);
        Assert.Equal(1, await stores.State.RefreshSessions.CountAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CustomerPasswordAndRefresh_PreserveEnvelopeAndNoEmployeeSidOrGrants(bool refresh)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        var tokens = await LoginAsync(client, IdentityKind.Customer);
        if (refresh)
        {
            using var response = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(tokens.RefreshToken));
            tokens = await ReadTokensAsync(response);
        }
        var jwt = ReadJwt(tokens.AccessToken, factory);
        Assert.Equal("issuance-customer", Assert.Single(jwt.Claims, claim => claim.Type == "sub").Value);
        Assert.Equal("customer", Assert.Single(jwt.Claims, claim => claim.Type == "identity_kind").Value);
        Assert.DoesNotContain(jwt.Claims, claim => claim.Type == "sid");
        Assert.DoesNotContain(jwt.Claims, claim => claim.Type == "permissions");
        var exact = await stores.State.RefreshSessions.AsNoTracking().SingleAsync(row => row.TokenHash == Hash(tokens.RefreshToken));
        Assert.Equal(IdentityKind.Customer, exact.IdentityKind);
        Assert.Equal("issuance-customer", exact.IdentityId);
    }

    [Fact]
    public async Task ServiceCredentialExchange_PreservesEnvelopeAndExactConfiguredGrants_NoEmployeeSid()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest("issuance-test", Factory.ServiceSecret));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(["accessToken", "expiresIn", "tokenType"], json.EnumerateObject().Select(property => property.Name).Order().ToArray());
        var tokens = Assert.IsType<ServiceTokenResponse>(json.Deserialize<ServiceTokenResponse>(new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        Assert.Equal("Bearer", tokens.TokenType);
        Assert.Equal(900, tokens.ExpiresIn);
        var jwt = ReadJwt(tokens.AccessToken, factory);
        Assert.Equal("service:issuance-test", Assert.Single(jwt.Claims, claim => claim.Type == "sub").Value);
        Assert.Equal("service", Assert.Single(jwt.Claims, claim => claim.Type == "identity_kind").Value);
        Assert.DoesNotContain(jwt.Claims, claim => claim.Type == "sid");
        Assert.Equal(["legacy-contact.messages.create"], jwt.Claims.Where(claim => claim.Type == "permissions").Select(claim => claim.Value).ToArray());
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EmployeePasswordOrRefresh_SaveFailure_ReturnsNoAccessResponseOrNewSession(bool refresh)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var fault = new RejectSave();
        await using var factory = new Factory(stores, fault);
        using var client = factory.CreateClient();
        TokenResponse? original = refresh ? await LoginAsync(client, IdentityKind.Employee) : null;
        fault.Enabled = true;
        using var response = refresh
            ? await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(original!.RefreshToken))
            : await client.PostAsJsonAsync("/auth/v1/login", Login(IdentityKind.Employee));
        Assert.True(fault.Injected);
        Assert.False(response.IsSuccessStatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("accessToken", body, StringComparison.Ordinal);
        Assert.DoesNotContain("refreshToken", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Synthetic", body, StringComparison.Ordinal);
        var rows = await stores.State.RefreshSessions.AsNoTracking().ToListAsync();
        if (refresh)
        {
            var row = Assert.Single(rows);
            Assert.Equal(Hash(original!.RefreshToken), row.TokenHash);
            Assert.Null(row.RotatedAt);
            Assert.Null(row.ReplacedById);
            Assert.Null(row.RevokedAt);
        }
        else Assert.Empty(rows);
    }

    [Fact]
    public async Task EmployeeGoogleExchange_SaveFailure_ReturnsNoIssuedResultOrSession()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var fault = new RejectSave();
        await using var factory = new Factory(stores, fault);
        using var scope = factory.Services.CreateScope();
        var nonce = await scope.ServiceProvider.GetRequiredService<IGoogleIdentityNonceService>()
            .IssueAsync("legacy-intranet", "intranet", default);
        fault.Enabled = true;
        await Assert.ThrowsAsync<DbUpdateException>(() => scope.ServiceProvider.GetRequiredService<GoogleAuthenticationService>()
            .ExchangeAsync(new GoogleExchangeRequest(new string('g', 128), "intranet", nonce.Nonce), "legacy-intranet", default));
        Assert.True(fault.Injected);
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    private static LoginRequest Login(IdentityKind kind) => new(kind == IdentityKind.Employee ? "issuance@example.com" : "customer@example.com", "issuance-password", kind);
    private static async Task<TokenResponse> LoginAsync(HttpClient client, IdentityKind kind)
    {
        using var response = await client.PostAsJsonAsync("/auth/v1/login", Login(kind));
        return await ReadTokensAsync(response);
    }
    private static async Task<TokenResponse> ReadTokensAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(["accessToken", "expiresIn", "refreshExpiresAt", "refreshToken", "tokenType"], json.EnumerateObject().Select(property => property.Name).Order().ToArray());
        var tokens = Assert.IsType<TokenResponse>(json.Deserialize<TokenResponse>(new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        Assert.Equal("Bearer", tokens.TokenType);
        Assert.Equal(900, tokens.ExpiresIn);
        return tokens;
    }
    private static JwtSecurityToken ReadJwt(string token, Factory factory)
    {
        var parameters = factory.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters;
        new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(token, parameters, out var validated);
        var jwt = Assert.IsType<JwtSecurityToken>(validated);
        Assert.Equal("RS256", jwt.Header.Alg);
        Assert.Equal("https://issuance.test", jwt.Issuer);
        Assert.Equal("issuance-test", Assert.Single(jwt.Audiences));
        return jwt;
    }
    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value)));
    private static async Task<RefreshSession> AssertStoredBindingAsync(TokenResponse tokens, Stores stores, Guid id, Factory factory)
    {
        var row = await stores.State.RefreshSessions.AsNoTracking().SingleAsync(session => session.Id == id);
        Assert.Equal("issuance-employee", row.IdentityId);
        Assert.Equal(IdentityKind.Employee, row.IdentityKind);
        Assert.Equal("issuance-stamp", row.SecurityStamp);
        Assert.Null(row.RevokedAt);
        Assert.Equal(Hash(tokens.RefreshToken), row.TokenHash);
        Assert.Equal("issuance-employee", Assert.Single(ReadJwt(tokens.AccessToken, factory).Claims, claim => claim.Type == "sub").Value);
        Assert.Equal("employee", Assert.Single(ReadJwt(tokens.AccessToken, factory).Claims, claim => claim.Type == "identity_kind").Value);
        return row;
    }

    private sealed class RejectSave : SaveChangesInterceptor
    {
        public bool Enabled { get; set; }
        public bool Injected { get; private set; }
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (Enabled && eventData.Context!.ChangeTracker.Entries<RefreshSession>().Any(entry => entry.State == EntityState.Added))
            {
                Injected = true;
                throw new DbUpdateException("Synthetic session persistence failure");
            }
            return ValueTask.FromResult(result);
        }
    }

    private sealed class Factory(Stores stores, RejectSave? fault = null) : WebApplicationFactory<Program>
    {
        public const string ServiceSecret = "issuance-test-only-secret-0123456789";
        private readonly RSA signing = RSA.Create(2048);
        public string PublicKey => signing.ExportSubjectPublicKeyInfoPem();
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:EmployeeIdentity"] = stores.Employees.Database.GetConnectionString(),
                ["ConnectionStrings:CustomerIdentity"] = stores.Customers.Database.GetConnectionString(),
                ["ConnectionStrings:RefreshSessions"] = stores.State.Database.GetConnectionString(),
                ["Jwt:Issuer"] = "https://issuance.test",
                ["Jwt:Audience"] = "issuance-test",
                ["Jwt:PrivateKeyPem"] = signing.ExportPkcs8PrivateKeyPem(),
                ["Jwt:KeyId"] = "issuance-test",
                ["Jwt:AccessTokenLifetimeSeconds"] = "900",
                ["ServiceClients:Clients:issuance-test:SecretSha256"] = ServiceClientCredential.HashSecret(ServiceSecret),
                ["ServiceClients:Clients:issuance-test:Permissions:0"] = "legacy-contact.messages.create",
            }));
            builder.ConfigureTestServices(services =>
            {
                // Only Google's external credential validation is controlled. The
                // actual nonce, reader, issuer, session store and runtime DI remain.
                services.RemoveAll<IGoogleIdentityTokenValidator>();
                services.AddSingleton<IGoogleIdentityTokenValidator, GoogleValidator>();
                if (fault is not null) services.AddDbContext<RefreshSessionDbContext>(options => options.AddInterceptors(fault));
            });
        }
        public override async ValueTask DisposeAsync()
        {
            var connections = new List<NpgsqlConnection>();
            await using (var scope = Services.CreateAsyncScope())
            {
                var contexts = new DbContext[]
                {
                    scope.ServiceProvider.GetRequiredService<EmployeeIdentityDbContext>(),
                    scope.ServiceProvider.GetRequiredService<CustomerIdentityDbContext>(),
                    scope.ServiceProvider.GetRequiredService<RefreshSessionDbContext>(),
                };
                foreach (var context in contexts)
                {
                    await context.Database.OpenConnectionAsync();
                    connections.Add((NpgsqlConnection)context.Database.GetDbConnection());
                    await context.Database.CloseConnectionAsync();
                }
            }
            await base.DisposeAsync();
            signing.Dispose();
            foreach (var connection in connections) NpgsqlConnection.ClearPool(connection);
        }
    }
    private sealed class GoogleValidator : IGoogleIdentityTokenValidator
    {
        public Task<GoogleIdentityValidationResult> ValidateAsync(string credential, string application, string expectedNonce, CancellationToken cancellationToken) =>
            Task.FromResult(new GoogleIdentityValidationResult(true, new VerifiedGoogleIdentity("controlled-sub", "issuance@example.com", true, "example.com", null, null), null, null));
    }
    private sealed class Stores(EmployeeIdentityDbContext employees, CustomerIdentityDbContext customers, RefreshSessionDbContext state) : IAsyncDisposable
    {
        public EmployeeIdentityDbContext Employees { get; } = employees;
        public CustomerIdentityDbContext Customers { get; } = customers;
        public RefreshSessionDbContext State { get; } = state;
        public static async Task<Stores> CreateAsync(PostgresFixture postgres)
        {
            var stores = new Stores(await postgres.CreateEmployeeContextAsync(), await postgres.CreateCustomerContextAsync(), await postgres.CreateStateContextAsync());
            var employee = Identity("issuance-employee", "issuance@example.com");
            var customer = Identity("issuance-customer", "customer@example.com");
            stores.Employees.Users.Add(employee);
            stores.Customers.Users.Add(customer);
            await stores.Employees.SaveChangesAsync();
            await stores.Customers.SaveChangesAsync();
            return stores;
        }
        private static LegacyIdentityRow Identity(string id, string email)
        {
            var row = new LegacyIdentityRow
            {
                Id = id,
                UserName = email,
                NormalizedUserName = email.ToUpperInvariant(),
                Email = email,
                NormalizedEmail = email.ToUpperInvariant(),
                EmailConfirmed = true,
                SecurityStamp = "issuance-stamp",
                ConcurrencyStamp = "issuance-concurrency",
                LockoutEnabled = true,
            };
            row.PasswordHash = new Microsoft.AspNetCore.Identity.PasswordHasher<LegacyIdentityRow>().HashPassword(row, "issuance-password");
            return row;
        }
        public async ValueTask DisposeAsync()
        {
            var connections = new[] { (NpgsqlConnection)Employees.Database.GetDbConnection(), (NpgsqlConnection)Customers.Database.GetDbConnection(), (NpgsqlConnection)State.Database.GetDbConnection() };
            await Employees.DisposeAsync();
            await Customers.DisposeAsync();
            await State.DisposeAsync();
            foreach (var connection in connections) NpgsqlConnection.ClearPool(connection);
        }
    }
}
