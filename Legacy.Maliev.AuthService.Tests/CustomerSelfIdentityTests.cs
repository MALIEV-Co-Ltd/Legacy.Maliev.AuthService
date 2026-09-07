using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class CustomerSelfIdentityTests(PostgresFixture postgres)
{
    private const string Route = "/auth/v1/customer-self-service/identity";

    [Fact]
    public async Task Get_Customer_ReturnsOnlyOwnCurrentContactFieldsWithoutCaching()
    {
        await using var factory = await SelfIdentityFactory.CreateAsync(postgres);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new("Bearer", factory.Token());
        using var response = await client.GetAsync(Route + "?customerId=99&identityId=other");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(["customerId", "email", "mobile"], json.RootElement.EnumerateObject().Select(value => value.Name).Order().ToArray());
        Assert.Equal(42, json.RootElement.GetProperty("customerId").GetInt32());
        Assert.Equal("current@example.com", json.RootElement.GetProperty("email").GetString());
        Assert.Equal("+66812345678", json.RootElement.GetProperty("mobile").GetString());
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.True(response.Headers.CacheControl?.Private);
        Assert.Null(response.Headers.ETag);
        Assert.False(response.Headers.Contains("Set-Cookie"));

        var row = await factory.Customers.Users.SingleAsync(value => value.Id == "customer-42");
        row.Email = null;
        row.MobileNumber = null;
        await factory.Customers.SaveChangesAsync();
        using var refreshed = await client.GetAsync(Route);
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        using var refreshedJson = JsonDocument.Parse(await refreshed.Content.ReadAsStringAsync());
        Assert.Equal(JsonValueKind.Null, refreshedJson.RootElement.GetProperty("email").ValueKind);
        Assert.Equal(JsonValueKind.Null, refreshedJson.RootElement.GetProperty("mobile").ValueKind);
    }

    [Theory]
    [InlineData("anonymous", 401)]
    [InlineData("employee", 403)]
    [InlineData("service", 403)]
    [InlineData("missing-sub", 401)]
    [InlineData("blank-sub", 401)]
    [InlineData("duplicate-sub", 401)]
    [InlineData("missing-customer", 401)]
    [InlineData("duplicate-customer", 401)]
    [InlineData("invalid-customer", 401)]
    [InlineData("zero-customer", 401)]
    [InlineData("negative-customer", 401)]
    [InlineData("expired", 401)]
    [InlineData("wrong-signature", 401)]
    [InlineData("wrong-issuer", 401)]
    [InlineData("wrong-audience", 401)]
    public async Task Get_InvalidPrincipal_CannotReadIdentity(string scenario, int expectedStatus)
    {
        await using var factory = await SelfIdentityFactory.CreateAsync(postgres);
        using var client = factory.CreateClient();
        if (scenario != "anonymous")
        {
            client.DefaultRequestHeaders.Authorization = new("Bearer", factory.Token(scenario));
        }
        using var response = await client.GetAsync(Route);
        Assert.Equal(expectedStatus, (int)response.StatusCode);
        Assert.DoesNotContain("current@example.com", await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("deleted", 404)]
    [InlineData("relinked", 403)]
    [InlineData("unlinked", 403)]
    [InlineData("unconfirmed", 403)]
    [InlineData("locked", 403)]
    [InlineData("expired-lock", 200)]
    [InlineData("disabled-lock", 200)]
    public async Task Get_CurrentIdentityState_PreservesLinkAndEligibility(string change, int expectedStatus)
    {
        await using var factory = await SelfIdentityFactory.CreateAsync(postgres);
        var row = await factory.Customers.Users.SingleAsync(value => value.Id == "customer-42");
        switch (change)
        {
            case "deleted": factory.Customers.Users.Remove(row); break;
            case "relinked": row.DatabaseID = 99; break;
            case "unlinked": row.DatabaseID = null; break;
            case "unconfirmed": row.EmailConfirmed = false; break;
            case "locked": row.LockoutEnd = DateTimeOffset.UtcNow.AddHours(1); break;
            case "expired-lock": row.LockoutEnd = DateTimeOffset.UtcNow.AddHours(-1); break;
            case "disabled-lock": row.LockoutEnd = DateTimeOffset.UtcNow.AddHours(1); row.LockoutEnabled = false; break;
        }
        await factory.Customers.SaveChangesAsync();
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new("Bearer", factory.Token());
        using var response = await client.GetAsync(Route);
        Assert.Equal(expectedStatus, (int)response.StatusCode);
        if (expectedStatus != 200)
        {
            Assert.DoesNotContain("current@example.com", await response.Content.ReadAsStringAsync());
        }
    }

    [Fact]
    public async Task Get_CustomerToken_CannotUseEmployeeIdentityAdminEndpoint()
    {
        await using var factory = await SelfIdentityFactory.CreateAsync(postgres);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new("Bearer", factory.Token());
        using var response = await client.GetAsync("/auth/v1/customer-identities/42");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    private sealed class SelfIdentityFactory(CustomerIdentityDbContext customers) : WebApplicationFactory<Program>
    {
        private readonly RSA signingKey = RSA.Create(2048);
        public CustomerIdentityDbContext Customers { get; } = customers;

        public static async Task<SelfIdentityFactory> CreateAsync(PostgresFixture postgres)
        {
            var customers = await postgres.CreateCustomerContextAsync();
            customers.Users.AddRange(
                new LegacyIdentityRow { Id = "customer-42", DatabaseID = 42, Email = "current@example.com", NormalizedUserName = "CURRENT", MobileNumber = "+66812345678", EmailConfirmed = true, LockoutEnabled = true },
                new LegacyIdentityRow { Id = "other", DatabaseID = 99, Email = "other@example.com", NormalizedUserName = "OTHER", MobileNumber = "private-other", EmailConfirmed = true });
            await customers.SaveChangesAsync();
            return new(customers);
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:CustomerIdentity"] = Customers.Database.GetConnectionString(),
                ["ConnectionStrings:EmployeeIdentity"] = Customers.Database.GetConnectionString(),
                ["ConnectionStrings:RefreshSessions"] = Customers.Database.GetConnectionString(),
                ["Jwt:Issuer"] = "https://self-identity.test",
                ["Jwt:Audience"] = "self-identity-tests",
                ["Jwt:PrivateKeyPem"] = signingKey.ExportPkcs8PrivateKeyPem(),
                ["Jwt:KeyId"] = "self-identity-key",
                ["Jwt:AccessTokenLifetimeSeconds"] = "900",
                ["CORS:AllowedOrigins"] = "https://localhost",
            }));
        }

        public string Token(string scenario = "customer")
        {
            var claims = new List<Claim>
            {
                new("identity_kind", scenario is "employee" or "service" ? scenario : "customer"),
                new("email", "stale-token@example.com"),
            };
            if (scenario is "service" or "employee")
            {
                claims.Add(new("permissions", "legacy-auth.customer-self-service"));
                claims.Add(new("permissions", "legacy-auth.customer-identities.read"));
            }
            if (scenario != "missing-sub") claims.Add(new("sub", scenario == "blank-sub" ? " " : scenario == "service" ? "service:web" : "customer-42"));
            if (scenario == "duplicate-sub") claims.Add(new("sub", "other"));
            if (scenario != "missing-customer") claims.Add(new("legacy_database_id", scenario == "invalid-customer" ? "invalid" : scenario == "zero-customer" ? "0" : scenario == "negative-customer" ? "-1" : "42"));
            if (scenario == "duplicate-customer") claims.Add(new("legacy_database_id", "99"));
            using var wrongKey = RSA.Create(2048);
            var key = new RsaSecurityKey(scenario == "wrong-signature" ? wrongKey : signingKey) { KeyId = "self-identity-key" };
            return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
                scenario == "wrong-issuer" ? "https://wrong.test" : "https://self-identity.test",
                scenario == "wrong-audience" ? "wrong" : "self-identity-tests",
                claims,
                DateTime.UtcNow.AddHours(-2),
                scenario == "expired" ? DateTime.UtcNow.AddHours(-1) : DateTime.UtcNow.AddMinutes(5),
                new SigningCredentials(key, SecurityAlgorithms.RsaSha256)));
        }

        public override async ValueTask DisposeAsync()
        {
            await base.DisposeAsync();
            Npgsql.NpgsqlConnection.ClearPool((Npgsql.NpgsqlConnection)Customers.Database.GetDbConnection());
            await Customers.DisposeAsync();
            signingKey.Dispose();
        }
    }
}
