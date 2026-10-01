using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using Legacy.Maliev.AuthService.Api.Authorization;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class CustomerEmailGenerationHttpTests(PostgresFixture postgres)
{
    private const string Root = "/auth/v1/customer-self-service/";

    [Theory]
    [InlineData(false, "ceg1:cd938242f1e209103761a5aaf6149f443701c7f6aa8a2da1016560e7f249c698")]
    [InlineData(true, "ceg1:00300dbecb4a5eec896baa90934339318c559fa15e4ce542e582be640a8f229e")]
    public async Task Issuance_PersistsLiteralTypedGenerationBinding_AndCompletes(bool changeEmail, string expectedBinding)
    {
        await using var stores = await Stores.CreateAsync(postgres, changeEmail);
        await using var factory = new Factory(stores);
        using var owner = factory.Client();
        var token = await IssueAsync(factory, owner, changeEmail);
        var action = await stores.State.IdentityActionTokens.AsNoTracking().SingleAsync();
        Assert.Equal(expectedBinding, action.BoundSecurityStamp);
        Assert.Equal(69, action.BoundSecurityStamp!.Length);
        Assert.Null(action.RecoveryVersion);
        using var response = await owner.PostAsJsonAsync(Root + (changeEmail ? "email-change/complete" : "email-confirmation/complete"),
            new CompleteCustomerActionRequest(changeEmail ? "new@example.com" : "customer@example.com", token));
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.NotNull((await stores.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
    }

    [Theory]
    [InlineData(false, "malformed")]
    [InlineData(true, "malformed")]
    [InlineData(false, "unknown-version")]
    [InlineData(true, "unknown-version")]
    [InlineData(false, "uppercase")]
    [InlineData(true, "uppercase")]
    public async Task PersistedBinding_InvalidCanonicalFormat_IsRejectedWithoutConsumption(bool changeEmail, string invalid)
    {
        await using var stores = await Stores.CreateAsync(postgres, changeEmail);
        await using var factory = new Factory(stores);
        using var owner = factory.Client();
        var token = await IssueAsync(factory, owner, changeEmail);
        var digest = changeEmail
            ? "00300dbecb4a5eec896baa90934339318c559fa15e4ce542e582be640a8f229e"
            : "cd938242f1e209103761a5aaf6149f443701c7f6aa8a2da1016560e7f249c698";
        var binding = invalid switch
        {
            "unknown-version" => "ceg2:" + digest,
            "uppercase" => "ceg1:" + digest.ToUpperInvariant(),
            _ => "ceg1:" + new string('z', 64),
        };
        await stores.State.IdentityActionTokens.ExecuteUpdateAsync(setters => setters.SetProperty(row => row.BoundSecurityStamp, binding));
        using var response = await owner.PostAsJsonAsync(Root + (changeEmail ? "email-change/complete" : "email-confirmation/complete"),
            new CompleteCustomerActionRequest(changeEmail ? "new@example.com" : "customer@example.com", token));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null((await stores.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
        var identity = await stores.Customers.Users.AsNoTracking().SingleAsync();
        Assert.Equal("original-generation", identity.SecurityStamp);
        Assert.Equal("customer@example.com", identity.Email);
        Assert.Equal(changeEmail, identity.EmailConfirmed);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task PendingEmailLink_AfterSecurityRotationAndHostRestart_IsRejectedWithoutConsumption(bool changeEmail, bool passwordChange)
    {
        await using var stores = await Stores.CreateAsync(postgres, changeEmail);
        string token;
        await using (var first = new Factory(stores))
        using (var client = first.Client())
        {
            token = await IssueAsync(first, client, changeEmail);
            if (passwordChange)
            {
                using var customer = first.Client("customer");
                using var changed = await customer.PostAsJsonAsync(Root + "password/change", new ChangeCustomerPasswordRequest("original-password", "replacement-password"));
                Assert.Equal(HttpStatusCode.NoContent, changed.StatusCode);
            }
            else
            {
                await stores.Customers.Users.Where(row => row.Id == "email-generation-customer")
                    .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.SecurityStamp, "administrator-rotated-generation"));
            }
        }

        await using var restarted = new Factory(stores);
        using var owner = restarted.Client();
        using var result = await owner.PostAsJsonAsync(Root + (changeEmail ? "email-change/complete" : "email-confirmation/complete"),
            new CompleteCustomerActionRequest(changeEmail ? "new@example.com" : "customer@example.com", token));
        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        Assert.Null((await stores.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
        var current = await stores.Customers.Users.AsNoTracking().SingleAsync();
        Assert.Equal("customer@example.com", current.Email);
        Assert.Equal(changeEmail, current.EmailConfirmed);
        Assert.DoesNotContain(token, await result.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EmailChangeValidation_AfterSecurityRotation_DoesNotAuthorizeProfileMutation(bool passwordChange)
    {
        await using var stores = await Stores.CreateAsync(postgres, confirmed: true);
        await using var factory = new Factory(stores);
        using var service = factory.Client();
        var token = await IssueAsync(factory, service, changeEmail: true);
        if (passwordChange)
        {
            using var customer = factory.Client("customer");
            using var changed = await customer.PostAsJsonAsync(Root + "password/change", new ChangeCustomerPasswordRequest("original-password", "replacement-password"));
            Assert.Equal(HttpStatusCode.NoContent, changed.StatusCode);
        }
        else await stores.Customers.Users.ExecuteUpdateAsync(setters => setters.SetProperty(row => row.SecurityStamp, "new-generation"));
        using var result = await service.PostAsJsonAsync(Root + "email-change/validate", new CompleteCustomerActionRequest("new@example.com", token));
        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        Assert.Null((await stores.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
        Assert.Equal("customer@example.com", (await stores.Customers.Users.AsNoTracking().SingleAsync()).Email);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SameGeneration_HostRestart_CompletesOnce_AndKeepsHistoricalCompletedProjection(bool changeEmail)
    {
        await using var stores = await Stores.CreateAsync(postgres, changeEmail);
        string token;
        await using (var first = new Factory(stores))
        using (var service = first.Client()) token = await IssueAsync(first, service, changeEmail);
        await using var restarted = new Factory(stores);
        using var owner = restarted.Client();
        var request = new CompleteCustomerActionRequest(changeEmail ? "new@example.com" : "customer@example.com", token);
        if (changeEmail)
        {
            using var pending = await owner.PostAsJsonAsync(Root + "email-change/validate", request);
            Assert.Equal(HttpStatusCode.OK, pending.StatusCode);
            Assert.False((await pending.Content.ReadFromJsonAsync<CustomerEmailChangeValidation>())!.Completed);
        }
        var route = Root + (changeEmail ? "email-change/complete" : "email-confirmation/complete");
        using var completed = await owner.PostAsJsonAsync(route, request);
        Assert.Equal(HttpStatusCode.NoContent, completed.StatusCode);
        using var replay = await owner.PostAsJsonAsync(route, request);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.NotNull((await stores.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
        var row = await stores.Customers.Users.AsNoTracking().SingleAsync();
        Assert.True(row.EmailConfirmed);
        Assert.Equal(request.Email, row.Email);
        if (changeEmail)
        {
            using var historical = await owner.PostAsJsonAsync(Root + "email-change/validate", request);
            Assert.Equal(HttpStatusCode.OK, historical.StatusCode);
            Assert.True((await historical.Content.ReadFromJsonAsync<CustomerEmailChangeValidation>())!.Completed);
        }
    }

    [Theory]
    [InlineData(false, "expired")]
    [InlineData(true, "expired")]
    [InlineData(false, "email")]
    [InlineData(true, "email")]
    [InlineData(false, "purpose")]
    [InlineData(true, "purpose")]
    public async Task InvalidLink_PreservesIdentityAndUnconsumedChallenge(bool changeEmail, string invalid)
    {
        await using var stores = await Stores.CreateAsync(postgres, changeEmail);
        await using var factory = new Factory(stores);
        using var owner = factory.Client();
        var token = await IssueAsync(factory, owner, changeEmail);
        if (invalid == "expired") stores.Clock.Advance(TimeSpan.FromHours(25));
        var route = invalid == "purpose"
            ? (changeEmail ? "email-confirmation/complete" : "email-change/complete")
            : (changeEmail ? "email-change/complete" : "email-confirmation/complete");
        using var result = await owner.PostAsJsonAsync(Root + route, new CompleteCustomerActionRequest(
            invalid == "email" ? "other@example.com" : changeEmail ? "new@example.com" : "customer@example.com", token));
        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        Assert.Null((await stores.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
        var row = await stores.Customers.Users.AsNoTracking().SingleAsync();
        Assert.Equal("original-generation", row.SecurityStamp);
        Assert.Equal("customer@example.com", row.Email);
        Assert.Equal(changeEmail, row.EmailConfirmed);
    }

    [Fact]
    public async Task ConfirmationRequest_UnknownAndKnown_BothAccepted_OnlyKnownInternalBffGetsToken()
    {
        await using var stores = await Stores.CreateAsync(postgres, confirmed: false);
        await using var factory = new Factory(stores);
        using var owner = factory.Client();
        using var missing = await owner.PostAsJsonAsync(Root + "email-confirmation/request", new CustomerActionRequest("missing@example.com"));
        using var known = await owner.PostAsJsonAsync(Root + "email-confirmation/request", new CustomerActionRequest("customer@example.com"));
        Assert.Equal(HttpStatusCode.OK, missing.StatusCode);
        Assert.Equal(HttpStatusCode.OK, known.StatusCode);
        var unknown = (await missing.Content.ReadFromJsonAsync<CustomerActionChallenge>())!;
        Assert.True(unknown.Accepted);
        Assert.Null(unknown.Token);
        Assert.True((await known.Content.ReadFromJsonAsync<CustomerActionChallenge>())!.Accepted);
        Assert.Single(await stores.State.IdentityActionTokens.ToListAsync());
    }

    [Theory]
    [InlineData("anonymous", HttpStatusCode.Unauthorized)]
    [InlineData("no-permission", HttpStatusCode.Forbidden)]
    [InlineData("bad-signature", HttpStatusCode.Unauthorized)]
    public async Task ConfirmationRequest_NormalJwtAdmissionRejectsInvalidCallerWithoutState(string caller, HttpStatusCode expected)
    {
        await using var stores = await Stores.CreateAsync(postgres, confirmed: false);
        await using var factory = new Factory(stores);
        using var client = factory.Client(caller);
        using var response = await client.PostAsJsonAsync(Root + "email-confirmation/request", new CustomerActionRequest("customer@example.com"));
        Assert.Equal(expected, response.StatusCode);
        Assert.Empty(await stores.State.IdentityActionTokens.ToListAsync());
        Assert.Equal("original-generation", (await stores.Customers.Users.AsNoTracking().SingleAsync()).SecurityStamp);
    }

    private static async Task<string> IssueAsync(Factory factory, HttpClient service, bool changeEmail)
    {
        using var customer = changeEmail ? factory.Client("customer") : null;
        using var response = changeEmail
            ? await customer!.PostAsJsonAsync(Root + "email/change", new ChangeCustomerEmailRequest("original-password", "new@example.com"))
            : await service.PostAsJsonAsync(Root + "email-confirmation/request", new CustomerActionRequest("customer@example.com"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var challenge = Assert.IsType<CustomerActionChallenge>(await response.Content.ReadFromJsonAsync<CustomerActionChallenge>());
        Assert.True(challenge.Accepted);
        return Assert.IsType<string>(challenge.Token);
    }

    [Theory]
    [InlineData(false, null)]
    [InlineData(false, "")]
    [InlineData(true, null)]
    [InlineData(true, "")]
    public async Task LegacyNullOrBlankStamp_SameGeneration_RemainsUsableAcrossRestart(bool changeEmail, string? stamp)
    {
        await using var stores = await Stores.CreateAsync(postgres, changeEmail);
        await stores.Customers.Users.ExecuteUpdateAsync(setters => setters.SetProperty(row => row.SecurityStamp, stamp));
        string token;
        await using (var first = new Factory(stores))
        using (var owner = first.Client()) token = await IssueAsync(first, owner, changeEmail);
        Assert.Equal(stamp, (await stores.Customers.Users.AsNoTracking().SingleAsync()).SecurityStamp);
        await using var restarted = new Factory(stores);
        using var service = restarted.Client();
        using var response = await service.PostAsJsonAsync(Root + (changeEmail ? "email-change/complete" : "email-confirmation/complete"),
            new CompleteCustomerActionRequest(changeEmail ? "new@example.com" : "customer@example.com", token));
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.NotNull((await stores.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
        Assert.False(string.IsNullOrWhiteSpace((await stores.Customers.Users.AsNoTracking().SingleAsync()).SecurityStamp));
    }

    [Theory]
    [InlineData(false, "unbound")]
    [InlineData(true, "unbound")]
    [InlineData(false, "null-to-empty")]
    [InlineData(true, "null-to-empty")]
    [InlineData(true, "email-only")]
    public async Task PendingBinding_HistoricalOrChangedTypedGeneration_IsRejected(bool changeEmail, string mutation)
    {
        await using var stores = await Stores.CreateAsync(postgres, changeEmail);
        if (mutation == "null-to-empty") await stores.Customers.Users.ExecuteUpdateAsync(setters => setters.SetProperty(row => row.SecurityStamp, (string?)null));
        await using var factory = new Factory(stores);
        using var owner = factory.Client();
        var token = await IssueAsync(factory, owner, changeEmail);
        if (mutation == "unbound")
            await stores.State.IdentityActionTokens.ExecuteUpdateAsync(setters => setters.SetProperty(row => row.BoundSecurityStamp, (string?)null));
        else if (mutation == "null-to-empty")
            await stores.Customers.Users.ExecuteUpdateAsync(setters => setters.SetProperty(row => row.SecurityStamp, ""));
        else
            await stores.Customers.Users.ExecuteUpdateAsync(setters => setters.SetProperty(row => row.Email, "administrator@example.com").SetProperty(row => row.NormalizedEmail, "ADMINISTRATOR@EXAMPLE.COM"));
        using var response = await owner.PostAsJsonAsync(Root + (changeEmail ? "email-change/complete" : "email-confirmation/complete"),
            new CompleteCustomerActionRequest(changeEmail ? "new@example.com" : "customer@example.com", token));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null((await stores.State.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OperatorReissue_AfterRotation_SupersedesOldLinkAndCompletesCurrentGeneration(bool changeEmail)
    {
        await using var stores = await Stores.CreateAsync(postgres, changeEmail);
        await using var factory = new Factory(stores);
        using var owner = factory.Client();
        var old = await IssueAsync(factory, owner, changeEmail);
        await stores.Customers.Users.ExecuteUpdateAsync(setters => setters.SetProperty(row => row.SecurityStamp, "reissued-generation"));
        var fresh = await IssueAsync(factory, owner, changeEmail);
        Assert.NotEqual(old, fresh);
        var route = Root + (changeEmail ? "email-change/complete" : "email-confirmation/complete");
        using var rejected = await owner.PostAsJsonAsync(route, new CompleteCustomerActionRequest(changeEmail ? "new@example.com" : "customer@example.com", old));
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        using var completed = await owner.PostAsJsonAsync(route, new CompleteCustomerActionRequest(changeEmail ? "new@example.com" : "customer@example.com", fresh));
        Assert.Equal(HttpStatusCode.NoContent, completed.StatusCode);
        Assert.Equal(2, await stores.State.IdentityActionTokens.CountAsync());
    }

    private sealed class Factory(Stores stores) : WebApplicationFactory<Program>
    {
        private readonly RSA signing = RSA.Create(2048);
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:CustomerIdentity"] = stores.Customers.Database.GetConnectionString(),
                ["ConnectionStrings:EmployeeIdentity"] = stores.Employees.Database.GetConnectionString(),
                ["ConnectionStrings:RefreshSessions"] = stores.State.Database.GetConnectionString(),
                ["Jwt:Issuer"] = "https://email-generation.test",
                ["Jwt:Audience"] = "email-generation-test",
                ["Jwt:PrivateKeyPem"] = signing.ExportPkcs8PrivateKeyPem(),
                ["Jwt:KeyId"] = "email-generation-test",
            }));
            builder.ConfigureTestServices(services => services.Replace(ServiceDescriptor.Singleton<TimeProvider>(stores.Clock)));
        }
        public HttpClient Client(string caller = "owner")
        {
            var client = CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
            if (caller == "anonymous") return client;
            using var other = caller == "bad-signature" ? RSA.Create(2048) : null;
            var claims = new List<Claim> { new("sub", caller == "customer" ? "email-generation-customer" : "service:legacy-web"), new("identity_kind", caller == "customer" ? "customer" : "service") };
            if (caller != "no-permission") claims.Add(new("permissions", CustomerSelfServicePermissions.Use));
            var jwt = new JwtSecurityToken("https://email-generation.test", "email-generation-test", claims,
                DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(10), new SigningCredentials(new RsaSecurityKey(other ?? signing) { KeyId = "email-generation-test" }, SecurityAlgorithms.RsaSha256));
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", new JwtSecurityTokenHandler().WriteToken(jwt));
            return client;
        }
        public override async ValueTask DisposeAsync()
        {
            var connections = new List<NpgsqlConnection>();
            await using (var scope = Services.CreateAsyncScope())
            {
                var contexts = new DbContext[]
                {
                    scope.ServiceProvider.GetRequiredService<CustomerIdentityDbContext>(),
                    scope.ServiceProvider.GetRequiredService<EmployeeIdentityDbContext>(),
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

    private sealed class Stores(CustomerIdentityDbContext customers, EmployeeIdentityDbContext employees, RefreshSessionDbContext state) : IAsyncDisposable
    {
        public CustomerIdentityDbContext Customers { get; } = customers;
        public EmployeeIdentityDbContext Employees { get; } = employees;
        public RefreshSessionDbContext State { get; } = state;
        public FakeTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow);
        public static async Task<Stores> CreateAsync(PostgresFixture postgres, bool confirmed)
        {
            var stores = new Stores(await postgres.CreateCustomerContextAsync(), await postgres.CreateEmployeeContextAsync(), await postgres.CreateStateContextAsync());
            var row = new LegacyIdentityRow { Id = "email-generation-customer", DatabaseID = 42, UserName = "customer@example.com", NormalizedUserName = "CUSTOMER@EXAMPLE.COM", Email = "customer@example.com", NormalizedEmail = "CUSTOMER@EXAMPLE.COM", EmailConfirmed = confirmed, SecurityStamp = "original-generation", ConcurrencyStamp = Guid.NewGuid().ToString() };
            row.PasswordHash = new PasswordHasher<LegacyIdentityRow>().HashPassword(row, "original-password");
            stores.Customers.Users.Add(row);
            await stores.Customers.SaveChangesAsync();
            return stores;
        }
        public async ValueTask DisposeAsync()
        {
            var connections = new[] { Customers.Database.GetDbConnection(), Employees.Database.GetDbConnection(), State.Database.GetDbConnection() };
            await Customers.DisposeAsync();
            await Employees.DisposeAsync();
            await State.DisposeAsync();
            foreach (var connection in connections) NpgsqlConnection.ClearPool((NpgsqlConnection)connection);
        }
    }
}
