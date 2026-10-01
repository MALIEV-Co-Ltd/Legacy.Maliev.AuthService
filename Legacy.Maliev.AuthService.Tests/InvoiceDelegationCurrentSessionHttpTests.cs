using System.Data.Common;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>Normal signed HTTP exchange with current, disposable PostgreSQL authority.</summary>
[Collection(PostgresCollection.Name)]
public sealed class InvoiceDelegationCurrentSessionHttpTests(PostgresFixture postgres)
{
    private static readonly Guid Operation = Guid.Parse("7a630e38-9dd6-4f31-b790-98679e056415");

    [Fact]
    public async Task ActiveNormalLoginLineage_IssuesUnchangedAccountingOnlyDelegation()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateClient();
        var employee = await LoginAsync(client);
        var caller = await CallerAsync(client);
        var normal = new JwtSecurityTokenHandler().ReadJwtToken(employee.AccessToken);
        var session = await stores.State.RefreshSessions.AsNoTracking().SingleAsync();
        Assert.Equal(session.Id.ToString("D"), Assert.Single(normal.Claims, x => x.Type == "sid").Value);
        using var response = await SendAsync(client, caller, employee.AccessToken);
        await AssertIssuedAsync(response, app);
        Assert.Equal(1, await stores.State.RefreshSessions.CountAsync());
        Assert.Null((await stores.State.RefreshSessions.AsNoTracking().SingleAsync()).RevokedAt);
    }

    [Theory]
    [InlineData("revoked")]
    [InlineData("expired")]
    [InlineData("kind")]
    [InlineData("owner")]
    [InlineData("stamp")]
    [InlineData("empty-stamp")]
    [InlineData("unconfirmed")]
    [InlineData("locked")]
    [InlineData("deleted")]
    [InlineData("missing-session")]
    [InlineData("family-revoked")]
    public async Task CurrentAuthorityChangedAfterSuccessfulExchange_NoNewDelegation(string mutation)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateClient();
        var employee = await LoginAsync(client);
        var caller = await CallerAsync(client);
        using (var before = await SendAsync(client, caller, employee.AccessToken)) await AssertIssuedAsync(before, app);
        var session = await stores.State.RefreshSessions.SingleAsync();
        var identity = await stores.Employees.Users.SingleAsync();
        switch (mutation)
        {
            case "revoked": session.RevokedAt = DateTimeOffset.UtcNow; break;
            case "expired": session.ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1); break;
            case "kind": session.IdentityKind = IdentityKind.Customer; break;
            case "owner": session.IdentityId = "another-employee"; break;
            case "stamp": identity.SecurityStamp = "rotated-stamp"; break;
            case "empty-stamp": session.SecurityStamp = ""; break;
            case "unconfirmed": identity.EmailConfirmed = false; break;
            case "locked": identity.LockoutEnd = DateTimeOffset.UtcNow.AddHours(1); break;
            case "deleted": stores.Employees.Users.Remove(identity); break;
            case "missing-session": stores.State.RefreshSessions.Remove(session); break;
            case "family-revoked": stores.State.RefreshSessions.Add(Session(session.FamilyId, "B", revoked: true)); break;
        }
        await stores.Employees.SaveChangesAsync();
        await stores.State.SaveChangesAsync();
        // A different valid family must never rescue the signed exact sid.
        stores.State.RefreshSessions.Add(Session(Guid.NewGuid(), "C"));
        await stores.State.SaveChangesAsync();
        var count = await stores.State.RefreshSessions.CountAsync();
        using var after = await SendAsync(client, caller, employee.AccessToken);
        await AssertDeniedAsync(after, employee.AccessToken);
        Assert.Equal(count, await stores.State.RefreshSessions.CountAsync());
    }

    [Theory]
    [InlineData("missing-sid")]
    [InlineData("wrong-sid")]
    [InlineData("duplicate-sid")]
    [InlineData("noncanonical-sid")]
    [InlineData("empty-sid")]
    [InlineData("alias-user")]
    [InlineData("alias-name")]
    [InlineData("duplicate-alias-user")]
    [InlineData("duplicate-alias-name")]
    [InlineData("kind")]
    [InlineData("duplicate-kind")]
    public async Task AdversarialSignedEmployeeBinding_DoesNotMintDelegation(string mutation)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateClient();
        var employee = await LoginAsync(client);
        var negative = app.ChangeBinding(employee.AccessToken, mutation);
        // Adversarial fixture is signed by the actual configured test key, not an auth-handler bypass.
        using var response = await SendAsync(client, await CallerAsync(client), negative);
        await AssertDeniedAsync(response, negative);
        Assert.Equal(1, await stores.State.RefreshSessions.CountAsync());
    }

    [Fact]
    public async Task RealRefreshRotation_AllowsBothBoundTokensUntilActualFamilyRevocation()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateClient();
        var employee = await LoginAsync(client);
        var caller = await CallerAsync(client);
        using var refresh = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(employee.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
        var rotated = Assert.IsType<TokenResponse>(await refresh.Content.ReadFromJsonAsync<TokenResponse>());
        foreach (var token in new[] { employee.AccessToken, rotated.AccessToken })
        { using var allowed = await SendAsync(client, caller, token); await AssertIssuedAsync(allowed, app); }
        using (var scope = app.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<IRefreshSessionStore>().RevokeFamilyAsync(
                Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(employee.RefreshToken))), DateTimeOffset.UtcNow, default);
        Assert.All(await stores.State.RefreshSessions.AsNoTracking().ToListAsync(), row => Assert.NotNull(row.RevokedAt));
        foreach (var token in new[] { employee.AccessToken, rotated.AccessToken })
        { using var denied = await SendAsync(client, caller, token); await AssertDeniedAsync(denied, token); }
    }

    [Fact]
    public async Task SessionStoreUnavailable_NoDelegationOrSensitiveError()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var fault = new AuthorityRead { Fail = true };
        await using var app = new Factory(stores, fault);
        using var client = app.CreateClient();
        var employee = await LoginAsync(client);
        var caller = await CallerAsync(client);
        fault.Enabled = true;
        using var response = await SendAsync(client, caller, employee.AccessToken);
        Assert.True(fault.Injected, "Existing exchange must consult current session authority; fault not reached.");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("session-authority-detail", body, StringComparison.Ordinal);
        Assert.DoesNotContain(employee.AccessToken, body, StringComparison.Ordinal);
        Assert.DoesNotContain("accessToken", body, StringComparison.Ordinal);
        Assert.Equal(1, await stores.State.RefreshSessions.CountAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CallerAbortDuringAuthorityReadOrFinalFamilyRead_PropagatesCancellationWithoutMinting(bool finalRead)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var pause = new AuthorityRead { AfterRead = finalRead };
        await using var app = new Factory(stores, pause);
        using var client = app.CreateClient();
        var employee = await LoginAsync(client);
        var caller = await CallerAsync(client);
        using var abort = new CancellationTokenSource();
        pause.Enabled = true;
        var pending = SendAsync(client, caller, employee.AccessToken, abort.Token);
        var winner = await Task.WhenAny(pause.Reached.Task, pending).WaitAsync(TimeSpan.FromSeconds(10));
        if (winner == pending)
        {
            using var unexpected = await pending;
            Assert.True(pause.Injected, "Existing exchange completed without current session read; cancellation boundary not reached.");
        }
        abort.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => { using var response = await pending; });
        Assert.True(pause.ObservedToken.IsCancellationRequested);
        Assert.Equal(1, await stores.State.RefreshSessions.CountAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FreshExpiryAtExactBoundaryWhileSessionReadPaused_DoesNotIssue(bool sessionExpiry)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var pause = new AuthorityRead();
        await using var app = new Factory(stores, pause);
        using var client = app.CreateClient();
        var employee = await LoginAsync(client);
        var caller = await CallerAsync(client);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(employee.AccessToken);
        var boundary = new DateTimeOffset(jwt.ValidTo, TimeSpan.Zero);
        if (sessionExpiry)
        {
            boundary = app.Clock.GetUtcNow().AddSeconds(100);
            var row = await stores.State.RefreshSessions.SingleAsync();
            row.ExpiresAt = boundary;
            await stores.State.SaveChangesAsync();
            // Persisted PostgreSQL precision is the exact session boundary, not a tracked raw timestamp.
            boundary = (await stores.State.RefreshSessions.AsNoTracking().SingleAsync()).ExpiresAt;
        }
        pause.Enabled = true;
        var pending = SendAsync(client, caller, employee.AccessToken);
        var winner = await Task.WhenAny(pause.Reached.Task, pending).WaitAsync(TimeSpan.FromSeconds(10));
        if (winner == pending)
        {
            using var unexpected = await pending;
            Assert.True(pause.Injected, "Existing exchange never reached current authority; post-read expiry remains unexecuted.");
        }
        app.Clock.Set(boundary);
        pause.Release.TrySetResult();
        using var response = await pending;
        await AssertDeniedAsync(response, employee.AccessToken);
        Assert.True(pause.Injected);
        Assert.Equal(1, await stores.State.RefreshSessions.CountAsync());
    }

    [Theory]
    [InlineData("consistent-user")]
    [InlineData("consistent-name")]
    public async Task ConsistentSignedSubjectAlias_PreservesUnambiguousEmployeeAdmission(string alias)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateClient();
        var employee = await LoginAsync(client);
        using var response = await SendAsync(client, await CallerAsync(client), app.ChangeBinding(employee.AccessToken, alias));
        await AssertIssuedAsync(response, app);
        Assert.Equal(1, await stores.State.RefreshSessions.CountAsync());
    }

    private static RefreshSession Session(Guid family, string hash, bool revoked = false) => new()
    {
        Id = Guid.NewGuid(),
        FamilyId = family,
        IdentityId = "invoice-employee",
        IdentityKind = IdentityKind.Employee,
        SecurityStamp = "invoice-stamp",
        TokenHash = new string(hash[0], 64),
        CreatedAt = DateTimeOffset.UtcNow,
        ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
        RevokedAt = revoked ? DateTimeOffset.UtcNow : null,
    };
    private static async Task<TokenResponse> LoginAsync(HttpClient client)
    {
        using var response = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest("invoice@example.test", "invoice-test-password", IdentityKind.Employee));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return Assert.IsType<TokenResponse>(await response.Content.ReadFromJsonAsync<TokenResponse>());
    }
    private static async Task<string> CallerAsync(HttpClient client)
    {
        using var response = await client.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest("legacy-intranet", Factory.ServiceSecret));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return Assert.IsType<ServiceTokenResponse>(await response.Content.ReadFromJsonAsync<ServiceTokenResponse>()).AccessToken;
    }
    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, string caller, string employee, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/v1/exchange/invoice-create")
        { Content = JsonContent.Create(new InvoiceDelegationRequest(employee, 84, Operation.ToString("D"))) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", caller);
        return await client.SendAsync(request, cancellationToken);
    }
    private static async Task AssertDeniedAsync(HttpResponseMessage response, string employee)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(employee, body, StringComparison.Ordinal);
        Assert.DoesNotContain("invoice-employee", body, StringComparison.Ordinal);
        Assert.DoesNotContain("accessToken", body, StringComparison.Ordinal);
    }
    private static async Task AssertIssuedAsync(HttpResponseMessage response, Factory app)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = Assert.IsType<InvoiceDelegationTokenResponse>(await response.Content.ReadFromJsonAsync<InvoiceDelegationTokenResponse>());
        Assert.Equal("Bearer", result.TokenType);
        Assert.Equal(120, result.ExpiresIn);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(result.AccessToken);
        Assert.Equal("invoice-employee", jwt.Subject);
        Assert.Equal("https://invoice-session.test", jwt.Issuer);
        Assert.Equal(["legacy-accounting:invoice-create"], jwt.Audiences);
        Assert.Equal("service:legacy-intranet", Assert.Single(jwt.Claims, x => x.Type == "azp").Value);
        Assert.Equal("legacy.accounting.create", Assert.Single(jwt.Claims, x => x.Type == "scope").Value);
        Assert.Equal("84", Assert.Single(jwt.Claims, x => x.Type == "quotation_id").Value);
        Assert.Equal(Operation.ToString("D"), Assert.Single(jwt.Claims, x => x.Type == "operation_id").Value);
        Assert.DoesNotContain(jwt.Claims, x => x.Type is "email" or "permissions" or "sid" or "employee_access_token");
        app.ValidateDelegation(result.AccessToken);
    }

    private sealed class Factory(Stores stores, AuthorityRead? read = null) : WebApplicationFactory<Program>
    {
        public const string ServiceSecret = "invoice-session-test-only-credential";
        private readonly RSA key = RSA.Create(2048);
        public ControlledClock Clock { get; } = new();
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:EmployeeIdentity"] = stores.Employees.Database.GetConnectionString(),
                ["ConnectionStrings:CustomerIdentity"] = stores.Customers.Database.GetConnectionString(),
                ["ConnectionStrings:RefreshSessions"] = stores.State.Database.GetConnectionString(),
                ["Jwt:Issuer"] = "https://invoice-session.test",
                ["Jwt:Audience"] = "invoice-session-access",
                ["Jwt:PrivateKeyPem"] = key.ExportPkcs8PrivateKeyPem(),
                ["Jwt:KeyId"] = "invoice-session-key",
                ["Jwt:AccessTokenLifetimeSeconds"] = "900",
                ["ServiceClients:Clients:legacy-intranet:SecretSha256"] = ServiceClientCredential.HashSecret(ServiceSecret),
                ["ServiceClients:Clients:legacy-intranet:Permissions:0"] = "legacy-auth.invoice-delegation.issue",
            }));
            builder.ConfigureTestServices(services =>
            {
                Microsoft.Extensions.DependencyInjection.Extensions.ServiceCollectionDescriptorExtensions.RemoveAll<TimeProvider>(services);
                services.AddSingleton<TimeProvider>(Clock);
                if (read is not null) services.AddDbContext<RefreshSessionDbContext>(options => options.AddInterceptors(read));
            });
        }
        public string ChangeBinding(string token, string mutation)
        {
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
            var claims = jwt.Claims.Where(x => x.Type is not ("iss" or "aud" or "iat" or "nbf" or "exp")).ToList();
            if (mutation is "missing-sid" or "wrong-sid" or "empty-sid" or "noncanonical-sid")
            {
                var original = claims.Single(x => x.Type == "sid").Value;
                claims.RemoveAll(x => x.Type == "sid");
                if (mutation != "missing-sid") claims.Add(new("sid", mutation switch
                { "wrong-sid" => Guid.NewGuid().ToString("D"), "empty-sid" => Guid.Empty.ToString("D"), _ => original.ToUpperInvariant() }));
            }
            if (mutation == "duplicate-sid") claims.Add(new("sid", Guid.NewGuid().ToString("D")));
            if (mutation == "alias-user") claims.Add(new("user_id", "another-employee"));
            if (mutation == "alias-name") claims.Add(new(ClaimTypes.NameIdentifier, "another-employee"));
            if (mutation is "consistent-user" or "duplicate-alias-user") claims.Add(new("user_id", jwt.Subject));
            if (mutation is "consistent-name" or "duplicate-alias-name") claims.Add(new(ClaimTypes.NameIdentifier, jwt.Subject));
            if (mutation == "duplicate-alias-user") claims.Add(new("user_id", "another-employee"));
            if (mutation == "duplicate-alias-name") claims.Add(new(ClaimTypes.NameIdentifier, "another-employee"));
            if (mutation == "kind") { claims.RemoveAll(x => x.Type == "identity_kind"); claims.Add(new("identity_kind", "customer")); }
            if (mutation == "duplicate-kind") claims.Add(new("identity_kind", "customer"));
            claims.Add(new("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), ClaimValueTypes.Integer64));
            return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(jwt.Issuer, jwt.Audiences.Single(), claims,
                DateTime.UtcNow.AddSeconds(-1), DateTime.UtcNow.AddMinutes(10), new SigningCredentials(new RsaSecurityKey(key), SecurityAlgorithms.RsaSha256)));
        }
        public void ValidateDelegation(string token) => new JwtSecurityTokenHandler().ValidateToken(token,
            new TokenValidationParameters
            {
                ValidIssuer = "https://invoice-session.test",
                ValidAudience = "legacy-accounting:invoice-create",
                IssuerSigningKey = new RsaSecurityKey(key),
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
            }, out _);
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
            key.Dispose();
            foreach (var connection in connections) NpgsqlConnection.ClearPool(connection);
        }
    }
    private sealed class AuthorityRead : DbCommandInterceptor
    {
        public bool Enabled { get; set; }
        public bool Fail { get; init; }
        public bool AfterRead { get; init; }
        public bool Injected { get; private set; }
        public CancellationToken ObservedToken { get; private set; }
        public TaskCompletionSource Reached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            if (!AfterRead && Enabled && !Injected && command.CommandText.Contains("refresh_sessions", StringComparison.Ordinal))
            {
                Injected = true; ObservedToken = cancellationToken; Reached.TrySetResult();
                if (Fail) throw new PostgresException("session-authority-detail", "ERROR", "ERROR", "42601");
                await Release.Task.WaitAsync(cancellationToken);
            }
            return result;
        }
        public override async ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData,
            DbDataReader result, CancellationToken cancellationToken = default)
        {
            if (AfterRead && Enabled && !Injected && command.CommandText.Contains("EXISTS", StringComparison.Ordinal))
            {
                Injected = true; ObservedToken = cancellationToken; Reached.TrySetResult();
                await Release.Task.WaitAsync(cancellationToken);
            }
            return result;
        }
    }
    private sealed class ControlledClock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => now;
        public void Set(DateTimeOffset value) => now = value;
    }
    private sealed class Stores(EmployeeIdentityDbContext employees, CustomerIdentityDbContext customers, RefreshSessionDbContext state) : IAsyncDisposable
    {
        public EmployeeIdentityDbContext Employees { get; } = employees;
        public CustomerIdentityDbContext Customers { get; } = customers;
        public RefreshSessionDbContext State { get; } = state;
        public static async Task<Stores> CreateAsync(PostgresFixture postgres)
        {
            var stores = new Stores(await postgres.CreateEmployeeContextAsync(), await postgres.CreateCustomerContextAsync(), await postgres.CreateStateContextAsync());
            var row = new LegacyIdentityRow
            {
                Id = "invoice-employee",
                UserName = "invoice@example.test",
                NormalizedUserName = "INVOICE@EXAMPLE.TEST",
                Email = "invoice@example.test",
                NormalizedEmail = "INVOICE@EXAMPLE.TEST",
                EmailConfirmed = true,
                SecurityStamp = "invoice-stamp",
                ConcurrencyStamp = "invoice-concurrency",
                LockoutEnabled = true,
            };
            row.PasswordHash = new Microsoft.AspNetCore.Identity.PasswordHasher<LegacyIdentityRow>().HashPassword(row, "invoice-test-password");
            stores.Employees.Users.Add(row);
            await stores.Employees.SaveChangesAsync();
            return stores;
        }
        public async ValueTask DisposeAsync()
        {
            var connections = new[] { (NpgsqlConnection)Employees.Database.GetDbConnection(), (NpgsqlConnection)Customers.Database.GetDbConnection(), (NpgsqlConnection)State.Database.GetDbConnection() };
            await Employees.DisposeAsync(); await Customers.DisposeAsync(); await State.DisposeAsync();
            foreach (var connection in connections) NpgsqlConnection.ClearPool(connection);
        }
    }
}
