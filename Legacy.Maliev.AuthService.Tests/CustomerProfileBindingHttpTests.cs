extern alias CustomerProducer;

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Data.Common;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.AuthService.Api.Authorization;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Legacy.Maliev.CustomerService.Data;
using Legacy.Maliev.CustomerService.Domain;
using Maliev.Aspire.ServiceDefaults.LegacyAuth;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Npgsql;
using CustomerProgram = CustomerProducer::Program;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class CustomerProfileBindingHttpTests(PostgresFixture postgres)
{
    private static CreateCustomerIdentityRequest Submitted => new(
        "submitted-user@identity.test", "forged-valid@identity.test", "abcdef", true,
        "+6621111111", "submitted-fax", "submitted-mobile", PasswordSetupRequired: true);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NormalCustomerProfileBinding_ActualHostsCopyStoredAuthorityAndHashOnlyRawSubmission(bool reconcile)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new AuthFactory(stores);
        using var client = factory.CreateClient();
        await AuthorizeAsync(client, reconcile);
        using var created = await SendAsync(client, 72, Submitted, reconcile, Guid.NewGuid());
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Equal(1, factory.ProfileReads);
        var user = Assert.Single(await stores.Identities.Users.AsNoTracking().ToListAsync());
        Assert.Equal(72, user.DatabaseID);
        Assert.Equal(Submitted.UserName, user.UserName);
        Assert.Equal("cafe\u0301@profile.test", user.Email);
        Assert.Equal("CAF\u00c9@PROFILE.TEST", user.NormalizedEmail);
        Assert.Equal("+66812345678", user.PhoneNumber);
        Assert.Equal("stored-fax", user.FaxNumber);
        Assert.Equal("stored-mobile", user.MobileNumber);
        Assert.True(user.EmailConfirmed);
        Assert.True(user.PasswordSetupRequired);
        Assert.Equal(PasswordVerificationResult.Success,
            new PasswordHasher<LegacyIdentityRow>().VerifyHashedPassword(user, user.PasswordHash!, Submitted.Password));
        var wire = JsonDocument.Parse(factory.LastProfileBody!);
        using (wire)
        {
            Assert.Equal(72, wire.RootElement.GetProperty("Id").GetInt32());
            Assert.Equal(user.Email, wire.RootElement.GetProperty("Email").GetString());
            Assert.Equal(user.PhoneNumber, wire.RootElement.GetProperty("Telephone").GetString());
            Assert.Equal(user.FaxNumber, wire.RootElement.GetProperty("Fax").GetString());
            Assert.Equal(user.MobileNumber, wire.RootElement.GetProperty("Mobile").GetString());
            Assert.False(wire.RootElement.TryGetProperty("email", out _));
        }
        var receipts = await stores.Identities.CreateOperations.AsNoTracking().ToListAsync();
        if (reconcile)
        {
            var receipt = Assert.Single(receipts);
            Assert.Equal("service:profile-writer", receipt.ServiceSubject);
            Assert.Equal(Rfc2898DeriveBytes.Pbkdf2(JsonSerializer.SerializeToUtf8Bytes(Submitted),
                receipt.PayloadSalt, 210_000, HashAlgorithmName.SHA256, 32), receipt.PayloadHash);
            Assert.NotEqual(Rfc2898DeriveBytes.Pbkdf2(JsonSerializer.SerializeToUtf8Bytes(Submitted with
                { Email = user.Email!, PhoneNumber = user.PhoneNumber, FaxNumber = user.FaxNumber, MobileNumber = user.MobileNumber }),
                receipt.PayloadSalt, 210_000, HashAlgorithmName.SHA256, 32), receipt.PayloadHash);
        }
        else Assert.Empty(receipts);
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
        var body = await created.Content.ReadAsStringAsync();
        Assert.DoesNotContain("PasswordHash", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SecurityStamp", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Submitted.Password, body, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("drift")]
    [InlineData("missing")]
    [InlineData("unavailable")]
    public async Task NormalCustomerProfileBinding_ReceiptFirstReplayAndRawConflictHaveNoNewProfileDependency(string state)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new AuthFactory(stores);
        using var client = factory.CreateClient();
        await AuthorizeAsync(client, true);
        var key = Guid.NewGuid();
        using var created = await SendAsync(client, 72, Submitted, true, key);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var before = await SnapshotAsync(stores);
        var profile = await stores.Profiles.Customers.SingleAsync();
        if (state == "missing") stores.Profiles.Customers.Remove(profile);
        else { profile.Email = "drift@profile.test"; profile.Telephone = "drift-phone"; }
        await stores.Profiles.SaveChangesAsync();
        if (state == "unavailable") factory.ResponseStatus = HttpStatusCode.ServiceUnavailable;
        var reads = factory.ProfileReads;
        using var replay = await SendAsync(client, 72, Submitted, true, key);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        Assert.Equal(new CustomerIdentityCreateReceipt(72, "replayed"),
            await replay.Content.ReadFromJsonAsync<CustomerIdentityCreateReceipt>());
        using var changed = await SendAsync(client, 72, Submitted with { Email = "equally-valid@identity.test" }, true, key);
        Assert.Equal(HttpStatusCode.Conflict, changed.StatusCode);
        using var wrongProfile = await SendAsync(client, 73, Submitted, true, key);
        Assert.Equal(HttpStatusCode.Conflict, wrongProfile.StatusCode);
        Assert.Equal(reads, factory.ProfileReads);
        Assert.Equal(before, await SnapshotAsync(stores));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NormalCustomerProfileBinding_NullOmissionClearsPostedFieldsAndSchemaScalarBoundsPersist(bool supplementary)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var profile = await stores.Profiles.Customers.SingleAsync();
        profile.Email = supplementary ? string.Concat(Enumerable.Repeat("\U0001F600", 249)) + "@x.test" : "stored@profile.test";
        profile.Telephone = supplementary ? string.Concat(Enumerable.Repeat("\U0001F600", 256)) : null;
        profile.Fax = supplementary ? new string('f', 256) : null;
        profile.Mobile = supplementary ? new string('m', 256) : null;
        if (supplementary)
        {
            Assert.True(new System.ComponentModel.DataAnnotations.EmailAddressAttribute().IsValid(profile.Email));
            Assert.Equal(profile.Email, new System.Net.Mail.MailAddress(profile.Email).Address);
        }
        await stores.Profiles.SaveChangesAsync();
        await using var factory = new AuthFactory(stores);
        using var client = factory.CreateClient();
        await AuthorizeAsync(client, false);
        using var created = await SendAsync(client, 72, Submitted, false, Guid.NewGuid());
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var stored = Assert.Single(await stores.Identities.Users.AsNoTracking().ToListAsync());
        Assert.Equal(profile.Email, stored.Email);
        Assert.Equal(profile.Telephone, stored.PhoneNumber);
        Assert.Equal(profile.Fax, stored.FaxNumber);
        Assert.Equal(profile.Mobile, stored.MobileNumber);
        if (!supplementary)
        {
            using var wire = JsonDocument.Parse(factory.LastProfileBody!);
            Assert.False(wire.RootElement.TryGetProperty("Telephone", out _));
            Assert.False(wire.RootElement.TryGetProperty("Fax", out _));
            Assert.False(wire.RootElement.TryGetProperty("Mobile", out _));
        }
        else Assert.Equal(512, stored.PhoneNumber!.Length);
    }

    [Theory]
    [InlineData("missing", 404)]
    [InlineData("unavailable", 503)]
    [InlineData("redirect", 503)]
    [InlineData("malformed", 503)]
    [InlineData("mismatched-id", 503)]
    [InlineData("duplicate-id", 503)]
    [InlineData("wrong-case", 503)]
    [InlineData("wrong-telephone-case", 503)]
    [InlineData("wrong-telephone-type", 503)]
    [InlineData("wrong-fax-type", 503)]
    [InlineData("wrong-mobile-type", 503)]
    [InlineData("email257", 503)]
    [InlineData("telephone257", 503)]
    [InlineData("fax257", 503)]
    [InlineData("mobile257", 503)]
    [InlineData("invalid-email", 503)]
    [InlineData("oversize", 503)]
    [InlineData("missing-own-read", 503)]
    [InlineData("downstream-denied", 503)]
    public async Task NormalCustomerProfileBinding_FailedAuthorityNeverCreatesIdentityReceiptOrRecoveryEffect(string failure, int status)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        if (failure == "missing")
        {
            stores.Profiles.Customers.Remove(await stores.Profiles.Customers.SingleAsync());
            await stores.Profiles.SaveChangesAsync();
        }
        await using var factory = new AuthFactory(stores, ownReadGrant: failure != "missing-own-read");
        using var client = factory.CreateClient();
        await AuthorizeAsync(client, true);
        factory.ResponseStatus = failure switch
        {
            "unavailable" => HttpStatusCode.ServiceUnavailable,
            "redirect" => HttpStatusCode.Redirect,
            _ => null,
        };
        var fields = new Dictionary<string, object?> { ["Id"] = 72, ["Email"] = "stored@profile.test" };
        switch (failure)
        {
            case "mismatched-id": fields["Id"] = 73; break;
            case "wrong-case": fields.Remove("Email"); fields["email"] = "stored@profile.test"; break;
            case "wrong-telephone-case": fields["telephone"] = "+66812345678"; break;
            case "invalid-email": fields["Email"] = "not-an-email"; break;
            case "email257": fields["Email"] = new string('e', 250) + "@x.test"; break;
            case "wrong-telephone-type": fields["Telephone"] = 1; break;
            case "wrong-fax-type": fields["Fax"] = false; break;
            case "wrong-mobile-type": fields["Mobile"] = new[] { "untrusted" }; break;
            case "telephone257": fields["Telephone"] = new string('1', 257); break;
            case "fax257": fields["Fax"] = new string('f', 257); break;
            case "mobile257": fields["Mobile"] = new string('m', 257); break;
        }
        if (failure is not ("missing" or "unavailable" or "redirect" or "missing-own-read" or "downstream-denied"))
            factory.ResponseBody = failure switch
            {
                "malformed" => "{",
                "duplicate-id" => "{\"Id\":72,\"Id\":72,\"Email\":\"stored@profile.test\"}",
                "oversize" => JsonSerializer.Serialize(new { Id = 72, Email = "stored@profile.test", Padding = new string('x', 33 * 1024) }),
                _ => JsonSerializer.Serialize(fields),
            };
        factory.DownstreamDenied = failure == "downstream-denied";
        var before = await SnapshotAsync(stores);
        using var refused = await SendAsync(client, 72, Submitted, true, Guid.NewGuid());
        Assert.Equal((HttpStatusCode)status, refused.StatusCode);
        Assert.Equal(before, await SnapshotAsync(stores));
        Assert.Empty(await stores.Identities.Users.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.Identities.CreateOperations.AsNoTracking().ToListAsync());
        var body = await refused.Content.ReadAsStringAsync();
        Assert.DoesNotContain(Submitted.Email, body, StringComparison.Ordinal);
        Assert.DoesNotContain("stored@profile.test", body, StringComparison.Ordinal);
        Assert.DoesNotContain(Submitted.Password, body, StringComparison.Ordinal);
        if (failure == "missing-own-read") Assert.Equal(0, factory.ProfileReads);
        if (failure == "downstream-denied") Assert.Equal(HttpStatusCode.Forbidden, factory.LastDownstreamStatus);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NormalCustomerProfileBinding_StoredCanonicalCollisionUsesAuthorityBeforeNewWrite(bool reconcile)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        stores.Identities.Users.Add(new LegacyIdentityRow
        {
            Id = "existing-owner", DatabaseID = 71, UserName = "other-user@identity.test",
            NormalizedUserName = "OTHER-USER@IDENTITY.TEST", Email = "caf\u00e9@profile.test",
            NormalizedEmail = "CAF\u00c9@PROFILE.TEST", SecurityStamp = "existing-security", ConcurrencyStamp = "existing-concurrency",
        });
        await stores.Identities.SaveChangesAsync();
        await using var factory = new AuthFactory(stores);
        using var client = factory.CreateClient();
        await AuthorizeAsync(client, reconcile);
        var before = await SnapshotAsync(stores);
        using var result = await SendAsync(client, 72, Submitted, reconcile, Guid.NewGuid());
        Assert.Equal(HttpStatusCode.Conflict, result.StatusCode);
        Assert.Equal(before, await SnapshotAsync(stores));
    }

    [Fact]
    public async Task NormalCustomerProfileBinding_GenuineRenewedEmployeeAndReadWorkloadCannotEscalateCustomerOrOwnReadIntoWrites()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await stores.SeedCustomerControlAsync();
        await using var factory = new AuthFactory(stores);
        using var client = factory.CreateClient();
        using var login = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest("staff@identity.test", "abcdef", IdentityKind.Employee));
        var employee = await login.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        using var refresh = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(employee!.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
        var renewed = (await refresh.Content.ReadFromJsonAsync<TokenResponse>())!;
        var jwt = ValidateJwt(renewed.AccessToken, factory);
        Assert.Equal("employee", Assert.Single(jwt.Claims, value => value.Type == "identity_kind").Value);
        Assert.Single(jwt.Claims, value => value.Type == "permissions" && value.Value == LegacyAccessTokenPermissions.CustomerIdentitiesCreate);
        client.DefaultRequestHeaders.Authorization = new("Bearer", renewed.AccessToken);
        using var created = await SendAsync(client, 72, Submitted, false, Guid.NewGuid());
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var before = await SnapshotAsync(stores);
        await using var scope = factory.Services.CreateAsyncScope();
        var ownRead = await scope.ServiceProvider.GetRequiredService<ILegacyServiceAccessTokenProvider>().GetAccessTokenAsync();
        client.DefaultRequestHeaders.Authorization = new("Bearer", ownRead);
        using var ownWrite = await SendAsync(client, 73, Submitted with { UserName = "second@identity.test" }, false, Guid.NewGuid());
        Assert.Equal(HttpStatusCode.Forbidden, ownWrite.StatusCode);
        using var ownReconcile = await SendAsync(client, 73, Submitted, true, Guid.NewGuid());
        Assert.Equal(HttpStatusCode.Forbidden, ownReconcile.StatusCode);
        Assert.Equal(before, await SnapshotAsync(stores));
        using var customerLogin = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest("customer@identity.test", "abcdef", IdentityKind.Customer));
        Assert.Equal(HttpStatusCode.OK, customerLogin.StatusCode);
        before = await SnapshotAsync(stores);
        client.DefaultRequestHeaders.Authorization = new("Bearer", (await customerLogin.Content.ReadFromJsonAsync<TokenResponse>())!.AccessToken);
        using var customerWrite = await SendAsync(client, 73, Submitted, false, Guid.NewGuid());
        Assert.Equal(HttpStatusCode.Forbidden, customerWrite.StatusCode);
        Assert.Equal(before, await SnapshotAsync(stores));
        Assert.Equal(1, factory.ProfileReads);
    }

    [Fact]
    public async Task NormalCustomerProfileBinding_RenewedOwnWorkloadWithoutReadGrantStopsBeforeTransportOrWrite()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new AuthFactory(stores);
        using var client = factory.CreateClient();
        await AuthorizeAsync(client, false);
        using var created = await SendAsync(client, 72, Submitted, false, Guid.NewGuid());
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var before = await SnapshotAsync(stores);
        await using var scope = factory.Services.CreateAsyncScope();
        var provider = scope.ServiceProvider.GetRequiredService<ILegacyServiceAccessTokenProvider>();
        var original = (await provider.GetAccessTokenAsync())!;
        var clients = scope.ServiceProvider.GetRequiredService<IOptions<ServiceClientOptions>>().Value;
        clients.Clients["legacy-auth"].Permissions = ["legacy-contact.messages.create"];
        provider.Invalidate(original);
        var renewed = (await provider.GetAccessTokenAsync())!;
        var jwt = ValidateJwt(renewed, factory);
        Assert.Equal("service:legacy-auth", Assert.Single(jwt.Claims, value => value.Type == "sub").Value);
        Assert.DoesNotContain(jwt.Claims, value => value.Type == "permissions" && value.Value == CustomerProfileBindingClient.ReadPermission);
        using var refused = await SendAsync(client, 73, Submitted with { UserName = "second@identity.test" }, false, Guid.NewGuid());
        Assert.Equal(HttpStatusCode.ServiceUnavailable, refused.StatusCode);
        Assert.Equal(1, factory.ProfileReads);
        Assert.Equal(before, await SnapshotAsync(stores));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NormalCustomerProfileBinding_DirectCreateRefusesMissingOrUnavailableAuthorityBeforePersistence(bool missing)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        if (missing)
        {
            stores.Profiles.Customers.Remove(await stores.Profiles.Customers.SingleAsync());
            await stores.Profiles.SaveChangesAsync();
        }
        await using var factory = new AuthFactory(stores);
        if (!missing) factory.ResponseStatus = HttpStatusCode.ServiceUnavailable;
        using var client = factory.CreateClient();
        await AuthorizeAsync(client, false);
        var before = await SnapshotAsync(stores);
        using var refused = await SendAsync(client, 72, Submitted, false, Guid.NewGuid());
        Assert.Equal(missing ? HttpStatusCode.NotFound : HttpStatusCode.ServiceUnavailable, refused.StatusCode);
        Assert.Equal(before, await SnapshotAsync(stores));
    }

    [Fact]
    public async Task NormalCustomerProfileBinding_ConcurrentSameRawOperationReadsProfileOnceAndReconcilesLockedReceipt()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new AuthFactory(stores);
        using var first = factory.CreateClient();
        using var second = factory.CreateClient();
        first.Timeout = second.Timeout = TimeSpan.FromSeconds(30);
        await AuthorizeAsync(first, true);
        await AuthorizeAsync(second, true);
        var key = Guid.NewGuid();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var replies = await Task.WhenAll(SendAsync(first, 72, Submitted, true, key), SendAsync(second, 72, Submitted, true, key));
        try
        {
            Assert.Single(replies, value => value.StatusCode == HttpStatusCode.Created);
            Assert.Single(replies, value => value.StatusCode == HttpStatusCode.OK);
            Assert.Equal(1, factory.ProfileReads);
            Assert.Single(await stores.Identities.Users.AsNoTracking().ToListAsync(deadline.Token));
            Assert.Single(await stores.Identities.CreateOperations.AsNoTracking().ToListAsync(deadline.Token));
        }
        finally { foreach (var reply in replies) reply.Dispose(); }
    }

    private static async Task AuthorizeAsync(HttpClient client, bool reconcile)
    {
        if (reconcile)
        {
            using var login = await client.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest("profile-writer", AuthFactory.Secret));
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            client.DefaultRequestHeaders.Authorization = new("Bearer", (await login.Content.ReadFromJsonAsync<ServiceTokenResponse>())!.AccessToken);
        }
        else
        {
            using var login = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest("staff@identity.test", "abcdef", IdentityKind.Employee));
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            client.DefaultRequestHeaders.Authorization = new("Bearer", (await login.Content.ReadFromJsonAsync<TokenResponse>())!.AccessToken);
        }
    }

    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, int id, CreateCustomerIdentityRequest request, bool reconcile, Guid key)
    {
        using var message = new HttpRequestMessage(HttpMethod.Post, $"/auth/v1/customer-identities/{id}" + (reconcile ? "/reconcile-create" : ""))
        { Content = JsonContent.Create(request) };
        if (reconcile) message.Headers.Add("Idempotency-Key", key.ToString("D"));
        return await client.SendAsync(message);
    }

    private static async Task<string> SnapshotAsync(Stores stores) => JsonSerializer.Serialize(new
    {
        Users = await stores.Identities.Users.AsNoTracking().OrderBy(value => value.Id).ToListAsync(),
        Receipts = await stores.Identities.CreateOperations.AsNoTracking().OrderBy(value => value.OperationKey).ToListAsync(),
        Actions = await stores.State.IdentityActionTokens.AsNoTracking().OrderBy(value => value.Id).ToListAsync(),
        Sessions = await stores.State.RefreshSessions.AsNoTracking().OrderBy(value => value.Id).ToListAsync(),
        Effects = await stores.Employees.RecoveryEffects.AsNoTracking().OrderBy(value => value.ActionId).ToListAsync(),
    });

    private static JwtSecurityToken ValidateJwt(string token, AuthFactory factory)
    {
        var parameters = factory.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters;
        new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(token, parameters, out var validated);
        var jwt = Assert.IsType<JwtSecurityToken>(validated);
        Assert.Equal("RS256", jwt.Header.Alg);
        return jwt;
    }

    private sealed class AuthFactory(Stores stores, bool ownReadGrant = true) : WebApplicationFactory<Program>
    {
        public const string Secret = "customer-profile-test-only-0123456789";
        private readonly RSA signing = RSA.Create(2048);
        private CustomerFactory? customer;
        public int ProfileReads { get; private set; }
        public HttpStatusCode? ResponseStatus { get; set; }
        public string? ResponseBody { get; set; }
        public string? LastProfileBody { get; private set; }
        public bool DownstreamDenied { get; set; }
        public HttpStatusCode? LastDownstreamStatus { get; private set; }
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.ConfigureLogging(logging => logging.AddProvider(new FixtureFailureLogger()));
            builder.UseSetting("CORS:AllowedOrigins:0", "https://localhost");
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:EmployeeIdentity"] = stores.Employees.Database.GetConnectionString(),
                ["ConnectionStrings:CustomerIdentity"] = stores.Identities.Database.GetConnectionString(),
                ["ConnectionStrings:RefreshSessions"] = stores.State.Database.GetConnectionString(),
                ["CORS:AllowedOrigins:0"] = "https://localhost",
                ["Jwt:Issuer"] = "https://customer-binding.test", ["Jwt:Audience"] = "customer-binding-test",
                ["Jwt:PrivateKeyPem"] = signing.ExportPkcs8PrivateKeyPem(), ["Jwt:KeyId"] = "customer-binding-test",
                ["Jwt:AccessTokenLifetimeSeconds"] = "900",
                ["Services:Auth:BaseUrl"] = "https://customer-binding.test",
                ["Services:CustomerService:BaseUrl"] = "https://customer-producer.test",
                ["ServiceAuthentication:ClientId"] = "legacy-auth", ["ServiceAuthentication:ClientSecret"] = Secret,
                ["ServiceClients:Clients:legacy-auth:SecretSha256"] = ServiceClientCredential.HashSecret(Secret),
                ["ServiceClients:Clients:legacy-auth:Permissions:0"] = ownReadGrant ? CustomerProfileBindingClient.ReadPermission : "legacy-contact.messages.create",
                ["ServiceClients:Clients:profile-writer:SecretSha256"] = ServiceClientCredential.HashSecret(Secret),
                ["ServiceClients:Clients:profile-writer:Permissions:0"] = LegacyAccessTokenPermissions.CustomerIdentitiesReconcileCreate,
            }));
            builder.ConfigureTestServices(services =>
            {
                var pools = new OwnedPoolCapture(stores);
                services.AddDbContext<CustomerIdentityDbContext>(options => options.AddInterceptors(pools));
                services.AddDbContext<EmployeeIdentityDbContext>(options => options.AddInterceptors(pools));
                services.AddDbContext<RefreshSessionDbContext>(options => options.AddInterceptors(pools));
                services.PostConfigure<ApiBehaviorOptions>(options =>
                {
                    var original = options.InvalidModelStateResponseFactory;
                    options.InvalidModelStateResponseFactory = context =>
                    {
                        Console.WriteLine("CustomerBindingInvalidModelFields: " + string.Join(",", context.ModelState.Where(value => value.Value!.Errors.Count != 0).Select(value => value.Key is "UserName" or "Password" or "IdentityKind" or "request" or "ClientId" or "ClientSecret" ? value.Key : "[redacted-field]").Distinct().Order().Take(8)));
                        return original(context);
                    };
                });
                services.AddHttpClient(LegacyServiceAccessTokenProvider.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => Server.CreateHandler());
                services.AddHttpClient(CustomerProfileBindingClient.HttpClientName).ConfigurePrimaryHttpMessageHandler(() =>
                {
                    customer ??= new CustomerFactory(stores, signing.ExportSubjectPublicKeyInfoPem());
                    return new ProfileTransport(this, customer.Server.CreateHandler());
                });
            });
        }
        private sealed class ProfileTransport(AuthFactory owner, HttpMessageHandler downstream) : DelegatingHandler(downstream)
        {
            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                owner.ProfileReads++;
                Assert.Equal(HttpMethod.Get, request.Method);
                Assert.Equal("customer-producer.test", request.RequestUri!.Host);
                Assert.StartsWith("/customers/", request.RequestUri.AbsolutePath, StringComparison.Ordinal);
                Assert.True(request.Headers.CacheControl!.NoCache);
                Assert.True(request.Headers.CacheControl.NoStore);
                var jwt = ValidateJwt(request.Headers.Authorization!.Parameter!, owner);
                Assert.Equal("service:legacy-auth", Assert.Single(jwt.Claims, value => value.Type == "sub").Value);
                Assert.Equal("service", Assert.Single(jwt.Claims, value => value.Type == "identity_kind").Value);
                Assert.Single(jwt.Claims, value => value.Type == "permissions" && value.Value == CustomerProfileBindingClient.ReadPermission);
                Assert.DoesNotContain(jwt.Claims, value => value.Type is "sid" or "role" or "employeeId");
                // Adversarial downstream control uses a genuine denied workload JWT from the normal issuer.
                if (owner.DownstreamDenied)
                {
                    using var authClient = owner.CreateClient();
                    using var login = await authClient.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest("profile-writer", Secret), cancellationToken);
                    Assert.Equal(HttpStatusCode.OK, login.StatusCode);
                    request.Headers.Authorization = new("Bearer", (await login.Content.ReadFromJsonAsync<ServiceTokenResponse>(cancellationToken))!.AccessToken);
                }
                if (owner.ResponseStatus is { } status) return new(status) { Content = new StringContent("{}") };
                if (owner.ResponseBody is { } body) return new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
                var result = await base.SendAsync(request, cancellationToken);
                owner.LastDownstreamStatus = result.StatusCode;
                owner.LastProfileBody = await result.Content.ReadAsStringAsync(cancellationToken);
                return result;
            }
        }
        public override async ValueTask DisposeAsync()
        {
            try
            {
                if (customer is not null) await customer.DisposeAsync();
            }
            finally
            {
                try { await base.DisposeAsync(); }
                finally { signing.Dispose(); }
            }
        }
    }

    private sealed class CustomerFactory(Stores stores, string publicKey) : WebApplicationFactory<CustomerProgram>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.ConfigureLogging(logging => logging.AddProvider(new FixtureFailureLogger()));
            foreach (var setting in new Dictionary<string, string?>
            {
                ["ConnectionStrings:CustomerDbContext"] = stores.Profiles.Database.GetConnectionString(),
                ["Cache:RedisEnabled"] = "false", ["CORS:AllowedOrigins:0"] = "https://localhost",
                ["Jwt:PublicKey"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(publicKey)),
                ["Jwt:Issuer"] = "https://customer-binding.test", ["Jwt:Audience"] = "customer-binding-test",
                ["Features:ResourceScopedAuthEnabled"] = "true", ["OTEL_EXPORTER_OTLP_ENDPOINT"] = "",
            }) builder.UseSetting(setting.Key, setting.Value);
            builder.ConfigureTestServices(services => services.AddDbContext<CustomerDbContext>(options => options.AddInterceptors(new OwnedPoolCapture(stores))));
        }
    }

    private sealed class OwnedPoolCapture(Stores stores) : DbConnectionInterceptor
    {
        public override InterceptionResult ConnectionOpening(DbConnection connection, ConnectionEventData eventData, InterceptionResult result)
        {
            stores.RegisterPool((NpgsqlConnection)connection);
            return result;
        }
        public override ValueTask<InterceptionResult> ConnectionOpeningAsync(DbConnection connection, ConnectionEventData eventData, InterceptionResult result, CancellationToken cancellationToken = default)
        {
            stores.RegisterPool((NpgsqlConnection)connection);
            return ValueTask.FromResult(result);
        }
    }

    private sealed class FixtureFailureLogger : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new FailureLogger();
        public void Dispose() { }
        private sealed class FailureLogger : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel level) => level >= LogLevel.Error;
            public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                if (exception is null) return;
                var depth = 0;
                for (var cause = exception; cause is not null && depth++ < 3; cause = cause.InnerException)
                    Console.WriteLine("CustomerBindingFailure: " + cause.GetType().FullName + " at " + string.Join(" -> ", new System.Diagnostics.StackTrace(cause).GetFrames().Take(8).Select(frame => frame.GetMethod()?.DeclaringType?.FullName + "." + frame.GetMethod()?.Name)));
            }
        }
    }

    private sealed class Stores : IAsyncDisposable
    {
        public CustomerIdentityDbContext Identities { get; private set; } = null!;
        public EmployeeIdentityDbContext Employees { get; private set; } = null!;
        public RefreshSessionDbContext State { get; private set; } = null!;
        public CustomerDbContext Profiles { get; private set; } = null!;
        private readonly List<DbContext> owned = [];
        private readonly HashSet<NpgsqlConnection> pools = [];
        private readonly object poolGate = new();
        public void RegisterPool(NpgsqlConnection connection) { lock (poolGate) pools.Add(connection); }
        public static async Task<Stores> CreateAsync(PostgresFixture postgres)
        {
            var stores = new Stores();
            try
            {
                stores.Identities = await postgres.CreateCustomerContextAsync(stores.RegisterPool); stores.owned.Add(stores.Identities);
                stores.Employees = await postgres.CreateEmployeeContextAsync(stores.RegisterPool); stores.owned.Add(stores.Employees);
                stores.State = await postgres.CreateStateContextAsync(stores.RegisterPool); stores.owned.Add(stores.State);
                stores.Profiles = new CustomerDbContext(new DbContextOptionsBuilder<CustomerDbContext>().UseNpgsql(await postgres.CreateDatabaseAsync()).Options);
                stores.owned.Add(stores.Profiles); stores.RegisterPool((NpgsqlConnection)stores.Profiles.Database.GetDbConnection());
                await stores.Profiles.Database.MigrateAsync();
                stores.Profiles.Customers.Add(new Customer { Id = 72, FirstName = "Stored", LastName = "Profile", Email = "cafe\u0301@profile.test", Telephone = "+66812345678", Fax = "stored-fax", Mobile = "stored-mobile" });
                await stores.Profiles.SaveChangesAsync();
                var hasher = new PasswordHasher<LegacyIdentityRow>();
                var employee = new LegacyIdentityRow { Id = "binding-staff", DatabaseID = 1, UserName = "staff@identity.test", NormalizedUserName = "STAFF@IDENTITY.TEST", Email = "staff@identity.test", NormalizedEmail = "STAFF@IDENTITY.TEST", EmailConfirmed = true, SecurityStamp = "staff-stamp", ConcurrencyStamp = "staff-concurrency" };
                employee.PasswordHash = hasher.HashPassword(employee, "abcdef");
                stores.Employees.Users.Add(employee); await stores.Employees.SaveChangesAsync();
                // Customer login denial control lives at another profile id and cannot own the new binding.
                var customer = new LegacyIdentityRow { Id = "binding-customer", DatabaseID = 1, UserName = "customer@identity.test", NormalizedUserName = "CUSTOMER@IDENTITY.TEST", Email = "customer@identity.test", NormalizedEmail = "CUSTOMER@IDENTITY.TEST", EmailConfirmed = true, SecurityStamp = "customer-stamp", ConcurrencyStamp = "customer-concurrency" };
                customer.PasswordHash = hasher.HashPassword(customer, "abcdef");
                // Added only by the escalation test when it needs a genuine customer login.
                stores.customerControl = customer;
                return stores;
            }
            catch { await stores.DisposeAsync(); throw; }
        }
        private LegacyIdentityRow customerControl = null!;
        public async Task SeedCustomerControlAsync() { Identities.Users.Add(customerControl); await Identities.SaveChangesAsync(); }
        public async ValueTask DisposeAsync()
        {
            var failures = new List<Exception>();
            foreach (var context in owned)
                try { await context.DisposeAsync(); } catch (Exception exception) { failures.Add(exception); }
            foreach (var pool in pools)
                try { NpgsqlConnection.ClearPool(pool); } catch (Exception exception) { failures.Add(exception); }
            if (failures.Count != 0) throw new AggregateException("Owned fixture cleanup failed", failures);
        }
    }
}
