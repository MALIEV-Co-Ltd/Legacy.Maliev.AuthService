using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.AuthService.Api.Authorization;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
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
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class EmployeeSessionIssuanceHttpTests(PostgresFixture postgres)
{
    [Theory]
    [InlineData(IdentityKind.Employee, false)]
    [InlineData(IdentityKind.Customer, false)]
    [InlineData(IdentityKind.Customer, true)]
    public async Task NormalAdministrativePasswordPolicy_NewCreationRejectsLowDistinctAndAcceptsSixCharacterBoundary(
        IdentityKind kind, bool reconcile)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores, identityAdministration: true);
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, reconcile);
        var identities = await SnapshotIdentitiesAsync(stores);
        var sessionCount = await stores.State.RefreshSessions.CountAsync();
        var key = Guid.NewGuid();
        var route = $"/auth/v1/{kind.ToString().ToLowerInvariant()}-identities/71" + (reconcile ? "/reconcile-create" : "");
        if (reconcile) client.DefaultRequestHeaders.Add("Idempotency-Key", key.ToString());
        const string email = "new-admin@example.com";
        foreach (var invalid in new string?[] { "aaabbbccc", "abcde", string.Empty, null, "abcdef" + new string('a', 1019) })
        {
            await using var scope = factory.Services.CreateAsyncScope();
            if (kind == IdentityKind.Employee)
                Assert.Null(await scope.ServiceProvider.GetRequiredService<IEmployeeIdentityAdminService>()
                    .CreateAsync(71, (CreateEmployeeIdentityRequest)AdministrativeRequest(kind, email, invalid), default));
            else if (reconcile)
                Assert.Equal(CustomerIdentityCreateOutcome.InvalidPassword,
                    (await scope.ServiceProvider.GetRequiredService<ICustomerIdentityAdminService>().CreateOrReconcileAsync(
                        71, "service:issuance-test", key, (CreateCustomerIdentityRequest)AdministrativeRequest(kind, email, invalid), default)).Outcome);
            else
                Assert.Null(await scope.ServiceProvider.GetRequiredService<ICustomerIdentityAdminService>()
                    .CreateAsync(71, (CreateCustomerIdentityRequest)AdministrativeRequest(kind, email, invalid), default));
            using var rejected = await client.PostAsJsonAsync(route, AdministrativeRequest(kind, email, invalid));
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
            var body = await rejected.Content.ReadAsStringAsync();
            Assert.DoesNotContain(email, body, StringComparison.Ordinal);
            if (!string.IsNullOrEmpty(invalid)) Assert.DoesNotContain(invalid, body, StringComparison.Ordinal);
            Assert.Equal(identities, await SnapshotIdentitiesAsync(stores));
            Assert.Empty(await stores.Customers.CreateOperations.AsNoTracking().ToListAsync());
            Assert.Equal(sessionCount, await stores.State.RefreshSessions.CountAsync());
        }
        using var created = await client.PostAsJsonAsync(route, AdministrativeRequest(kind, email, "abcdef"));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        if (reconcile)
        {
            using var replay = await client.PostAsJsonAsync(route, AdministrativeRequest(kind, email, "abcdef"));
            Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
            var receipt = await replay.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal(["databaseId", "status"], receipt.EnumerateObject().Select(value => value.Name).Order().ToArray());
            Assert.Equal(71, receipt.GetProperty("databaseId").GetInt32());
            Assert.Equal("replayed", receipt.GetProperty("status").GetString());
        }
        var users = kind == IdentityKind.Employee ? stores.Employees.Users : stores.Customers.Users;
        var identity = await users.AsNoTracking().SingleAsync(value => value.DatabaseID == 71);
        Assert.Equal(PasswordVerificationResult.Success,
            new PasswordHasher<LegacyIdentityRow>().VerifyHashedPassword(identity, identity.PasswordHash!, "abcdef"));
        client.DefaultRequestHeaders.Authorization = null;
        using var login = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest(email, "abcdef", kind));
        var tokens = await ReadTokensAsync(login);
        var jwt = ReadJwt(tokens.AccessToken, factory);
        Assert.Equal(identity.Id, Assert.Single(jwt.Claims, value => value.Type == "sub").Value);
        Assert.Equal(kind.ToString().ToLowerInvariant(), Assert.Single(jwt.Claims, value => value.Type == "identity_kind").Value);
        Assert.Equal(kind == IdentityKind.Employee ? "Employee" : "Customer", Assert.Single(jwt.Claims, value => value.Type == ClaimTypes.Role).Value);
        var session = await stores.State.RefreshSessions.AsNoTracking().SingleAsync(value => value.IdentityId == identity.Id);
        Assert.Equal(kind, session.IdentityKind);
        Assert.Equal(identity.SecurityStamp, session.SecurityStamp);
        Assert.Equal(Hash(tokens.RefreshToken), session.TokenHash);
    }

    [Fact]
    public async Task NormalAdministrativePasswordPolicy_WebRegistrationKeepsEightCharacterLowDistinctPolicy()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores, identityAdministration: true);
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, service: true);
        await using (var scope = factory.Services.CreateAsyncScope())
            Assert.True(scope.ServiceProvider.GetRequiredService<CustomerIdentityDbContext>().Database.CreateExecutionStrategy().RetriesOnFailure);
        using var registered = await client.PostAsJsonAsync("/auth/v1/customer-self-service/register",
            new RegisterCustomerIdentityRequest(72, "web-policy@example.com", "aabbccdd"));
        if (registered.StatusCode != HttpStatusCode.Created)
        {
            var classification = "non-validation-response";
            try
            {
                var problem = await registered.Content.ReadFromJsonAsync<JsonElement>();
                if (problem.TryGetProperty("errors", out var errors) && errors.ValueKind == JsonValueKind.Object)
                {
                    var fields = errors.EnumerateObject().Take(8).Select(error => error.Name switch
                    {
                        "DatabaseId" or "databaseId" => "DatabaseId",
                        "Email" or "email" => "Email",
                        "Password" or "password" => "Password",
                        _ => "other-field",
                    }).ToArray();
                    classification = "validation-fields:" + string.Join(",", fields);
                }
            }
            catch (JsonException) { classification = "non-json-response"; }
            Assert.Fail($"Registration did not return Created: HTTP {(int)registered.StatusCode}; {classification}.");
        }
        var identity = await stores.Customers.Users.AsNoTracking().SingleAsync(value => value.DatabaseID == 72);
        Assert.Equal(PasswordVerificationResult.Success,
            new PasswordHasher<LegacyIdentityRow>().VerifyHashedPassword(identity, identity.PasswordHash!, "aabbccdd"));
        Assert.False(identity.EmailConfirmed);
        Assert.Empty(await stores.Customers.CreateOperations.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        var committed = await SnapshotIdentitiesAsync(stores);
        using var wrongLink = await client.PostAsJsonAsync("/auth/v1/customer-self-service/register/resolve",
            new ResolveCustomerIdentityRequest(73, "web-policy@example.com", "aabbccdd"));
        Assert.Equal(HttpStatusCode.NotFound, wrongLink.StatusCode);
        using var wrongPassword = await client.PostAsJsonAsync("/auth/v1/customer-self-service/register/resolve",
            new ResolveCustomerIdentityRequest(72, "web-policy@example.com", "wrong-password"));
        Assert.Equal(HttpStatusCode.NotFound, wrongPassword.StatusCode);
        using var resolved = await client.PostAsJsonAsync("/auth/v1/customer-self-service/register/resolve",
            new ResolveCustomerIdentityRequest(72, "web-policy@example.com", "aabbccdd"));
        Assert.Equal(HttpStatusCode.OK, resolved.StatusCode);
        var result = (await resolved.Content.ReadFromJsonAsync<CustomerSelfServiceResult>())!;
        Assert.True(result.Succeeded);
        Assert.True(result.Created);
        Assert.Equal(identity.Id, result.IdentityId);
        Assert.Equal(72, result.DatabaseId);
        Assert.Equal(committed, await SnapshotIdentitiesAsync(stores));
        Assert.Empty(await stores.Customers.CreateOperations.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    [Fact]
    public async Task NormalAdministrativePasswordPolicy_PreviouslyCommittedWeakPasswordReceiptRemainsReplayable()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        const string email = "legacy-admin@example.com";
        var identity = new LegacyIdentityRow
        {
            Id = "legacy-admin-policy",
            DatabaseID = 73,
            UserName = email,
            NormalizedUserName = email.ToUpperInvariant(),
            Email = email,
            NormalizedEmail = email.ToUpperInvariant(),
            EmailConfirmed = true,
            SecurityStamp = "legacy-admin-stamp",
            ConcurrencyStamp = "legacy-admin-concurrency",
            LockoutEnabled = true,
        };
        identity.PasswordHash = new PasswordHasher<LegacyIdentityRow>().HashPassword(identity, "aaaaaaaa");
        var key = Guid.NewGuid();
        stores.Customers.Users.Add(identity);
        stores.Customers.CreateOperations.Add(new CustomerIdentityCreateOperation
        {
            ServiceSubject = "service:issuance-test",
            OperationKey = key,
            DatabaseId = 73,
            IdentityId = identity.Id,
            PayloadSalt = Enumerable.Range(0, 16).Select(value => (byte)value).ToArray(),
            // Independent Python PBKDF2-SHA256/210000/32 fixture over the original Pascal-case request JSON.
            PayloadHash = Convert.FromHexString("10971819444ebc3d554c2229c8840bb783dab70386418b83b39d5d6c03a755bb"),
        });
        await stores.Customers.SaveChangesAsync();
        var before = await SnapshotIdentitiesAsync(stores);
        var operationBefore = JsonSerializer.Serialize(await stores.Customers.CreateOperations.AsNoTracking().SingleAsync());
        await using var factory = new Factory(stores, identityAdministration: true);
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, service: true);
        client.DefaultRequestHeaders.Add("Idempotency-Key", key.ToString());
        const string route = "/auth/v1/customer-identities/73/reconcile-create";
        using var replay = await client.PostAsJsonAsync(route, AdministrativeRequest(IdentityKind.Customer, email, "aaaaaaaa"));
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        var receipt = await replay.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(["databaseId", "status"], receipt.EnumerateObject().Select(value => value.Name).Order().ToArray());
        Assert.Equal("replayed", receipt.GetProperty("status").GetString());
        using var conflict = await client.PostAsJsonAsync(route, AdministrativeRequest(IdentityKind.Customer, email, "abcdef"));
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        Assert.Equal(before, await SnapshotIdentitiesAsync(stores));
        Assert.Equal(operationBefore, JsonSerializer.Serialize(await stores.Customers.CreateOperations.AsNoTracking().SingleAsync()));
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NormalAdministrativePasswordPolicy_LengthMaximumAndUtf16DistinctBoundaryUseActualWrite(bool unicode)
    {
        var password = unicode ? "abc\uD83D\uDE00d" : "abcdef" + new string('a', 1018);
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, service: false);
        using var created = await client.PostAsJsonAsync("/auth/v1/employee-identities/74",
            AdministrativeRequest(IdentityKind.Employee, "boundary-admin@example.com", password));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var identity = await stores.Employees.Users.AsNoTracking().SingleAsync(value => value.DatabaseID == 74);
        Assert.Equal(PasswordVerificationResult.Success,
            new PasswordHasher<LegacyIdentityRow>().VerifyHashedPassword(identity, identity.PasswordHash!, password));
        Assert.Equal(unicode ? 6 : 1024, password.Length);
    }

    private static object AdministrativeRequest(IdentityKind kind, string email, string? password) => kind == IdentityKind.Employee
        ? new CreateEmployeeIdentityRequest(email, email, password!, true, null)
        : new CreateCustomerIdentityRequest(email, email, password!, true, null, null, null);

    private static async Task AuthorizeAdministrationAsync(HttpClient client, bool service)
    {
        string token;
        if (service)
        {
            using var response = await client.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest("issuance-test", Factory.ServiceSecret));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            token = (await response.Content.ReadFromJsonAsync<ServiceTokenResponse>())!.AccessToken;
        }
        else token = (await LoginAsync(client, IdentityKind.Employee)).AccessToken;
        client.DefaultRequestHeaders.Authorization = new("Bearer", token);
    }

    [Theory]
    [InlineData(IdentityKind.Employee, false)]
    [InlineData(IdentityKind.Customer, false)]
    [InlineData(IdentityKind.Employee, true)]
    [InlineData(IdentityKind.Customer, true)]
    public async Task NormalHistoricalPasswordFormat_LegacyHashAuthenticatesWithoutRehashOrIdentityMutation(IdentityKind kind, bool versionThree)
    {
        // Independently constructed PBKDF2 fixtures: salt bytes 00..0f, password issuance-password.
        // V2: marker 00, SHA1/1000/32. V3: marker 01, big-endian PRF=1/iterations=10000/saltLength=16, SHA256/32.
        var storedHash = versionThree
            ? "AQAAAAEAACcQAAAAEAABAgMEBQYHCAkKCwwNDg/L+ligzuuNDfC4puJ7/XESuifEOqBUSJqj0uubEuaNLQ=="
            : "AAABAgMEBQYHCAkKCwwNDg9XcaRSqhkwK0f7PnHfbpe/YYjZAgTebgJbfRuJrkU1dQ==";
        await using var stores = await Stores.CreateAsync(postgres);
        var context = kind == IdentityKind.Employee ? (LegacyIdentityDbContext)stores.Employees : stores.Customers;
        var row = await context.Users.SingleAsync();
        row.PasswordHash = storedHash;
        await context.SaveChangesAsync();
        var identities = await SnapshotIdentitiesAsync(stores);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var login = Login(kind);
        using (var scope = factory.Services.CreateScope())
        {
            var hasher = Assert.IsType<PasswordHasher<LegacyIdentityRow>>(scope.ServiceProvider.GetRequiredService<IPasswordHasher<LegacyIdentityRow>>());
            Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, hasher.VerifyHashedPassword(row, storedHash, login.Password));
        }
        using var denied = await client.PostAsJsonAsync("/auth/v1/login", login with { Password = "synthetic-wrong-password" });
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        var problem = await denied.Content.ReadAsStringAsync();
        foreach (var sensitive in new[] { row.Id, login.UserName, login.Password, "synthetic-wrong-password", storedHash, "accessToken" })
            Assert.DoesNotContain(sensitive, problem, StringComparison.Ordinal);
        Assert.Equal(identities, await SnapshotIdentitiesAsync(stores));
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());

        var tokens = await LoginAsync(client, kind);
        var jwt = ReadJwt(tokens.AccessToken, factory);
        Assert.Equal(row.Id, Assert.Single(jwt.Claims, claim => claim.Type == "sub").Value);
        Assert.Equal(kind.ToString().ToLowerInvariant(), Assert.Single(jwt.Claims, claim => claim.Type == "identity_kind").Value);
        var role = kind == IdentityKind.Employee ? "Employee" : "Customer";
        Assert.Equal(role, Assert.Single(jwt.Claims, claim => claim.Type == ClaimTypes.Role).Value);
        Assert.Equal(role, Assert.Single(jwt.Claims, claim => claim.Type == "role").Value);
        var session = Assert.Single(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Equal(row.Id, session.IdentityId);
        Assert.Equal(kind, session.IdentityKind);
        Assert.Equal(Hash(tokens.RefreshToken), session.TokenHash);
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
        Assert.Equal(identities, await SnapshotIdentitiesAsync(stores));
        Assert.Equal(storedHash, (await context.Users.AsNoTracking().SingleAsync()).PasswordHash);
    }

    [Theory]
    [InlineData(IdentityKind.Employee)]
    [InlineData(IdentityKind.Customer)]
    public async Task NormalHistoricalSecurity_IdentityIdPasswordDeniesWithoutMutation_RealPasswordIssuesBoundActor(IdentityKind kind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var identities = await SnapshotIdentitiesAsync(stores);
        var id = kind == IdentityKind.Employee ? "issuance-employee" : "issuance-customer";
        var login = Login(kind);
        using var denied = await client.PostAsJsonAsync("/auth/v1/login", login with { Password = id });
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        var problem = await denied.Content.ReadAsStringAsync();
        Assert.DoesNotContain(id, problem, StringComparison.Ordinal);
        Assert.DoesNotContain(login.UserName, problem, StringComparison.Ordinal);
        Assert.DoesNotContain(login.Password, problem, StringComparison.Ordinal);
        Assert.DoesNotContain("accessToken", problem, StringComparison.Ordinal);
        Assert.Equal(identities, await SnapshotIdentitiesAsync(stores));
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());

        var tokens = await LoginAsync(client, kind);
        var jwt = ReadJwt(tokens.AccessToken, factory);
        var role = kind == IdentityKind.Employee ? "Employee" : "Customer";
        Assert.Equal(id, Assert.Single(jwt.Claims, claim => claim.Type == "sub").Value);
        Assert.Equal(kind.ToString().ToLowerInvariant(), Assert.Single(jwt.Claims, claim => claim.Type == "identity_kind").Value);
        Assert.Equal(role, Assert.Single(jwt.Claims, claim => claim.Type == ClaimTypes.Role).Value);
        Assert.Equal(role, Assert.Single(jwt.Claims, claim => claim.Type == "role").Value);
        var session = Assert.Single(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Equal(id, session.IdentityId);
        Assert.Equal(kind, session.IdentityKind);
        Assert.Equal(Hash(tokens.RefreshToken), session.TokenHash);
        Assert.Equal(identities, await SnapshotIdentitiesAsync(stores));
    }

    [Theory]
    [InlineData("validate")]
    [InlineData("longlived")]
    public async Task NormalHistoricalSecurity_RetiredCredentialRoutesRemainAbsentWithoutIdentityOrSessionMutation(string route)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var identities = await SnapshotIdentitiesAsync(stores);
        var login = Login(IdentityKind.Employee);
        using var request = route == "validate"
            ? new HttpRequestMessage(HttpMethod.Get, "/auth/validate?username=" + Uri.EscapeDataString(login.UserName)
                + "&password=" + Uri.EscapeDataString(login.Password))
            : new HttpRequestMessage(HttpMethod.Post, "/auth/token/longlived");
        if (route == "longlived")
            request.Headers.Authorization = new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(login.UserName + ":" + login.Password)));
        using var absent = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NotFound, absent.StatusCode);
        var body = await absent.Content.ReadAsStringAsync();
        Assert.DoesNotContain(login.UserName, body, StringComparison.Ordinal);
        Assert.DoesNotContain(login.Password, body, StringComparison.Ordinal);
        Assert.DoesNotContain("accessToken", body, StringComparison.Ordinal);
        if (request.Headers.Authorization is not null)
            Assert.DoesNotContain(request.Headers.Authorization.Parameter!, body, StringComparison.Ordinal);
        Assert.Equal(identities, await SnapshotIdentitiesAsync(stores));
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
        var tokens = await LoginAsync(client, IdentityKind.Employee);
        Assert.Equal("employee", Assert.Single(ReadJwt(tokens.AccessToken, factory).Claims, claim => claim.Type == "identity_kind").Value);
        Assert.Single(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    private static async Task<string> SnapshotIdentitiesAsync(Stores stores) => JsonSerializer.Serialize(new
    {
        Employees = await stores.Employees.Users.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
        Customers = await stores.Customers.Users.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
    });

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
        Assert.Equal(ClaimTypes.Role, Assert.IsAssignableFrom<ClaimsIdentity>(principal.Identity).RoleClaimType);
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

    [Fact]
    public async Task NormalIssuer_UndefinedInteractiveKind_RefusesBeforeIssuance()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        await using var scope = factory.Services.CreateAsyncScope();
        var identity = await scope.ServiceProvider.GetRequiredService<ILegacyIdentityReader>()
            .FindActiveAsync("issuance-employee", IdentityKind.Employee, default);
        Assert.NotNull(identity);
        var issuer = scope.ServiceProvider.GetRequiredService<IAccessTokenIssuer>();
        Assert.Throws<ArgumentOutOfRangeException>(() => issuer.Issue(
            identity with { Kind = (IdentityKind)42 }, DateTimeOffset.UtcNow, null));
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
        try
        {
            await app.StartAsync();
            return app;
        }
        catch
        {
            await app.DisposeAsync();
            throw;
        }
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

    private sealed class Factory(Stores stores, RejectSave? fault = null, bool identityAdministration = false) : WebApplicationFactory<Program>
    {
        public const string ServiceSecret = "issuance-test-only-secret-0123456789";
        private readonly RSA signing = RSA.Create(2048);
        public string PublicKey => signing.ExportSubjectPublicKeyInfoPem();
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                var settings = new Dictionary<string, string?>
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
                };
                if (identityAdministration)
                {
                    settings["ServiceClients:Clients:issuance-test:Permissions:1"] = LegacyAccessTokenPermissions.CustomerIdentitiesReconcileCreate;
                    settings["ServiceClients:Clients:issuance-test:Permissions:2"] = CustomerSelfServicePermissions.Use;
                }
                configuration.AddInMemoryCollection(settings);
            });
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
