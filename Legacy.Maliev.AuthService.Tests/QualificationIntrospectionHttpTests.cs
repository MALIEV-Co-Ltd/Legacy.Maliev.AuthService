using System.Net;
using System.Data.Common;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Routing;
using Legacy.Maliev.AuthService.Api.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class QualificationIntrospectionHttpTests(PostgresFixture postgres)
{
    private const string Route = "/auth/v1/introspection/quotation-qualification";

    [Theory]
    [InlineData("permission")]
    [InlineData("purpose")]
    [InlineData("resource")]
    public async Task DirectService_UnsupportedRequestNeverAllowsOrReadsAuthority(string invalid)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var read = new AuthorityRead { Fail = true };
        await using var factory = new Factory(stores, read: read);
        using var client = factory.CreateClient();
        var employee = await EmployeeAsync(client);
        using var scope = factory.Services.CreateScope();
        var authority = scope.ServiceProvider.GetRequiredService<IQualificationIntrospectionService>();
        var request = new QualificationIntrospectionRequest(employee.AccessToken, invalid == "permission" ? "global.other" : "legacy.quotation-requests.update", invalid == "purpose" ? "other-purpose" : "quotation-request-qualification", invalid == "resource" ? 0 : 84);
        Assert.False((await authority.EvaluateAsync(request, default)).Allowed);
        read.Enabled = true;
        Assert.False((await authority.EvaluateAsync(request, default)).Allowed);
        Assert.False(read.Injected);
    }

    [Fact]
    public async Task DirectService_NullRequestIsExplicitArgumentFailure()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        using var scope = factory.Services.CreateScope();
        await Assert.ThrowsAsync<ArgumentNullException>(() => scope.ServiceProvider.GetRequiredService<IQualificationIntrospectionService>().EvaluateAsync(null!, default));
    }

    [Fact]
    public async Task DirectActionFilter_ValidatedPrincipalWithoutLocalAdmissionProof_IsDenied()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        var employee = await EmployeeAsync(client);
        var caller = await CallerAsync(client);
        var normal = factory.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);
        var validation = await normal.TokenHandlers.Single().ValidateTokenAsync(caller, normal.TokenValidationParameters);
        Assert.True(validation.IsValid);
        var http = new DefaultHttpContext { User = new ClaimsPrincipal(validation.ClaimsIdentity) };
        var action = new ActionContext(http, new RouteData(), new ActionDescriptor(), new ModelStateDictionary());
        var context = new ActionExecutingContext(action, [], new Dictionary<string, object?> { ["request"] = new QualificationIntrospectionRequest(employee.AccessToken, "legacy.quotation-requests.update", "quotation-request-qualification", 84) }, new object());
        using var scope = factory.Services.CreateScope();
        scope.ServiceProvider.GetRequiredService<QualificationIntrospectionBoundaryFilter>().OnActionExecuting(context);
        Assert.Equal(401, Assert.IsType<ObjectResult>(context.Result).StatusCode);
    }

    [Fact]
    public async Task ExactDedicatedCapabilityWithOtherOrdinaryConfiguredGrant_PreservesAdmission()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores, additionalGrant: "legacy-contact.messages.create");
        using var client = factory.CreateClient();
        var employee = await EmployeeAsync(client);
        using var response = await SendAsync(client, await CallerAsync(client), employee.AccessToken);
        await AssertDecisionAsync(response, true);
    }

    [Theory]
    [InlineData("customer")]
    [InlineData("other-service")]
    [InlineData("invoice-capability")]
    public async Task NormalCustomerOtherWorkloadAndInvoiceCapability_CannotAdmit(string kind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores, callerPermission: kind == "invoice-capability" ? "legacy-auth.invoice-delegation.issue" : "legacy-auth.quotation-qualification.introspect");
        using var client = factory.CreateClient();
        var employee = await EmployeeAsync(client);
        string caller;
        if (kind == "customer")
        {
            using var login = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest("customer@example.com", "issuance-password", IdentityKind.Customer));
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            caller = Assert.IsType<TokenResponse>(await login.Content.ReadFromJsonAsync<TokenResponse>()).AccessToken;
        }
        else if (kind == "other-service")
        {
            using var login = await client.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest("legacy-intranet", Factory.ServiceSecret));
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            caller = Assert.IsType<ServiceTokenResponse>(await login.Content.ReadFromJsonAsync<ServiceTokenResponse>()).AccessToken;
        }
        else caller = await CallerAsync(client);
        using var response = await SendAsync(client, caller, employee.AccessToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BlankOrOverlongEmployeeToken_IsGeneric400(bool overlong)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        using var response = await SendAsync(client, await CallerAsync(client), overlong ? new string('x', 16385) : " ");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData(false, -1, true)]
    [InlineData(false, 0, false)]
    [InlineData(false, 1, false)]
    [InlineData(true, -1, true)]
    [InlineData(true, 0, false)]
    [InlineData(true, 1, false)]
    public async Task FinalFreshExpiry_UsesStrictEqualityAfterPausedAuthorityRead(bool sessionExpiry, int offsetSeconds, bool allowed)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var pause = new AuthorityRead();
        await using var factory = new Factory(stores, read: pause);
        using var client = factory.CreateClient();
        var employee = await EmployeeAsync(client);
        var caller = await CallerAsync(client);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(employee.AccessToken);
        var boundary = new DateTimeOffset(jwt.ValidTo, TimeSpan.Zero);
        if (sessionExpiry)
        {
            boundary = factory.Clock.GetUtcNow().AddSeconds(100);
            var row = await stores.State.RefreshSessions.SingleAsync();
            row.ExpiresAt = boundary;
            await stores.State.SaveChangesAsync();
        }
        pause.Enabled = true;
        var pending = SendAsync(client, caller, employee.AccessToken);
        await pause.Reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
        factory.Clock.Set(boundary.AddSeconds(offsetSeconds));
        pause.Release.TrySetResult();
        using var response = await pending;
        await AssertDecisionAsync(response, allowed);
        Assert.True(pause.Injected);
    }

    [Fact]
    public async Task KnownAuthorityStoreFailure_IsGeneric503WithoutAllowOrMutation()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var read = new AuthorityRead { Fail = true };
        await using var factory = new Factory(stores, read: read);
        using var client = factory.CreateClient();
        var employee = await EmployeeAsync(client);
        var caller = await CallerAsync(client);
        read.Enabled = true;
        using var response = await SendAsync(client, caller, employee.AccessToken);
        Assert.True(read.Injected);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("authority-store-detail", body, StringComparison.Ordinal);
        Assert.DoesNotContain(employee.AccessToken, body, StringComparison.Ordinal);
        Assert.DoesNotContain("allowed", body, StringComparison.Ordinal);
        Assert.Equal(1, await stores.State.RefreshSessions.CountAsync());
    }

    [Fact]
    public async Task CallerCancellation_DuringAuthorityReadPropagatesWithoutDecisionOrMutation()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var pause = new AuthorityRead();
        await using var factory = new Factory(stores, read: pause);
        using var client = factory.CreateClient();
        var employee = await EmployeeAsync(client);
        var caller = await CallerAsync(client);
        using var abort = new CancellationTokenSource();
        pause.Enabled = true;
        var pending = SendAsync(client, caller, employee.AccessToken, cancellationToken: abort.Token);
        await pause.Reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
        abort.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => { using var response = await pending; });
        Assert.True(pause.Injected);
        Assert.Equal(1, await stores.State.RefreshSessions.CountAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ChangeAfterCorrespondingRead_IsPointInTimeOnly_NextUncachedDecisionDenies(bool revoke)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var pause = new AuthorityRead { AfterRead = true };
        await using var factory = new Factory(stores, read: pause);
        using var client = factory.CreateClient();
        var employee = await EmployeeAsync(client);
        var caller = await CallerAsync(client);
        pause.Enabled = true;
        var pending = SendAsync(client, caller, employee.AccessToken);
        await pause.Reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
        if (revoke)
        {
            using var scope = factory.Services.CreateScope();
            await scope.ServiceProvider.GetRequiredService<IRefreshSessionStore>().RevokeFamilyAsync(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(employee.RefreshToken))), DateTimeOffset.UtcNow, default);
        }
        else
        {
            var identity = await stores.Employees.Users.SingleAsync();
            identity.SecurityStamp = "changed-after-identity-read";
            await stores.Employees.SaveChangesAsync();
        }
        pause.Release.TrySetResult();
        using (var inflight = await pending) await AssertDecisionAsync(inflight, true);
        pause.Enabled = false;
        using var next = await SendAsync(client, caller, employee.AccessToken);
        await AssertDecisionAsync(next, false);
    }

    [Fact]
    public async Task NormalIssuedTokenInsideOrdinarySkew_IsStillDeniedAtExplicitBridgeExpiry()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        factory.Clock.Set(DateTimeOffset.UtcNow.AddSeconds(-901));
        using var client = factory.CreateClient();
        var employee = await EmployeeAsync(client);
        var caller = await CallerAsync(client);
        var normal = factory.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);
        var validation = await normal.TokenHandlers.Single().ValidateTokenAsync(employee.AccessToken, normal.TokenValidationParameters);
        Assert.True(validation.IsValid);
        factory.Clock.Set(DateTimeOffset.UtcNow);
        using var response = await SendAsync(client, caller, employee.AccessToken);
        await AssertDecisionAsync(response, false);
    }

    [Theory]
    [InlineData("permission", 403)]
    [InlineData("client", 403)]
    [InlineData("invalid", 503)]
    public async Task RequestCurrentReload_RechecksEarlierNormalWorkloadToken(string change, int status)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        var employee = await EmployeeAsync(client);
        var caller = await CallerAsync(client);
        using (var before = await SendAsync(client, caller, employee.AccessToken)) await AssertDecisionAsync(before, true);
        factory.Configuration.Reload(change);
        using var after = await SendAsync(client, caller, employee.AccessToken);
        Assert.Equal(status, (int)after.StatusCode);
        Assert.DoesNotContain("Secret", await after.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DedicatedLimiter_WrongCallersDoNotConsumeAuthenticatedPartition_ZeroQueueResets()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores, permitLimit: 2);
        using var client = factory.CreateClient();
        var employee = await EmployeeAsync(client);
        var caller = await CallerAsync(client);
        for (var i = 0; i < 3; i++)
        { using var wrong = await SendAsync(client, employee.AccessToken, employee.AccessToken); Assert.Equal(HttpStatusCode.Forbidden, wrong.StatusCode); }
        for (var i = 0; i < 2; i++)
        { using var allowed = await SendAsync(client, caller, employee.AccessToken); await AssertDecisionAsync(allowed, true); }
        using (var rejected = await SendAsync(client, caller, employee.AccessToken)) Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        factory.Clock.Advance(TimeSpan.FromSeconds(60));
        using var reset = await SendAsync(client, caller, employee.AccessToken);
        await AssertDecisionAsync(reset, true);
    }

    [Theory]
    [InlineData("alias")]
    [InlineData("duplicate-sub")]
    [InlineData("wildcard")]
    [InlineData("duplicate-capability")]
    public async Task NegativeSignedWorkloadAuthority_FailsClosed(string mutation)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        var employee = await EmployeeAsync(client);
        var negative = factory.NegativeToken(await CallerAsync(client), mutation);
        if (mutation == "duplicate-sub")
        {
            var normal = factory.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);
            var validation = await normal.TokenHandlers.Single().ValidateTokenAsync(negative, normal.TokenValidationParameters);
            Assert.False(validation.IsValid);
            Assert.IsType<ArgumentException>(validation.Exception);
        }
        using var response = await SendAsync(client, negative, employee.AccessToken);
        Assert.Equal(mutation == "duplicate-sub" ? HttpStatusCode.Unauthorized : HttpStatusCode.Forbidden, response.StatusCode);
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
    [InlineData("family-revoked")]
    public async Task FreshInvalidAuthority_DeniesWithoutAlternateSessionOrPositiveCache(string mutation)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        var employee = await EmployeeAsync(client);
        var caller = await CallerAsync(client);
        using (var before = await SendAsync(client, caller, employee.AccessToken)) await AssertDecisionAsync(before, true);
        var row = await stores.State.RefreshSessions.SingleAsync();
        var identity = await stores.Employees.Users.SingleAsync();
        switch (mutation)
        {
            case "revoked": row.RevokedAt = DateTimeOffset.UtcNow; break;
            case "expired": row.ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1); break;
            case "kind": row.IdentityKind = IdentityKind.Customer; break;
            case "owner": row.IdentityId = "another-employee"; break;
            case "stamp": identity.SecurityStamp = "changed"; break;
            case "empty-stamp": row.SecurityStamp = ""; break;
            case "unconfirmed": identity.EmailConfirmed = false; break;
            case "locked": identity.LockoutEnd = DateTimeOffset.UtcNow.AddHours(1); break;
            case "deleted": stores.Employees.Users.Remove(identity); break;
            case "family-revoked":
                stores.State.RefreshSessions.Add(new RefreshSession { Id = Guid.NewGuid(), FamilyId = row.FamilyId, IdentityId = row.IdentityId, IdentityKind = IdentityKind.Employee, SecurityStamp = row.SecurityStamp, TokenHash = new string('B', 64), CreatedAt = row.CreatedAt, ExpiresAt = row.ExpiresAt, RevokedAt = DateTimeOffset.UtcNow });
                break;
        }
        await stores.Employees.SaveChangesAsync();
        await stores.State.SaveChangesAsync();
        // Another active family cannot rescue the exact binding.
        stores.State.RefreshSessions.Add(new RefreshSession { Id = Guid.NewGuid(), FamilyId = Guid.NewGuid(), IdentityId = "issuance-employee", IdentityKind = IdentityKind.Employee, SecurityStamp = "issuance-stamp", TokenHash = new string('C', 64), CreatedAt = DateTimeOffset.UtcNow, ExpiresAt = DateTimeOffset.UtcNow.AddDays(1) });
        await stores.State.SaveChangesAsync();
        using var after = await SendAsync(client, caller, employee.AccessToken);
        await AssertDecisionAsync(after, false);
    }

    [Fact]
    public async Task RealRotation_PreservesOldBoundAccessUntilFamilyRevocation_DeniesBothAfterward()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        var original = await EmployeeAsync(client);
        var caller = await CallerAsync(client);
        using var refresh = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(original.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
        var replacement = Assert.IsType<TokenResponse>(await refresh.Content.ReadFromJsonAsync<TokenResponse>());
        foreach (var token in new[] { original.AccessToken, replacement.AccessToken })
        { using var response = await SendAsync(client, caller, token); await AssertDecisionAsync(response, true); }
        using (var scope = factory.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<IRefreshSessionStore>().RevokeFamilyAsync(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(original.RefreshToken))), DateTimeOffset.UtcNow, default);
        foreach (var token in new[] { original.AccessToken, replacement.AccessToken })
        { using var response = await SendAsync(client, caller, token); await AssertDecisionAsync(response, false); }
    }

    [Theory]
    [InlineData("no-sid")]
    [InlineData("duplicate-sid")]
    [InlineData("noncanonical-sid")]
    [InlineData("kind")]
    [InlineData("duplicate-sub")]
    [InlineData("alias")]
    [InlineData("issuer")]
    [InlineData("audience")]
    [InlineData("signature")]
    [InlineData("algorithm")]
    [InlineData("no-expiry")]
    [InlineData("expired")]
    [InlineData("empty-sid")]
    [InlineData("duplicate-kind")]
    public async Task NegativeSignedEmployeeShapes_DoNotBecomeAuthority(string mutation)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        var employee = await EmployeeAsync(client);
        var negative = factory.NegativeToken(employee.AccessToken, mutation);
        using var response = await SendAsync(client, await CallerAsync(client), negative);
        await AssertDecisionAsync(response, false);
    }

    private static async Task AssertDecisionAsync(HttpResponseMessage response, bool allowed)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(allowed, body.GetProperty("allowed").GetBoolean());
        Assert.Equal(allowed ? "issuance-employee" : null, body.GetProperty("subject").GetString());
        Assert.Equal(5, body.EnumerateObject().Count());
        Assert.True(response.Headers.CacheControl?.NoStore);
    }

    [Theory]
    [InlineData("legacy.quotation-requests.read")]
    [InlineData("legacy.quotation-requests.update")]
    public async Task ExactNormalCallerAndBoundEmployee_ReturnFiveFieldUncachedAllow(string permission)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        var employee = await EmployeeAsync(client);
        var caller = await CallerAsync(client);
        using var response = await SendAsync(client, caller, employee.AccessToken, permission);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(["allowed", "permission", "purpose", "requestId", "subject"], body.EnumerateObject().Select(x => x.Name).Order().ToArray());
        Assert.True(body.GetProperty("allowed").GetBoolean());
        Assert.Equal("issuance-employee", body.GetProperty("subject").GetString());
        Assert.Equal(permission, body.GetProperty("permission").GetString());
        Assert.Equal("quotation-request-qualification", body.GetProperty("purpose").GetString());
        Assert.Equal(84, body.GetProperty("requestId").GetInt32());
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.Contains(response.Headers.Pragma, value => value.Name == "no-cache");
        Assert.Equal(1, await stores.State.RefreshSessions.CountAsync());
        Assert.Equal("issuance-stamp", (await stores.Employees.Users.AsNoTracking().SingleAsync()).SecurityStamp);
    }

    [Fact]
    public async Task Disabled_PrecedesAuthenticationAndMalformedOversizedBody()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores, false);
        using var client = factory.CreateClient();
        using var response = await client.PostAsync(Route, new StringContent(new string('!', 30000), Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.True(response.Headers.CacheControl?.NoStore);
    }

    [Theory]
    [InlineData(false, 401)]
    [InlineData(true, 403)]
    public async Task MissingOrHumanCaller_IsRejectedBeforeBinding(bool human, int status)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, Route) { Content = new StringContent("{bad", Encoding.UTF8, "application/json") };
        if (human) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", (await EmployeeAsync(client)).AccessToken);
        using var response = await client.SendAsync(request);
        Assert.Equal(status, (int)response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
    }

    [Theory]
    [InlineData("{bad")]
    [InlineData("{\"employeeAccessToken\":\"a\",\"permission\":\"legacy.quotation-requests.update\",\"purpose\":\"quotation-request-qualification\",\"requestId\":84,\"actor\":\"override\"}")]
    [InlineData("{\"employeeAccessToken\":\"a\",\"permission\":\"other\",\"purpose\":\"quotation-request-qualification\",\"requestId\":84}")]
    [InlineData("{\"employeeAccessToken\":\"a\",\"permission\":\"legacy.quotation-requests.update\",\"purpose\":\"other\",\"requestId\":84}")]
    [InlineData("{\"employeeAccessToken\":\"a\",\"permission\":\"legacy.quotation-requests.update\",\"purpose\":\"quotation-request-qualification\",\"requestId\":0}")]
    public async Task InvalidInput_IsBoundedGeneric400(string json)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, Route) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await CallerAsync(client));
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("employeeAccessToken", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task OversizedKnownAndStreamingBody_Is400BeforeBinding()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        var caller = await CallerAsync(client);
        var employee = await EmployeeAsync(client);
        var json = JsonSerializer.Serialize(new { employeeAccessToken = employee.AccessToken, permission = "legacy.quotation-requests.update", purpose = "quotation-request-qualification", requestId = 84 });
        var oversizedValidJson = json + new string(' ', 24577 - Encoding.UTF8.GetByteCount(json));
        foreach (var streaming in new[] { false, true })
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, Route) { Content = streaming ? new StreamingContent(oversizedValidJson) : new StringContent(oversizedValidJson, Encoding.UTF8, "application/json") };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", caller);
            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    private sealed class StreamingContent(string text) : HttpContent
    {
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => stream.WriteAsync(Encoding.UTF8.GetBytes(text)).AsTask();
    }

    [Fact]
    public async Task UnsupportedContentType_IsGeneric400()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, Route) { Content = new StringContent("{}", Encoding.UTF8, "text/plain") };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await CallerAsync(client));
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
    private static async Task<TokenResponse> EmployeeAsync(HttpClient client)
    {
        using var response = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest("issuance@example.com", "issuance-password", IdentityKind.Employee));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return Assert.IsType<TokenResponse>(await response.Content.ReadFromJsonAsync<TokenResponse>());
    }
    private static async Task<string> CallerAsync(HttpClient client)
    {
        using var response = await client.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest("legacy-quotation", Factory.ServiceSecret));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return Assert.IsType<ServiceTokenResponse>(await response.Content.ReadFromJsonAsync<ServiceTokenResponse>()).AccessToken;
    }
    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, string caller, string employee, string permission = "legacy.quotation-requests.update", CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, Route) { Content = JsonContent.Create(new { employeeAccessToken = employee, permission, purpose = "quotation-request-qualification", requestId = 84 }) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", caller);
        return await client.SendAsync(request, cancellationToken);
    }

    private sealed class Factory(Stores stores, bool enabled = true, int permitLimit = 30, AuthorityRead? read = null, string callerPermission = "legacy-auth.quotation-qualification.introspect", string? additionalGrant = null) : WebApplicationFactory<Program>
    {
        public const string ServiceSecret = "issuance-test-only-secret-0123456789";
        private readonly RSA signing = RSA.Create(2048);
        public ControlledClock Clock { get; } = new();
        public ReloadableConfiguration Configuration { get; } = new();
        public string NegativeToken(string normal, string mutation)
        {
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(normal);
            var claims = jwt.Claims.Where(c => c.Type is not ("iss" or "aud" or "iat" or "nbf" or "exp")).ToList();
            if (mutation == "no-sid") claims.RemoveAll(c => c.Type == "sid");
            if (mutation == "duplicate-sid") claims.Add(new Claim("sid", Guid.NewGuid().ToString("D")));
            if (mutation == "noncanonical-sid") { var sid = claims.Single(c => c.Type == "sid"); claims.Remove(sid); claims.Add(new Claim("sid", sid.Value.ToUpperInvariant())); }
            if (mutation == "kind") { claims.RemoveAll(c => c.Type == "identity_kind"); claims.Add(new Claim("identity_kind", "customer")); }
            if (mutation == "duplicate-sub") claims.Add(new Claim("sub", "another"));
            if (mutation == "alias") claims.Add(new Claim(ClaimTypes.NameIdentifier, "another"));
            if (mutation == "wildcard") claims.Add(new Claim("permissions", "*"));
            if (mutation == "duplicate-capability") claims.Add(new Claim("permissions", "legacy-auth.quotation-qualification.introspect"));
            if (mutation == "empty-sid") { claims.RemoveAll(c => c.Type == "sid"); claims.Add(new Claim("sid", Guid.Empty.ToString("D"))); }
            if (mutation == "duplicate-kind") claims.Add(new Claim("identity_kind", "customer"));
            using var wrongKey = RSA.Create(2048);
            return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
                mutation == "issuer" ? "https://wrong.test" : jwt.Issuer,
                mutation == "audience" ? "wrong" : jwt.Audiences.Single(), claims,
                DateTime.UtcNow.AddMinutes(-10), mutation == "no-expiry" ? null : mutation == "expired" ? DateTime.UtcNow.AddMinutes(-1) : DateTime.UtcNow.AddMinutes(10),
                new SigningCredentials(new RsaSecurityKey(mutation == "signature" ? wrongKey : signing) { KeyId = "issuance-test" }, mutation == "algorithm" ? SecurityAlgorithms.RsaSha512 : SecurityAlgorithms.RsaSha256)));
        }
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                Configuration.Initialize(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:EmployeeIdentity"] = stores.Employees.Database.GetConnectionString(),
                    ["ConnectionStrings:CustomerIdentity"] = stores.Customers.Database.GetConnectionString(),
                    ["ConnectionStrings:RefreshSessions"] = stores.State.Database.GetConnectionString(),
                    ["Jwt:Issuer"] = "https://issuance.test",
                    ["Jwt:Audience"] = "issuance-test",
                    ["Jwt:PrivateKeyPem"] = signing.ExportPkcs8PrivateKeyPem(),
                    ["Jwt:KeyId"] = "issuance-test",
                    ["Jwt:AccessTokenLifetimeSeconds"] = "900",
                    ["QualificationIntrospection:Enabled"] = enabled.ToString(),
                    ["QualificationIntrospection:PermitLimit"] = permitLimit.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["ServiceClients:Clients:legacy-quotation:SecretSha256"] = ServiceClientCredential.HashSecret(ServiceSecret),
                    ["ServiceClients:Clients:legacy-quotation:Permissions:0"] = callerPermission,
                    ["ServiceClients:Clients:legacy-intranet:SecretSha256"] = ServiceClientCredential.HashSecret(ServiceSecret),
                    ["ServiceClients:Clients:legacy-intranet:Permissions:0"] = "legacy-auth.quotation-qualification.introspect",
                });
                if (additionalGrant is not null) Configuration.Set("ServiceClients:Clients:legacy-quotation:Permissions:1", additionalGrant);
                configuration.Add(new ReloadSource(Configuration));
            });
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(Clock);
                if (read is not null)
                {
                    services.AddDbContext<RefreshSessionDbContext>(options => options.AddInterceptors(read));
                }
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
    private sealed class ControlledClock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan amount) => now += amount;
        public void Set(DateTimeOffset value) => now = value;
    }
    private sealed class AuthorityRead : DbCommandInterceptor
    {
        public bool Enabled { get; set; }
        public bool Fail { get; init; }
        public bool AfterRead { get; init; }
        public bool Injected { get; private set; }
        public TaskCompletionSource Reached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private bool Matches(DbCommand command) => Enabled && !Injected && (AfterRead ? command.CommandText.Contains("EXISTS", StringComparison.Ordinal) : command.CommandText.Contains("refresh_sessions", StringComparison.Ordinal));
        public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            if (!AfterRead && Matches(command))
            {
                Injected = true;
                if (Fail) throw new PostgresException("authority-store-detail", "ERROR", "ERROR", "42601");
                Reached.TrySetResult();
                await Release.Task.WaitAsync(cancellationToken);
            }
            return result;
        }
        public override async ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData, DbDataReader result, CancellationToken cancellationToken = default)
        {
            if (AfterRead && Matches(command))
            {
                Injected = true;
                Reached.TrySetResult();
                await Release.Task.WaitAsync(cancellationToken);
            }
            return result;
        }
    }
    private sealed class ReloadSource(ReloadableConfiguration provider) : IConfigurationSource
    {
        public IConfigurationProvider Build(IConfigurationBuilder builder) => provider;
    }
    private sealed class ReloadableConfiguration : ConfigurationProvider
    {
        public void Initialize(Dictionary<string, string?> values) => Data = values;
        public void Reload(string change)
        {
            var next = new Dictionary<string, string?>(Data, StringComparer.OrdinalIgnoreCase);
            if (change == "permission") next.Remove("ServiceClients:Clients:legacy-quotation:Permissions:0");
            if (change == "client") foreach (var key in next.Keys.Where(x => x.StartsWith("ServiceClients:Clients:legacy-quotation:", StringComparison.Ordinal)).ToArray()) next.Remove(key);
            if (change == "invalid") next["ServiceClients:Clients:legacy-quotation:SecretSha256"] = "invalid";
            Data = next;
            try { OnReload(); }
            catch (AggregateException) when (change == "invalid") { }
        }
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
