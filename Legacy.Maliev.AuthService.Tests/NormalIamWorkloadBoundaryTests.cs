using Legacy.Maliev.AuthService.Api.Authorization;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.AuthService.Tests;

[CollectionDefinition("Normal IAM workload", DisableParallelization = true)]
public sealed class NormalIamWorkloadCollection : ICollectionFixture<PostgresFixture>;

[Collection("Normal IAM workload")]
public sealed class NormalIamWorkloadBoundaryTests(PostgresFixture postgres)
{
    [Theory]
    [InlineData("password-reset")]
    [InlineData("email-confirmation")]
    public async Task NormalRecovery_CallbackRoundtripPreservesExactToken_AlteredEncodingsNeverConsumeIt(string action)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        await using var employees = await postgres.CreateEmployeeContextAsync();
        await using var customers = await postgres.CreateCustomerContextAsync();
        await using var sessions = await postgres.CreateStateContextAsync();
        var employee = new LegacyIdentityRow
        {
            Id = "callback-wire-employee",
            UserName = "employee+callback@example.test",
            NormalizedUserName = "EMPLOYEE+CALLBACK@EXAMPLE.TEST",
            Email = "employee+callback@example.test",
            NormalizedEmail = "EMPLOYEE+CALLBACK@EXAMPLE.TEST",
            EmailConfirmed = action == "password-reset",
            SecurityStamp = Guid.NewGuid().ToString("D"),
            ConcurrencyStamp = Guid.NewGuid().ToString("D"),
            LockoutEnabled = true,
        };
        employee.PasswordHash = new PasswordHasher<LegacyIdentityRow>().HashPassword(employee, "callback-original-password");
        employees.Users.Add(employee);
        await employees.SaveChangesAsync(deadline.Token);
        await using var app = new Factory(employees, customers, sessions, recovery: true);
        using var client = app.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            await app.LoginServiceAsync(client, "legacy-intranet", deadline.Token));
        const string root = "/auth/v1/employee-self-service/";
        using var issuance = await client.PostAsJsonAsync(root + action + "/request",
            new EmployeeActionRequest(employee.Email!), deadline.Token);
        Assert.Equal(HttpStatusCode.OK, issuance.StatusCode);
        var challenge = Assert.IsType<EmployeeActionChallenge>(await issuance.Content.ReadFromJsonAsync<EmployeeActionChallenge>(deadline.Token));
        var original = Assert.IsType<string>(challenge.Token);
        Assert.Equal(32, WebEncoders.Base64UrlDecode(original).Length);
        var callback = new Uri(QueryHelpers.AddQueryString("https://intranet.example.test/Employees/Callback",
            new Dictionary<string, string?> { ["email"] = employee.Email, ["token"] = original }));
        var query = QueryHelpers.ParseQuery(callback.Query);
        Assert.Equal(employee.Email, query["email"].ToString());
        Assert.Equal(original, query["token"].ToString());
        Assert.Equal(2, query.Count);
        var before = JsonSerializer.Serialize(await employees.Users.AsNoTracking().SingleAsync(deadline.Token));
        var issued = JsonSerializer.Serialize(await sessions.IdentityActionTokens.AsNoTracking().SingleAsync(deadline.Token));
        var escapedFirst = "%" + ((int)original[0]).ToString("X2") + original[1..];
        var invalid = new[]
        {
            escapedFirst,
            "%25" + escapedFirst[1..],
            WebEncoders.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(original)),
            original + "+",
            original + " ",
            "%GG" + original,
            "%" + original,
        };
        foreach (var altered in invalid)
        {
            using var rejected = await CompleteAsync(altered);
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
            var problem = await rejected.Content.ReadAsStringAsync(deadline.Token);
            Assert.DoesNotContain(original, problem, StringComparison.Ordinal);
            Assert.DoesNotContain(altered, problem, StringComparison.Ordinal);
            Assert.Equal(before, JsonSerializer.Serialize(await employees.Users.AsNoTracking().SingleAsync(deadline.Token)));
            Assert.Equal(issued, JsonSerializer.Serialize(await sessions.IdentityActionTokens.AsNoTracking().SingleAsync(deadline.Token)));
            Assert.Empty(await employees.RecoveryEffects.AsNoTracking().ToListAsync(deadline.Token));
        }
        using var completed = await CompleteAsync(query["token"].ToString());
        Assert.Equal(HttpStatusCode.NoContent, completed.StatusCode);
        var after = await employees.Users.AsNoTracking().SingleAsync(deadline.Token);
        Assert.NotEqual(employee.SecurityStamp, after.SecurityStamp);
        Assert.True(after.EmailConfirmed);
        if (action == "password-reset")
            Assert.Equal(PasswordVerificationResult.Success,
                new PasswordHasher<LegacyIdentityRow>().VerifyHashedPassword(after, after.PasswordHash!, "callback-new-password"));
        else Assert.Equal(employee.PasswordHash, after.PasswordHash);
        var receipt = Assert.Single(await employees.RecoveryEffects.AsNoTracking().ToListAsync(deadline.Token));
        Assert.NotNull(receipt.FinalizedAcknowledgedAt);
        Assert.NotNull((await sessions.IdentityActionTokens.AsNoTracking().SingleAsync(deadline.Token)).ConsumedAt);
        using var replay = await CompleteAsync(original);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.True(app.IamRequests > 0);
        Assert.True(app.WorkloadExchanges > 0);
        Assert.Equal(0, app.UnmatchedRequests);

        Task<HttpResponseMessage> CompleteAsync(string token) => action == "password-reset"
            ? client.PostAsJsonAsync(root + action + "/complete",
                new CompleteEmployeePasswordResetRequest(employee.Email!, token, "callback-new-password"), deadline.Token)
            : client.PostAsJsonAsync(root + action + "/complete",
                new CompleteEmployeeActionRequest(employee.Email!, token), deadline.Token);
    }

    [Fact]
    public async Task NormalDelegation_ConsultsActualIamThroughOwnWorkloadBeforeCurrentSessionAuthority()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        await using var employees = await postgres.CreateEmployeeContextAsync();
        await using var customers = await postgres.CreateCustomerContextAsync();
        await using var sessions = await postgres.CreateStateContextAsync();
        var employeeCredential = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        var identity = new LegacyIdentityRow
        {
            Id = "normal-iam-employee",
            UserName = "normal-iam-employee@example.test",
            NormalizedUserName = "NORMAL-IAM-EMPLOYEE@EXAMPLE.TEST",
            Email = "normal-iam-employee@example.test",
            NormalizedEmail = "NORMAL-IAM-EMPLOYEE@EXAMPLE.TEST",
            EmailConfirmed = true,
            SecurityStamp = Guid.NewGuid().ToString("D"),
            ConcurrencyStamp = Guid.NewGuid().ToString("D"),
            LockoutEnabled = true,
        };
        identity.PasswordHash = new PasswordHasher<LegacyIdentityRow>().HashPassword(identity, employeeCredential);
        employees.Users.Add(identity);
        await employees.SaveChangesAsync(deadline.Token);
        await using var app = new Factory(employees, customers, sessions);
        using var client = app.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        // Other compatibility tests use claim fallback without workload credentials.
        // Their denied standard IAM cache expires after five seconds. This isolated
        // collection waits for that real expiry without clearing or replacing it.
        await Task.Delay(TimeSpan.FromSeconds(6), deadline.Token);
        using var login = await client.PostAsJsonAsync("/auth/v1/login",
            new LoginRequest(identity.UserName, employeeCredential, IdentityKind.Employee), deadline.Token);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var employee = Assert.IsType<TokenResponse>(await login.Content.ReadFromJsonAsync<TokenResponse>(deadline.Token));
        var caller = await app.LoginServiceAsync(client, "legacy-intranet", deadline.Token);
        using var granted = await SendAsync(client, caller, employee.AccessToken, deadline.Token);
        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);
        var delegation = Assert.IsType<InvoiceDelegationTokenResponse>(
            await granted.Content.ReadFromJsonAsync<InvoiceDelegationTokenResponse>(deadline.Token));
        var delegated = app.Validate(delegation.AccessToken, InvoiceDelegationContract.Audience);
        Assert.Equal("normal-iam-employee", delegated.FindFirst("sub")?.Value);
        Assert.Equal(1, app.IamRequests);
        Assert.Equal(1, app.WorkloadExchanges);
        Assert.Equal(0, app.UnmatchedRequests);
        using var revoke = await client.PostAsJsonAsync("/auth/v1/revoke", new RevokeRequest(employee.RefreshToken), deadline.Token);
        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        Assert.NotNull((await sessions.RefreshSessions.AsNoTracking().SingleAsync(deadline.Token)).RevokedAt);
        using var revoked = await SendAsync(client, caller, employee.AccessToken, deadline.Token);
        Assert.Equal(HttpStatusCode.Unauthorized, revoked.StatusCode);
        var revokedBody = await revoked.Content.ReadAsStringAsync(deadline.Token);
        Assert.DoesNotContain("accessToken", revokedBody, StringComparison.Ordinal);
        Assert.DoesNotContain(employee.AccessToken, revokedBody, StringComparison.Ordinal);
        var unprivileged = await app.LoginServiceAsync(client, "legacy-accounting", deadline.Token);
        using var wrongCaller = await SendAsync(client, unprivileged, employee.AccessToken, deadline.Token);
        Assert.Equal(HttpStatusCode.Forbidden, wrongCaller.StatusCode);
        Assert.Equal(2, app.IamRequests);
        Assert.Equal(1, app.WorkloadExchanges);
        Assert.Equal(0, app.UnmatchedRequests);
    }

    private static Task<HttpResponseMessage> SendAsync(HttpClient client, string caller, string employee, CancellationToken token)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/auth/v1/exchange/invoice-create");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", caller);
        request.Content = JsonContent.Create(new InvoiceDelegationRequest(employee, 42, Guid.NewGuid().ToString("D")));
        return SendAndDisposeAsync(client, request, token);
    }

    private static async Task<HttpResponseMessage> SendAndDisposeAsync(HttpClient client, HttpRequestMessage request, CancellationToken token)
    {
        using (request) return await client.SendAsync(request, token);
    }

    private sealed class Factory(EmployeeIdentityDbContext employees, CustomerIdentityDbContext customers, RefreshSessionDbContext sessions, bool recovery = false)
        : WebApplicationFactory<Program>
    {
        private const string Issuer = "https://normal-iam-workload.test";
        private const string Audience = "normal-iam-workload-test";
        private readonly RSA key = RSA.Create(2048);
        private readonly Dictionary<string, string> credentials = new(StringComparer.Ordinal)
        {
            ["legacy-auth"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)),
            ["legacy-intranet"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)),
            ["legacy-accounting"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)),
        };
        public int IamRequests;
        public int WorkloadExchanges;
        public int UnmatchedRequests;
        private string RecoveryPermission => recovery ? EmployeeSelfServicePermissions.Use : LegacyAccessTokenPermissions.InvoiceDelegationIssue;

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment(recovery ? "Production" : "Testing");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.UseSetting("Services:IAMService:BaseUrl", "https://normal-iam-workload.invalid");
            builder.UseSetting("Services:Auth:BaseUrl", "https://normal-auth-workload.invalid");
            var configuration = new Dictionary<string, string?>
            {
                ["ConnectionStrings:EmployeeIdentity"] = employees.Database.GetConnectionString(),
                ["ConnectionStrings:CustomerIdentity"] = customers.Database.GetConnectionString(),
                ["ConnectionStrings:RefreshSessions"] = sessions.Database.GetConnectionString(),
                ["Jwt:Issuer"] = Issuer,
                ["Jwt:Audience"] = Audience,
                ["Jwt:PrivateKeyPem"] = key.ExportPkcs8PrivateKeyPem(),
                ["Jwt:KeyId"] = "normal-iam-workload-test",
                ["ServiceAuthentication:ClientId"] = "legacy-auth",
                ["ServiceAuthentication:ClientSecret"] = credentials["legacy-auth"],
                ["ServiceClients:Clients:legacy-intranet:Permissions:0"] = recovery ? EmployeeSelfServicePermissions.Use : LegacyAccessTokenPermissions.InvoiceDelegationIssue,
                ["EmployeeRecovery:Enabled"] = recovery.ToString(),
            };
            foreach (var pair in credentials)
                configuration[$"ServiceClients:Clients:{pair.Key}:SecretSha256"] = ServiceClientCredential.HashSecret(pair.Value);
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(configuration));
            // Only upstream transport is controlled. Normal Program owns the actual
            // auth services, issuer, session store, permission handler and IAM client.
            builder.ConfigureTestServices(services => services.PostConfigureAll<HttpClientFactoryOptions>(options =>
                options.HttpMessageHandlerBuilderActions.Add(http => http.PrimaryHandler = new Upstream(this))));
        }

        public async Task<string> LoginServiceAsync(HttpClient client, string clientId, CancellationToken token)
        {
            using var response = await client.PostAsJsonAsync("/auth/v1/service/login",
                new ServiceLoginRequest(clientId, credentials[clientId]), token);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return Assert.IsType<ServiceTokenResponse>(await response.Content.ReadFromJsonAsync<ServiceTokenResponse>(token)).AccessToken;
        }

        public System.Security.Claims.ClaimsPrincipal Validate(string token, string audience) =>
            new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = Issuer,
                ValidateAudience = true,
                ValidAudience = audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new RsaSecurityKey(key),
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            }, out _);

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing) key.Dispose();
        }

        private sealed class Upstream(Factory app) : HttpMessageHandler
        {
            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
            {
                var uri = request.RequestUri;
                if (uri?.Host == "normal-auth-workload.invalid" && uri.AbsolutePath == "/auth/v1/service/login" && request.Method == HttpMethod.Post)
                {
                    using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                    Assert.Equal("legacy-auth", body.RootElement.GetProperty("clientId").GetString());
                    Assert.True(string.Equals(app.credentials["legacy-auth"], body.RootElement.GetProperty("clientSecret").GetString(),
                        StringComparison.Ordinal), "Synthetic workload credential contract mismatch.");
                    using var transport = new HttpMessageInvoker(app.Server.CreateHandler());
                    var response = await transport.SendAsync(request, token);
                    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                    Interlocked.Increment(ref app.WorkloadExchanges);
                    return response;
                }
                if (uri?.Host == "normal-iam-workload.invalid" && uri.AbsolutePath == "/iam/v1/auth/check-permission" && request.Method == HttpMethod.Post)
                {
                    var workload = app.Validate(Assert.IsType<string>(request.Headers.Authorization?.Parameter), Audience);
                    Assert.Equal("service:legacy-auth", workload.FindFirst("sub")?.Value);
                    Assert.Equal("service", workload.FindFirst("identity_kind")?.Value);
                    using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                    var root = body.RootElement;
                    var permission = app.RecoveryPermission;
                    Assert.Equal(permission, root.GetProperty("permissionId").GetString());
                    Assert.Equal("global", root.GetProperty("resourcePath").GetString());
                    Assert.False(root.GetProperty("bypassCache").GetBoolean());
                    Assert.False(request.Headers.Contains("X-Maliev-IAM-Live-Check-Key"));
                    var principal = root.GetProperty("principalId").GetString();
                    var allowed = principal == "service:legacy-intranet";
                    Interlocked.Increment(ref app.IamRequests);
                    return new(HttpStatusCode.OK)
                    {
                        Content = JsonContent.Create(new
                        {
                            principalId = principal,
                            permissionId = permission,
                            resourcePath = "global",
                            allowed,
                            fromCache = false,
                            latencyMs = 0
                        }),
                    };
                }
                Interlocked.Increment(ref app.UnmatchedRequests);
                throw new InvalidOperationException("Unmatched synthetic upstream refused before send.");
            }
        }
    }
}
