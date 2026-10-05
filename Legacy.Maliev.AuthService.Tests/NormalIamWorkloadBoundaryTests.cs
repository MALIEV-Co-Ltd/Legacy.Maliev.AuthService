using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
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

    private sealed class Factory(EmployeeIdentityDbContext employees, CustomerIdentityDbContext customers, RefreshSessionDbContext sessions)
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

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.UseSetting("Services:IAMService:BaseUrl", "https://normal-iam-workload.invalid");
            builder.UseSetting("Services:Auth:BaseUrl", "https://normal-auth-workload.invalid");
            var configuration = new Dictionary<string, string?>
            {
                ["ConnectionStrings:EmployeeIdentity"] = employees.Database.GetConnectionString(),
                ["ConnectionStrings:CustomerIdentity"] = customers.Database.GetConnectionString(),
                ["ConnectionStrings:RefreshSessions"] = sessions.Database.GetConnectionString(),
                ["Jwt:Issuer"] = Issuer, ["Jwt:Audience"] = Audience,
                ["Jwt:PrivateKeyPem"] = key.ExportPkcs8PrivateKeyPem(), ["Jwt:KeyId"] = "normal-iam-workload-test",
                ["ServiceAuthentication:ClientId"] = "legacy-auth",
                ["ServiceAuthentication:ClientSecret"] = credentials["legacy-auth"],
                ["ServiceClients:Clients:legacy-intranet:Permissions:0"] = LegacyAccessTokenPermissions.InvoiceDelegationIssue,
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
                ValidateIssuer = true, ValidIssuer = Issuer,
                ValidateAudience = true, ValidAudience = audience,
                ValidateIssuerSigningKey = true, IssuerSigningKey = new RsaSecurityKey(key),
                ValidateLifetime = true, ClockSkew = TimeSpan.Zero,
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
                    Assert.Equal(LegacyAccessTokenPermissions.InvoiceDelegationIssue, root.GetProperty("permissionId").GetString());
                    Assert.Equal("global", root.GetProperty("resourcePath").GetString());
                    Assert.False(root.GetProperty("bypassCache").GetBoolean());
                    Assert.False(request.Headers.Contains("X-Maliev-IAM-Live-Check-Key"));
                    var principal = root.GetProperty("principalId").GetString();
                    var allowed = principal == "service:legacy-intranet";
                    Interlocked.Increment(ref app.IamRequests);
                    return new(HttpStatusCode.OK)
                    {
                        Content = JsonContent.Create(new { principalId = principal, permissionId = LegacyAccessTokenPermissions.InvoiceDelegationIssue,
                            resourcePath = "global", allowed, fromCache = false, latencyMs = 0 }),
                    };
                }
                Interlocked.Increment(ref app.UnmatchedRequests);
                throw new InvalidOperationException("Unmatched synthetic upstream refused before send.");
            }
        }
    }
}
