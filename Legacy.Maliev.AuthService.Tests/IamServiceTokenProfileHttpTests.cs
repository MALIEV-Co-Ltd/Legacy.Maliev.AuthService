using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Maliev.IAMService.Api.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class IamServiceTokenProfileHttpTests
{
    private const string LiveCredential = "isolated-iam-live-credential-0123456789";

    [Theory]
    [InlineData("iam-live-profile-test", HttpStatusCode.Unauthorized)]
    [InlineData("iam-profile-test", HttpStatusCode.Forbidden)]
    public async Task IamServiceProfile_NormalHttpPreservesLegacyAndAdmitsOnlyExplicitProfile(string audience, HttpStatusCode legacyDenial)
    {
        await using var app = new Factory(iamAudience: audience);
        using var client = app.CreateClient();
        client.Timeout = TimeSpan.FromSeconds(30);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var legacy = await LoginAsync(client, "service/login", deadline.Token);
        var profile = await LoginAsync(client, "service/iam-login", deadline.Token);
        var legacyPrincipal = app.Validate(legacy.AccessToken);
        var iamPrincipal = app.Validate(profile.AccessToken, true);
        if (audience != "iam-profile-test")
            Assert.Throws<SecurityTokenInvalidAudienceException>(() => app.Validate(legacy.AccessToken, true));
        Assert.Equal("service:legacy-quotation", Assert.Single(legacyPrincipal.FindAll("sub")).Value);
        Assert.Equal("service", Assert.Single(legacyPrincipal.FindAll("identity_kind")).Value);
        Assert.DoesNotContain(legacyPrincipal.Claims, value => value.Type is "user_type" or "service_name" or "purpose" or "role" or "sid");
        Assert.Equal(new[] { "legacy.documents.render", IamServiceTokenProfile.CheckPermission }, legacyPrincipal.FindAll("permissions").Select(value => value.Value).ToArray());
        AssertProfile(iamPrincipal);
        Assert.NotEqual(Assert.Single(legacyPrincipal.FindAll("jti")).Value, Assert.Single(iamPrincipal.FindAll("jti")).Value);
        Assert.Equal(900, profile.ExpiresIn);
        using var guard = Guard();
        var oldAdmission = await guard.AcquireAsync(legacyPrincipal, "employee-target", LiveCredential, deadline.Token);
        using (oldAdmission.Lease) Assert.Equal(LivePermissionCheckDecision.Forbidden, oldAdmission.Decision);
        var admission = await guard.AcquireAsync(iamPrincipal, "employee-target", LiveCredential, deadline.Token);
        using (admission.Lease)
        {
            Assert.Equal(LivePermissionCheckDecision.Acquired, admission.Decision);
            Assert.Equal("QuotationService", admission.CallerService);
        }
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", profile.AccessToken);
        using var denied = await client.PostAsJsonAsync("/auth/v1/exchange/invoice-create",
            new { employeeSubject = "employee-target", quotationId = 42, operationId = Guid.NewGuid() }, deadline.Token);
        Assert.Equal(legacyDenial, denied.StatusCode);
    }

    [Fact]
    public async Task IamServiceProfile_ClientSuppliedClaimsCannotSelectProfile()
    {
        await using var app = new Factory();
        using var client = app.CreateClient();
        client.Timeout = TimeSpan.FromSeconds(30);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var response = await client.PostAsJsonAsync("/auth/v1/service/iam-login", new
        {
            clientId = "legacy-quotation", clientSecret = Factory.Secret,
            serviceName = "AccountingService", service_name = "AccountingService",
            sub = "system:service:accounting", role = "admin", purpose = "other",
            permissions = new[] { "*", "legacy.invoices.create" }, audience = "other", expiresIn = 86400,
        }, deadline.Token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var token = (await response.Content.ReadFromJsonAsync<ServiceTokenResponse>(deadline.Token))!;
        AssertProfile(app.Validate(token.AccessToken, true));
        Assert.Equal(900, token.ExpiresIn);
    }

    [Theory]
    [InlineData("missing-profile")]
    [InlineData("missing-permission")]
    [InlineData("wrong-secret")]
    [InlineData("unknown-client")]
    [InlineData("missing-audience")]
    public async Task IamServiceProfile_MissingEnrollmentOrWrongCredentialIsGeneric(string control)
    {
        await using var app = new Factory(control != "missing-profile", control != "missing-permission", control == "missing-audience" ? null : "iam-live-profile-test");
        using var client = app.CreateClient();
        client.Timeout = TimeSpan.FromSeconds(30);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var response = await client.PostAsJsonAsync("/auth/v1/service/iam-login",
            new ServiceLoginRequest(control == "unknown-client" ? "unknown-client" : "legacy-quotation",
                control == "wrong-secret" ? "wrong-isolated-secret-0123456789" : Factory.Secret), deadline.Token);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using var unknown = await client.PostAsJsonAsync("/auth/v1/service/iam-login",
            new ServiceLoginRequest("unknown-client", Factory.Secret), deadline.Token);
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        using var unknownBody = JsonDocument.Parse(await unknown.Content.ReadAsStringAsync(deadline.Token));
        using var responseBody = JsonDocument.Parse(await response.Content.ReadAsStringAsync(deadline.Token));
        Assert.Equal(unknownBody.RootElement.GetProperty("title").GetString(), responseBody.RootElement.GetProperty("title").GetString());
        Assert.Equal(unknownBody.RootElement.GetProperty("status").GetInt32(), responseBody.RootElement.GetProperty("status").GetInt32());
        Assert.DoesNotContain(responseBody.RootElement.EnumerateObject(), value => value.Name is "accessToken" or "refreshToken");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("wrong-isolated-live-key-0123456789")]
    public async Task IamServiceProfile_ValidJwtWithoutDedicatedLiveCredentialIsDenied(string? credential)
    {
        await using var app = new Factory();
        using var client = app.CreateClient();
        client.Timeout = TimeSpan.FromSeconds(30);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var token = await LoginAsync(client, "service/iam-login", deadline.Token);
        using var guard = Guard();
        var admission = await guard.AcquireAsync(app.Validate(token.AccessToken, true), "employee-target", credential, deadline.Token);
        using (admission.Lease) Assert.Equal(LivePermissionCheckDecision.Forbidden, admission.Decision);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Quotation")]
    [InlineData(" QuotationService")]
    [InlineData("QuotationService ")]
    [InlineData("Quota-tionService")]
    [InlineData("system:service:quotation")]
    public void IamServiceProfile_InvalidConfiguredNamesFailClosed(string serviceName)
    {
        var options = new ServiceClientOptions
        {
            Clients = { ["legacy-quotation"] = new ServiceClientCredential
            {
                SecretSha256 = ServiceClientCredential.HashSecret(Factory.Secret),
                Permissions = [IamServiceTokenProfile.CheckPermission], IamServiceName = serviceName,
            } },
        };
        Assert.True(new ServiceClientOptionsValidator().Validate(null, options).Failed);
        Assert.False(IamServiceTokenProfile.IsCanonicalServiceName(serviceName));
    }

    private static void AssertProfile(ClaimsPrincipal principal)
    {
        Assert.Equal("system:service:quotation", Assert.Single(principal.FindAll("sub")).Value);
        Assert.Equal("service:legacy-quotation", Assert.Single(principal.FindAll("azp")).Value);
        Assert.Equal("legacy-quotation", Assert.Single(principal.FindAll("name")).Value);
        Assert.Equal("service", Assert.Single(principal.FindAll("identity_kind")).Value);
        Assert.Equal("service", Assert.Single(principal.FindAll("user_type")).Value);
        Assert.Equal("QuotationService", Assert.Single(principal.FindAll("service_name")).Value);
        Assert.Equal("service-account", Assert.Single(principal.FindAll("role")).Value);
        Assert.Equal("iam-registration", Assert.Single(principal.FindAll("purpose")).Value);
        Assert.Equal(IamServiceTokenProfile.CheckPermission, Assert.Single(principal.FindAll("permissions")).Value);
        Assert.DoesNotContain(principal.Claims, value => value.Type is "sid" or "employeeId" or "legacy_database_id");
        Assert.True(Guid.TryParseExact(Assert.Single(principal.FindAll("jti")).Value, "D", out _));
    }

    private static LivePermissionCheckGuard Guard() => new(Options.Create(new LivePermissionCheckOptions
    {
        AllowedServices = ["QuotationService"],
        CredentialHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["QuotationService"] = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(LiveCredential))),
        },
    }));

    private static async Task<ServiceTokenResponse> LoginAsync(HttpClient client, string path, CancellationToken cancellationToken)
    {
        using var response = await client.PostAsJsonAsync("/auth/v1/" + path,
            new ServiceLoginRequest("legacy-quotation", Factory.Secret), cancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        Assert.Equal(new[] { "accessToken", "expiresIn", "tokenType" }, body.RootElement.EnumerateObject().Select(value => value.Name).Order().ToArray());
        var result = body.RootElement.Deserialize<ServiceTokenResponse>(new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        Assert.Equal("Bearer", result.TokenType);
        return result;
    }

    private sealed class Factory(bool enrolled = true, bool granted = true, string? iamAudience = "iam-live-profile-test") : WebApplicationFactory<Program>
    {
        public const string Secret = "isolated-iam-profile-secret-0123456789";
        private readonly RSA signing = RSA.Create(2048);
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            var settings = new Dictionary<string, string?>
            {
                ["CORS:AllowedOrigins"] = "https://localhost",
                ["ConnectionStrings:CustomerIdentity"] = "Host=127.0.0.1;Port=1;Database=unused;Username=unused",
                ["ConnectionStrings:EmployeeIdentity"] = "Host=127.0.0.1;Port=1;Database=unused;Username=unused",
                ["ConnectionStrings:RefreshSessions"] = "Host=127.0.0.1;Port=1;Database=unused;Username=unused",
                ["Jwt:Issuer"] = "https://iam-profile.test",
                ["Jwt:Audience"] = "iam-profile-test",
                ["Jwt:PrivateKeyPem"] = signing.ExportPkcs8PrivateKeyPem(),
                ["Jwt:KeyId"] = "iam-profile-test",
                ["Jwt:AccessTokenLifetimeSeconds"] = "900",
                ["ServiceClients:Clients:legacy-quotation:SecretSha256"] = ServiceClientCredential.HashSecret(Secret),
                ["ServiceClients:Clients:legacy-quotation:Permissions:0"] = "legacy.documents.render",
            };
            if (enrolled) settings["ServiceClients:Clients:legacy-quotation:IamServiceName"] = "QuotationService";
            if (granted) settings["ServiceClients:Clients:legacy-quotation:Permissions:1"] = IamServiceTokenProfile.CheckPermission;
            if (iamAudience is not null) settings["Jwt:IamAudience"] = iamAudience;
            foreach (var setting in settings) builder.UseSetting(setting.Key, setting.Value);
            // Normal Auth issuer/authentication/credential stores/authorization remain registered.
            // Service login does not open a database; no database process is created by this fixture.
        }
        public ClaimsPrincipal Validate(string token, bool iamProfile = false) => new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(token,
            new TokenValidationParameters
            {
                ValidIssuer = "https://iam-profile.test", ValidAudience = iamProfile ? iamAudience : "iam-profile-test",
                IssuerSigningKey = new RsaSecurityKey(signing) { KeyId = "iam-profile-test" },
                ValidateIssuerSigningKey = true, ValidateIssuer = true, ValidateAudience = true,
                ValidateLifetime = true, RequireSignedTokens = true, RequireExpirationTime = true,
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256], ClockSkew = TimeSpan.Zero,
                NameClaimType = "sub", RoleClaimType = "role",
            }, out _);
        public override async ValueTask DisposeAsync()
        {
            try { await base.DisposeAsync(); }
            finally { signing.Dispose(); }
        }
    }
}
