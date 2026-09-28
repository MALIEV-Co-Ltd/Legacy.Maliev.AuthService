using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Api.Controllers;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Reflection;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class InvoiceDelegationContractTests : IClassFixture<InvoiceDelegationContractTests.AuthApiFactory>
{
    private static readonly Guid OperationId = Guid.Parse("7a630e38-9dd6-4f31-b790-98679e056415");
    private readonly AuthApiFactory factory;

    public InvoiceDelegationContractTests(AuthApiFactory factory) => this.factory = factory;

    [Fact]
    public void Endpoint_IsServiceOnlyAndRequiresDedicatedGrant()
    {
        var controller = typeof(InvoiceDelegationController);
        Assert.Equal("auth/v1/exchange/invoice-create", controller.GetCustomAttribute<RouteAttribute>()?.Template);
        Assert.Equal("LegacyService", controller.GetCustomAttribute<AuthorizeAttribute>()?.Policy);
        var exchange = controller.GetMethod(nameof(InvoiceDelegationController.Exchange))!;
        Assert.NotNull(exchange.GetCustomAttribute<HttpPostAttribute>());
        Assert.Equal(
            LegacyAccessTokenPermissions.InvoiceDelegationIssue,
            exchange.GetCustomAttribute<RequirePermissionAttribute>()?.Permission);
    }

    [Fact]
    public async Task ValidDualCredential_IssuesSignedMinimalAccountingOnlyToken()
    {
        var employee = factory.IssueEmployee("employee-7");
        using var response = await SendAsync(factory.IssueService(), employee, OperationId.ToString("D"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var issued = await response.Content.ReadFromJsonAsync<InvoiceDelegationTokenResponse>();
        Assert.NotNull(issued);
        Assert.Equal("Bearer", issued.TokenType);
        Assert.Equal(InvoiceDelegationContract.LifetimeSeconds, issued.ExpiresIn);

        var token = new JwtSecurityTokenHandler().ReadJwtToken(issued.AccessToken);
        Assert.Equal(SecurityAlgorithms.RsaSha256, token.Header.Alg);
        Assert.Equal(factory.KeyId, token.Header.Kid);
        Assert.Equal(factory.Issuer, token.Issuer);
        Assert.Equal([InvoiceDelegationContract.Audience], token.Audiences);
        Assert.Equal("employee-7", token.Subject);
        Assert.Equal(InvoiceDelegationContract.IntranetServiceSubject, Claim(token, "azp"));
        Assert.Equal(InvoiceDelegationContract.Scope, Claim(token, "scope"));
        Assert.Equal("84", Claim(token, "quotation_id"));
        Assert.Equal(OperationId.ToString("D"), Claim(token, "operation_id"));
        Assert.True(Guid.TryParseExact(Claim(token, JwtRegisteredClaimNames.Jti), "D", out _));
        var issuedAt = long.Parse(Claim(token, JwtRegisteredClaimNames.Iat));
        var notBefore = long.Parse(Claim(token, JwtRegisteredClaimNames.Nbf));
        var expires = long.Parse(Claim(token, JwtRegisteredClaimNames.Exp));
        Assert.Equal(issuedAt, notBefore);
        Assert.Equal(InvoiceDelegationContract.LifetimeSeconds, expires - issuedAt);
        Assert.InRange((token.ValidTo - token.ValidFrom).TotalSeconds, 119, 120);
        Assert.DoesNotContain(token.Claims, claim => claim.Type is "name" or "email" or "permissions" or "legacy_database_id" or "employee_access_token");
        Assert.DoesNotContain("employee@maliev.com", issued.AccessToken, StringComparison.Ordinal);
        factory.ValidateDelegation(issued.AccessToken);
    }

    [Fact]
    public async Task MissingOrUnapprovedServiceCredential_CannotExchangeEmployeeToken()
    {
        var employee = factory.IssueEmployee("employee-7");
        using var missing = await SendAsync(null, employee, OperationId.ToString("D"));
        using var unpermitted = await SendAsync(factory.IssueService(permissions: []), employee, OperationId.ToString("D"));
        using var otherClient = await SendAsync(factory.IssueService(clientId: "legacy-web"), employee, OperationId.ToString("D"));

        Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, unpermitted.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, otherClient.StatusCode);
    }

    [Fact]
    public async Task InvalidEmployeeTokens_AreRejectedWithoutEchoingCredential()
    {
        var now = DateTimeOffset.UtcNow;
        var invalid = new[]
        {
            "not-a-jwt",
            factory.IssueEmployee("customer-7", kind: IdentityKind.Customer),
            factory.IssueCustomEmployee("employee-7", includeAccountingPermission: false),
            factory.IssueCustomEmployee("employee-7", issuer: "https://wrong-issuer.test"),
            factory.IssueCustomEmployee("employee-7", audience: "wrong-audience"),
            factory.IssueCustomEmployee("employee-7", notBefore: now.AddMinutes(-10), expires: now.AddMinutes(-5)),
            factory.IssueCustomEmployee("employee-7", notBefore: now.AddMinutes(5), expires: now.AddMinutes(10)),
            factory.IssueCustomEmployee("employee-7", useForeignKey: true),
            factory.IssueCustomEmployee("employee-7", useHmac: true),
        };

        foreach (var employeeToken in invalid)
        {
            using var response = await SendAsync(factory.IssueService(), employeeToken, OperationId.ToString("D"));
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            var body = await response.Content.ReadAsStringAsync();
            Assert.DoesNotContain(employeeToken, body, StringComparison.Ordinal);
            Assert.DoesNotContain("employee-7", body, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("7A630E38-9DD6-4F31-B790-98679E056415")]
    [InlineData("not-a-guid")]
    public async Task InvalidOperation_IsRejectedBeforeIssuing(string operationId)
    {
        using var response = await SendAsync(factory.IssueService(), factory.IssueEmployee("employee-7"), operationId);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task RenewedSameOperation_UsesFreshJtiWithoutChangingBoundActorOrOperation()
    {
        var employee = factory.IssueEmployee("employee-7");
        using var first = await SendAsync(factory.IssueService(), employee, OperationId.ToString("D"));
        using var second = await SendAsync(factory.IssueService(), employee, OperationId.ToString("D"));
        var firstToken = new JwtSecurityTokenHandler().ReadJwtToken((await first.Content.ReadFromJsonAsync<InvoiceDelegationTokenResponse>())!.AccessToken);
        var secondToken = new JwtSecurityTokenHandler().ReadJwtToken((await second.Content.ReadFromJsonAsync<InvoiceDelegationTokenResponse>())!.AccessToken);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.NotEqual(Claim(firstToken, JwtRegisteredClaimNames.Jti), Claim(secondToken, JwtRegisteredClaimNames.Jti));
        Assert.Equal(firstToken.Subject, secondToken.Subject);
        Assert.Equal(Claim(firstToken, "operation_id"), Claim(secondToken, "operation_id"));
    }

    [Fact]
    public async Task SameOperationWithDifferentEmployee_DerivesEachSubjectOnlyFromValidatedToken()
    {
        using var first = await SendAsync(factory.IssueService(), factory.IssueEmployee("employee-7"), OperationId.ToString("D"));
        using var second = await SendAsync(factory.IssueService(), factory.IssueEmployee("employee-8"), OperationId.ToString("D"));
        var firstToken = new JwtSecurityTokenHandler().ReadJwtToken((await first.Content.ReadFromJsonAsync<InvoiceDelegationTokenResponse>())!.AccessToken);
        var secondToken = new JwtSecurityTokenHandler().ReadJwtToken((await second.Content.ReadFromJsonAsync<InvoiceDelegationTokenResponse>())!.AccessToken);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal("employee-7", firstToken.Subject);
        Assert.Equal("employee-8", secondToken.Subject);
        Assert.Equal(Claim(firstToken, "operation_id"), Claim(secondToken, "operation_id"));
    }

    private async Task<HttpResponseMessage> SendAsync(string? serviceToken, string employeeToken, string operationId)
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri("https://localhost"),
        });
        if (serviceToken is not null) client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", serviceToken);
        return await client.PostAsJsonAsync("/auth/v1/exchange/invoice-create", new InvoiceDelegationRequest(employeeToken, 84, operationId));
    }

    private static string Claim(JwtSecurityToken token, string type) => Assert.Single(token.Claims, claim => claim.Type == type).Value;

    public sealed class AuthApiFactory : WebApplicationFactory<Program>
    {
        private readonly string privateKeyPem;
        private readonly RsaAccessTokenIssuer issuer;

        public AuthApiFactory()
        {
            using var rsa = RSA.Create(2048);
            privateKeyPem = rsa.ExportPkcs8PrivateKeyPem();
            issuer = new RsaAccessTokenIssuer(Options.Create(JwtSettings()));
        }

        public string Issuer => "https://auth.delegation.test";
        public string KeyId => "delegation-test-key";

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:CustomerIdentity"] = "Host=localhost;Database=unused;Username=unused;Password=unused",
                ["ConnectionStrings:EmployeeIdentity"] = "Host=localhost;Database=unused;Username=unused;Password=unused",
                ["ConnectionStrings:RefreshSessions"] = "Host=localhost;Database=unused;Username=unused;Password=unused",
                ["Jwt:Issuer"] = Issuer,
                ["Jwt:Audience"] = "legacy-access-test",
                ["Jwt:PrivateKeyPem"] = privateKeyPem,
                ["Jwt:KeyId"] = KeyId,
                ["Jwt:AccessTokenLifetimeSeconds"] = "900",
            }));
        }

        public string IssueService(string clientId = "legacy-intranet", IReadOnlyList<string>? permissions = null) =>
            issuer.IssueService(clientId, permissions ?? [LegacyAccessTokenPermissions.InvoiceDelegationIssue], DateTimeOffset.UtcNow).Value;

        public string IssueEmployee(string subject, IdentityKind kind = IdentityKind.Employee) =>
            issuer.Issue(new LegacyIdentity(subject, "employee@maliev.com", "employee@maliev.com", kind, 7, "stamp"), DateTimeOffset.UtcNow).Value;

        public string IssueCustomEmployee(
            string subject,
            bool includeAccountingPermission = true,
            string? issuer = null,
            string? audience = null,
            DateTimeOffset? notBefore = null,
            DateTimeOffset? expires = null,
            bool useForeignKey = false,
            bool useHmac = false)
        {
            var now = DateTimeOffset.UtcNow;
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, subject),
                new(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new("identity_kind", "employee"),
            };
            if (includeAccountingPermission) claims.Add(new("permissions", LegacyAccessTokenPermissions.AccountingCreate));
            using var rsa = RSA.Create(2048);
            SigningCredentials credentials;
            if (useHmac)
            {
                credentials = new SigningCredentials(new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)), SecurityAlgorithms.HmacSha256);
            }
            else
            {
                rsa.ImportFromPem(useForeignKey ? CreateForeignKey() : privateKeyPem);
                credentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);
            }
            var token = new JwtSecurityToken(
                issuer ?? Issuer,
                audience ?? "legacy-access-test",
                claims,
                (notBefore ?? now.AddSeconds(-1)).UtcDateTime,
                (expires ?? now.AddMinutes(10)).UtcDateTime,
                credentials);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public void ValidateDelegation(string token)
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem);
            new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = Issuer,
                ValidateAudience = true,
                ValidAudience = InvoiceDelegationContract.Audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new RsaSecurityKey(rsa),
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
                ValidateLifetime = true,
            }, out _);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) issuer.Dispose();
            base.Dispose(disposing);
        }

        private JwtOptions JwtSettings() => new()
        {
            Issuer = Issuer,
            Audience = "legacy-access-test",
            PrivateKeyPem = privateKeyPem,
            KeyId = KeyId,
            AccessTokenLifetimeSeconds = 900,
        };

        private static string CreateForeignKey()
        {
            using var rsa = RSA.Create(2048);
            return rsa.ExportPkcs8PrivateKeyPem();
        }
    }
}
