using Legacy.Maliev.AuthService.Api.Controllers;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class ServiceAuthenticationTests
{
    private static readonly string[] LegacyAccountingPermissions =
    [
        "legacy.documents.render",
        "legacy-file.uploads.create",
        "legacy-file.uploads.read",
        "legacy-file.uploads.delete",
        "legacy.notifications.send",
        "legacy-customer.customers.read",
        "legacy-employee.signatures.read",
    ];

    [Fact]
    public async Task Login_ValidConfiguredSecret_IssuesShortLivedServiceToken()
    {
        var issuer = new RecordingIssuer();
        var service = new ServiceAuthenticationService(
            Options.Create(new ServiceClientOptions
            {
                Clients =
                {
                    ["legacy-web"] = new ServiceClientCredential
                    {
                        SecretSha256 = ServiceClientCredential.HashSecret("correct-secret"),
                        Permissions = ["legacy-contact.messages.create", "legacy-quotation.quotations.create"],
                    },
                },
            }),
            issuer,
            new FakeTimeProvider(new DateTimeOffset(2026, 7, 15, 0, 0, 0, TimeSpan.Zero)));

        var result = await service.LoginAsync(new ServiceLoginRequest("legacy-web", "correct-secret"));

        Assert.True(result.Succeeded);
        Assert.Equal("service-token", result.Token?.AccessToken);
        Assert.Equal("legacy-web", issuer.ClientId);
        Assert.Equal(["legacy-contact.messages.create", "legacy-quotation.quotations.create"], issuer.Permissions);
    }

    [Theory]
    [InlineData("missing", "correct-secret")]
    [InlineData("legacy-web", "wrong-secret")]
    public async Task Login_UnknownClientOrWrongSecret_ReturnsSameGenericFailure(string clientId, string secret)
    {
        var issuer = new RecordingIssuer();
        var service = new ServiceAuthenticationService(
            Options.Create(new ServiceClientOptions
            {
                Clients = { ["legacy-web"] = new ServiceClientCredential { SecretSha256 = ServiceClientCredential.HashSecret("correct-secret") } },
            }), issuer, TimeProvider.System);

        var result = await service.LoginAsync(new ServiceLoginRequest(clientId, secret));

        Assert.False(result.Succeeded);
        Assert.Null(result.Token);
        Assert.Null(issuer.ClientId);
    }

    [Fact]
    public async Task Login_LegacyAccounting_IssuesExactlyTheApprovedSevenPermissions()
    {
        var issuer = new RecordingIssuer();
        var service = new ServiceAuthenticationService(
            Options.Create(new ServiceClientOptions
            {
                Clients =
                {
                    ["legacy-accounting"] = new ServiceClientCredential
                    {
                        SecretSha256 = ServiceClientCredential.HashSecret("accounting-secret"),
                        Permissions = [.. LegacyAccountingPermissions],
                    },
                },
            }),
            issuer,
            TimeProvider.System);

        var result = await service.LoginAsync(
            new ServiceLoginRequest("legacy-accounting", "accounting-secret"));

        Assert.True(result.Succeeded);
        Assert.Equal("legacy-accounting", issuer.ClientId);
        var permissions = Assert.IsAssignableFrom<IReadOnlyList<string>>(issuer.Permissions);
        Assert.Equal(7, permissions.Count);
        Assert.Equal(LegacyAccountingPermissions, permissions);
        Assert.DoesNotContain(permissions, permission => permission.Contains('*', StringComparison.Ordinal));
    }

    [Fact]
    public async Task Login_ConfiguredWildcardPermission_FailsClosedWithoutIssuingToken()
    {
        var issuer = new RecordingIssuer();
        var service = new ServiceAuthenticationService(
            Options.Create(new ServiceClientOptions
            {
                Clients =
                {
                    ["legacy-accounting"] = new ServiceClientCredential
                    {
                        SecretSha256 = ServiceClientCredential.HashSecret("accounting-secret"),
                        Permissions = [.. LegacyAccountingPermissions, "*"],
                    },
                },
            }),
            issuer,
            TimeProvider.System);

        var result = await service.LoginAsync(
            new ServiceLoginRequest("legacy-accounting", "accounting-secret"));

        Assert.False(result.Succeeded);
        Assert.Null(result.Token);
        Assert.Null(issuer.ClientId);
    }

    [Fact]
    public async Task Controller_InvalidServiceCredentials_ReturnsNonEnumeratingProblem()
    {
        var service = new ServiceAuthenticationService(Options.Create(new ServiceClientOptions()), new RecordingIssuer(), TimeProvider.System);
        var controller = new AuthenticationController(null!, service);

        var response = await controller.ServiceLogin(new ServiceLoginRequest("unknown", "wrong"));

        var unauthorized = Assert.IsType<UnauthorizedObjectResult>(response.Result);
        var problem = Assert.IsType<ProblemDetails>(unauthorized.Value);
        Assert.Equal("Authentication failed", problem.Title);
        Assert.DoesNotContain("unknown", problem.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void RsaIssuer_ServiceTokenCarriesOnlyConfiguredPermissionsAndNoRefreshMaterial()
    {
        using var rsa = RSA.Create(2048);
        var issuer = new RsaAccessTokenIssuer(Options.Create(new JwtOptions
        {
            Issuer = "https://auth.test",
            Audience = "legacy-test",
            PrivateKeyPem = rsa.ExportPkcs8PrivateKeyPem(),
            KeyId = "test-key",
            AccessTokenLifetimeSeconds = 900,
        }));

        var issued = issuer.IssueService("legacy-web", ["legacy-contact.messages.create"], DateTimeOffset.UnixEpoch);
        var token = new JwtSecurityTokenHandler().ReadJwtToken(issued.Value);

        Assert.Equal("service:legacy-web", token.Subject);
        Assert.Contains(token.Claims, claim => claim.Type == "identity_kind" && claim.Value == "service");
        Assert.Contains(token.Claims, claim => claim.Type == "permissions" && claim.Value == "legacy-contact.messages.create");
        Assert.DoesNotContain(token.Claims, claim => claim.Type.Contains("secret", StringComparison.OrdinalIgnoreCase) || claim.Type.Contains("refresh", StringComparison.OrdinalIgnoreCase));
    }

    private sealed class RecordingIssuer : IServiceAccessTokenIssuer
    {
        public string? ClientId { get; private set; }
        public IReadOnlyList<string>? Permissions { get; private set; }
        public IssuedAccessToken IssueService(string clientId, IReadOnlyList<string> permissions, DateTimeOffset now)
        {
            ClientId = clientId; Permissions = permissions; return new("service-token", 900);
        }
    }
}
