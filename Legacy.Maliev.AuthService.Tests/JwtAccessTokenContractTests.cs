using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class JwtAccessTokenContractTests
{
    private const string CatalogMaterialsRead = "legacy-catalog.materials.read";
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Login_ValidatedEmployee_IssuesCatalogMaterialsReadPermission()
    {
        using var fixture = new TokenFixture();
        var identity = EmployeeIdentity();
        var service = new AuthenticationService(
            new StubValidator(identity),
            new StubIdentityReader(identity),
            fixture.Issuer,
            new RecordingRefreshStore(),
            new FakeTimeProvider(Now));

        var result = await service.LoginAsync(
            new LoginRequest(identity.Email!, "correct password", IdentityKind.Employee),
            default);

        var token = fixture.ReadAndValidate(Assert.IsType<TokenResponse>(result.Tokens).AccessToken);
        Assert.Equal([CatalogMaterialsRead], PermissionValues(token));
        AssertStableEmployeeContract(token, fixture.KeyId);
    }

    [Fact]
    public async Task Refresh_ValidatedEmployee_RetainsCatalogMaterialsReadPermission()
    {
        using var fixture = new TokenFixture();
        var identity = EmployeeIdentity();
        var store = new RecordingRefreshStore
        {
            RotationResult = new(
                RefreshRotationStatus.Succeeded,
                identity.Id,
                identity.Kind,
                identity.SecurityStamp),
        };
        var service = new AuthenticationService(
            new StubValidator(null),
            new StubIdentityReader(identity),
            fixture.Issuer,
            store,
            new FakeTimeProvider(Now));

        var result = await service.RefreshAsync(
            new RefreshRequest(new string('r', 64)),
            default);

        var token = fixture.ReadAndValidate(Assert.IsType<TokenResponse>(result.Tokens).AccessToken);
        Assert.Equal([CatalogMaterialsRead], PermissionValues(token));
        AssertStableEmployeeContract(token, fixture.KeyId);
        Assert.NotNull(store.Replacement);
    }

    [Fact]
    public async Task Login_ValidatedCustomer_DoesNotIssueEmployeeCatalogPermission()
    {
        using var fixture = new TokenFixture();
        var identity = CustomerIdentity();
        var service = new AuthenticationService(
            new StubValidator(identity),
            new StubIdentityReader(identity),
            fixture.Issuer,
            new RecordingRefreshStore(),
            new FakeTimeProvider(Now));

        var result = await service.LoginAsync(
            new LoginRequest(identity.Email!, "correct password", IdentityKind.Customer),
            default);

        var token = fixture.ReadAndValidate(Assert.IsType<TokenResponse>(result.Tokens).AccessToken);
        Assert.DoesNotContain(CatalogMaterialsRead, PermissionValues(token));
        Assert.Contains(token.Claims, claim => claim.Type == "identity_kind" && claim.Value == "customer");
    }

    [Fact]
    public void ServiceToken_WithoutExplicitCatalogPermission_DoesNotGainEmployeePermission()
    {
        using var fixture = new TokenFixture();

        var issued = fixture.Issuer.IssueService(
            "legacy-intranet",
            ["legacy-contact.messages.create"],
            Now);

        var token = fixture.ReadAndValidate(issued.Value);
        Assert.Equal(["legacy-contact.messages.create"], PermissionValues(token));
        Assert.Contains(token.Claims, claim => claim.Type == "identity_kind" && claim.Value == "service");
    }

    [Fact]
    public void ServiceToken_ExplicitlyRequestedCatalogPermission_RetainsRequestedPermissions()
    {
        using var fixture = new TokenFixture();

        var issued = fixture.Issuer.IssueService(
            "legacy-intranet",
            ["legacy-contact.messages.create", CatalogMaterialsRead],
            Now);

        var token = fixture.ReadAndValidate(issued.Value);
        Assert.Equal(
            ["legacy-contact.messages.create", CatalogMaterialsRead],
            PermissionValues(token));
        Assert.Contains(token.Claims, claim => claim.Type == "identity_kind" && claim.Value == "service");
    }

    [Fact]
    public async Task Login_ResponseJsonShapeRemainsUnchanged()
    {
        using var fixture = new TokenFixture();
        var identity = EmployeeIdentity();
        var service = new AuthenticationService(
            new StubValidator(identity),
            new StubIdentityReader(identity),
            fixture.Issuer,
            new RecordingRefreshStore(),
            new FakeTimeProvider(Now));

        var result = await service.LoginAsync(
            new LoginRequest(identity.Email!, "correct password", IdentityKind.Employee),
            default);

        var json = JsonSerializer.SerializeToElement(
            Assert.IsType<TokenResponse>(result.Tokens),
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.Equal(
            ["accessToken", "expiresIn", "refreshExpiresAt", "refreshToken", "tokenType"],
            json.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray());
    }

    private static string[] PermissionValues(JwtSecurityToken token) =>
        token.Claims
            .Where(claim => claim.Type == "permissions")
            .Select(claim => claim.Value)
            .ToArray();

    private static void AssertStableEmployeeContract(JwtSecurityToken token, string expectedKeyId)
    {
        Assert.Equal(SecurityAlgorithms.RsaSha256, token.Header.Alg);
        Assert.Equal(expectedKeyId, token.Header.Kid);
        Assert.Equal("https://auth.test", token.Issuer);
        Assert.Equal(["legacy-test"], token.Audiences);
        Assert.Equal("employee", token.Claims.Single(claim => claim.Type == "identity_kind").Value);
        Assert.Equal(EmployeeIdentity().Id, token.Subject);
        Assert.Equal(EmployeeIdentity().UserName, token.Claims.Single(claim => claim.Type == JwtRegisteredClaimNames.Name).Value);
        Assert.Equal(EmployeeIdentity().Email, token.Claims.Single(claim => claim.Type == JwtRegisteredClaimNames.Email).Value);
    }

    private static LegacyIdentity EmployeeIdentity() =>
        new("employee-7", "employee@maliev.com", "employee@maliev.com", IdentityKind.Employee, 7, "employee-stamp");

    private static LegacyIdentity CustomerIdentity() =>
        new("customer-42", "customer@maliev.com", "customer@maliev.com", IdentityKind.Customer, 42, "customer-stamp");

    private sealed class TokenFixture : IDisposable
    {
        private readonly RSA rsa = RSA.Create(2048);
        private readonly RsaSecurityKey validationKey;

        public TokenFixture()
        {
            KeyId = "catalog-contract-key";
            validationKey = new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = KeyId };
            Issuer = new RsaAccessTokenIssuer(Options.Create(new JwtOptions
            {
                Issuer = "https://auth.test",
                Audience = "legacy-test",
                PrivateKeyPem = rsa.ExportPkcs8PrivateKeyPem(),
                KeyId = KeyId,
                AccessTokenLifetimeSeconds = 900,
            }));
        }

        public string KeyId { get; }

        public RsaAccessTokenIssuer Issuer { get; }

        public JwtSecurityToken ReadAndValidate(string encodedToken)
        {
            var handler = new JwtSecurityTokenHandler();
            handler.ValidateToken(encodedToken, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = "https://auth.test",
                ValidateAudience = true,
                ValidAudience = "legacy-test",
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = validationKey,
                ValidateLifetime = false,
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            }, out var validatedToken);
            return Assert.IsType<JwtSecurityToken>(validatedToken);
        }

        public void Dispose()
        {
            Issuer.Dispose();
            rsa.Dispose();
        }
    }

    private sealed class StubValidator(LegacyIdentity? identity) : ILegacyCredentialValidator
    {
        public Task<LegacyIdentity?> ValidateAsync(
            string userName,
            string password,
            IdentityKind kind,
            CancellationToken cancellationToken) => Task.FromResult(identity);
    }

    private sealed class StubIdentityReader(LegacyIdentity? identity) : ILegacyIdentityReader
    {
        public Task<LegacyIdentity?> FindActiveAsync(
            string identityId,
            IdentityKind kind,
            CancellationToken cancellationToken) => Task.FromResult(identity);
    }

    private sealed class RecordingRefreshStore : IRefreshSessionStore
    {
        public RefreshSession? Replacement { get; private set; }

        public RefreshRotationResult RotationResult { get; init; } =
            new(RefreshRotationStatus.Invalid, null, null, null);

        public Task CreateAsync(RefreshSession session, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<RefreshRotationResult> RotateAsync(
            string presentedHash,
            RefreshSession replacement,
            CancellationToken cancellationToken)
        {
            Replacement = replacement;
            return Task.FromResult(RotationResult);
        }

        public Task RevokeFamilyAsync(string tokenHash, DateTimeOffset now, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }
}
