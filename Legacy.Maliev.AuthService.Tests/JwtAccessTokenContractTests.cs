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
    private const string CatalogMaterialsCreate = "legacy-catalog.materials.create";
    private const string CatalogMaterialsUpdate = "legacy-catalog.materials.update";
    private const string CustomersList = "legacy-customer.customers.list";
    private const string CustomersCreate = "legacy-customer.customers.create";
    private const string CustomersRead = "legacy-customer.customers.read";
    private const string CustomerIdentitiesCreate = "legacy-auth.customer-identities.create";
    private const string EmployeeIdentitiesCreate = "legacy-auth.employee-identities.create";
    private const string EmployeesList = "legacy-employee.employees.list";
    private const string EmployeesRead = "legacy-employee.employees.read";
    private const string OrdersRead = "legacy.orders.read";
    private const string OrdersCreate = "legacy.orders.create";
    private const string SuppliersRead = "legacy-procurement.suppliers.read";
    private const string PurchaseOrdersRead = "legacy-procurement.purchase-orders.read";
    private const string OrderCatalogRead = "legacy.order-catalog.read";
    private const string OrdersUpdate = "legacy.orders.update";
    private const string OrderFilesRead = "legacy.order-files.read";
    private const string OrderFilesWrite = "legacy.order-files.write";
    private const string OrderFilesDelete = "legacy.order-files.delete";
    private const string OrderStatusRead = "legacy.order-status.read";
    private const string OrderStatusWrite = "legacy.order-status.write";
    private const string FileUploadsCreate = "legacy-file.uploads.create";
    private const string FileUploadsRead = "legacy-file.uploads.read";
    private const string FileUploadsDelete = "legacy-file.uploads.delete";
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 0, 0, 0, TimeSpan.Zero);
    private static readonly string[] EmployeeOrderWorkflowPermissions =
    [
        OrdersCreate,
        OrdersUpdate,
        OrderFilesRead,
        OrderFilesWrite,
        OrderFilesDelete,
        OrderStatusRead,
        OrderStatusWrite,
        FileUploadsCreate,
        FileUploadsRead,
        FileUploadsDelete,
    ];

    [Fact]
    public async Task Login_ValidatedEmployee_IssuesInteractivePermissions()
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
        Assert.Equal([CatalogMaterialsRead, CatalogMaterialsCreate, CatalogMaterialsUpdate, CustomersList, CustomersCreate, CustomersRead, CustomerIdentitiesCreate, EmployeeIdentitiesCreate, EmployeesList, EmployeesRead, OrdersRead, OrdersCreate, SuppliersRead, PurchaseOrdersRead, OrderCatalogRead, OrdersUpdate, OrderFilesRead, OrderFilesWrite, OrderFilesDelete, OrderStatusRead, OrderStatusWrite, FileUploadsCreate, FileUploadsRead, FileUploadsDelete], PermissionValues(token));
        AssertStableEmployeeContract(token, fixture.KeyId);
    }

    [Fact]
    public async Task Refresh_ValidatedEmployee_RetainsInteractivePermissions()
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
        Assert.Equal([CatalogMaterialsRead, CatalogMaterialsCreate, CatalogMaterialsUpdate, CustomersList, CustomersCreate, CustomersRead, CustomerIdentitiesCreate, EmployeeIdentitiesCreate, EmployeesList, EmployeesRead, OrdersRead, OrdersCreate, SuppliersRead, PurchaseOrdersRead, OrderCatalogRead, OrdersUpdate, OrderFilesRead, OrderFilesWrite, OrderFilesDelete, OrderStatusRead, OrderStatusWrite, FileUploadsCreate, FileUploadsRead, FileUploadsDelete], PermissionValues(token));
        AssertStableEmployeeContract(token, fixture.KeyId);
        Assert.NotNull(store.Replacement);
    }

    [Fact]
    public async Task Login_ValidatedCustomer_DoesNotIssueEmployeePermissions()
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
        Assert.DoesNotContain(CatalogMaterialsCreate, PermissionValues(token));
        Assert.DoesNotContain(CatalogMaterialsUpdate, PermissionValues(token));
        Assert.DoesNotContain(CustomersList, PermissionValues(token));
        Assert.DoesNotContain(CustomersCreate, PermissionValues(token));
        Assert.DoesNotContain(CustomerIdentitiesCreate, PermissionValues(token));
        Assert.DoesNotContain(EmployeeIdentitiesCreate, PermissionValues(token));
        Assert.DoesNotContain(CustomersRead, PermissionValues(token));
        Assert.DoesNotContain(EmployeesList, PermissionValues(token));
        Assert.DoesNotContain(EmployeesRead, PermissionValues(token));
        Assert.DoesNotContain(OrdersRead, PermissionValues(token));
        Assert.DoesNotContain(SuppliersRead, PermissionValues(token));
        Assert.DoesNotContain(PurchaseOrdersRead, PermissionValues(token));
        Assert.DoesNotContain(OrderCatalogRead, PermissionValues(token));
        AssertDoesNotContainEmployeeOrderWorkflowPermissions(token);
        Assert.Contains(token.Claims, claim => claim.Type == "identity_kind" && claim.Value == "customer");
    }

    [Fact]
    public async Task Refresh_ValidatedCustomer_DoesNotIssueEmployeeOrderWorkflowPermissions()
    {
        using var fixture = new TokenFixture();
        var identity = CustomerIdentity();
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
        Assert.DoesNotContain(SuppliersRead, PermissionValues(token));
        Assert.DoesNotContain(PurchaseOrdersRead, PermissionValues(token));
        AssertDoesNotContainEmployeeOrderWorkflowPermissions(token);
        Assert.Contains(token.Claims, claim => claim.Type == "identity_kind" && claim.Value == "customer");
    }

    [Fact]
    public void ServiceToken_WithoutExplicitEmployeePermission_DoesNotGainInteractivePermissions()
    {
        using var fixture = new TokenFixture();

        var issued = fixture.Issuer.IssueService(
            "legacy-intranet",
            ["legacy-contact.messages.create"],
            Now);

        var token = fixture.ReadAndValidate(issued.Value);
        Assert.Equal(["legacy-contact.messages.create"], PermissionValues(token));
        Assert.DoesNotContain(OrdersRead, PermissionValues(token));
        Assert.DoesNotContain(SuppliersRead, PermissionValues(token));
        Assert.DoesNotContain(PurchaseOrdersRead, PermissionValues(token));
        Assert.DoesNotContain(OrderCatalogRead, PermissionValues(token));
        AssertDoesNotContainEmployeeOrderWorkflowPermissions(token);
        Assert.Contains(token.Claims, claim => claim.Type == "identity_kind" && claim.Value == "service");
    }

    [Fact]
    public void ServiceToken_ExplicitlyRequestedEmployeePermissions_RetainsRequestedPermissions()
    {
        using var fixture = new TokenFixture();

        var issued = fixture.Issuer.IssueService(
            "legacy-intranet",
            ["legacy-contact.messages.create", CatalogMaterialsRead, CatalogMaterialsCreate, CatalogMaterialsUpdate, CustomersCreate, CustomersRead, CustomerIdentitiesCreate, EmployeesList, EmployeesRead, OrdersRead, PurchaseOrdersRead, OrderCatalogRead],
            Now);

        var token = fixture.ReadAndValidate(issued.Value);
        Assert.Equal(
            ["legacy-contact.messages.create", CatalogMaterialsRead, CatalogMaterialsCreate, CatalogMaterialsUpdate, CustomersCreate, CustomersRead, CustomerIdentitiesCreate, EmployeesList, EmployeesRead, OrdersRead, PurchaseOrdersRead, OrderCatalogRead],
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

    private static void AssertDoesNotContainEmployeeOrderWorkflowPermissions(JwtSecurityToken token)
    {
        var permissions = PermissionValues(token);
        foreach (var permission in EmployeeOrderWorkflowPermissions)
        {
            Assert.DoesNotContain(permission, permissions);
        }
    }

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
