using Legacy.Maliev.AuthService.Api.Controllers;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Cryptography;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class CustomerIdentityAuthorizationTests : IClassFixture<CustomerIdentityAuthorizationTests.AuthApiFactory>
{
    private const string CustomerIdentitiesCreate = "legacy-auth.customer-identities.create";
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    private readonly AuthApiFactory factory;

    public CustomerIdentityAuthorizationTests(AuthApiFactory factory) => this.factory = factory;

    [Fact]
    public void Controller_PostUsesCreatePermission_WhileOtherOperationsRemainEmployeeOnly()
    {
        var controller = typeof(CustomerIdentitiesController);
        Assert.Null(controller.GetCustomAttribute<AuthorizeAttribute>());

        var create = controller.GetMethod(nameof(CustomerIdentitiesController.Create))!;
        Assert.Equal(
            CustomerIdentitiesCreate,
            Assert.Single(create.GetCustomAttributes<RequirePermissionAttribute>()).Permission);

        foreach (var methodName in new[]
                 {
                     nameof(CustomerIdentitiesController.Get),
                     nameof(CustomerIdentitiesController.Update),
                     nameof(CustomerIdentitiesController.Delete)
                 })
        {
            Assert.Equal(
                "LegacyEmployee",
                controller.GetMethod(methodName)!.GetCustomAttribute<AuthorizeAttribute>()?.Policy);
        }
    }

    [Fact]
    public async Task Post_ConfiguredIntranetServiceToken_ReturnsCreated()
    {
        using var client = factory.CreateAuthorizedClient(factory.IssueService([CustomerIdentitiesCreate]));

        using var response = await client.PostAsJsonAsync("/auth/v1/customer-identities/42", CreateRequest());

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal(42, (await response.Content.ReadFromJsonAsync<CustomerIdentityResponse>())?.DatabaseID);
    }

    [Fact]
    public async Task Post_EmployeeInteractiveToken_ReturnsCreated()
    {
        using var client = factory.CreateAuthorizedClient(factory.IssueEmployee());

        using var response = await client.PostAsJsonAsync("/auth/v1/customer-identities/42", CreateRequest());

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Theory]
    [InlineData("customer")]
    [InlineData("service-without-permission")]
    public async Task Post_TokenWithoutCreatePermission_ReturnsForbidden(string tokenKind)
    {
        var token = tokenKind == "customer"
            ? factory.IssueCustomer()
            : factory.IssueService([]);
        using var client = factory.CreateAuthorizedClient(token);

        using var response = await client.PostAsJsonAsync("/auth/v1/customer-identities/42", CreateRequest());

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    public async Task ExistingAdminOperations_ServiceTokenWithCreatePermission_RemainForbidden(string method)
    {
        using var client = factory.CreateAuthorizedClient(factory.IssueService([CustomerIdentitiesCreate]));
        using var request = new HttpRequestMessage(new HttpMethod(method), "/auth/v1/customer-identities/42");
        if (method == "PUT")
        {
            request.Content = JsonContent.Create(new UpdateCustomerIdentityRequest(
                "customer@example.com",
                "customer@example.com",
                true,
                null,
                false,
                false,
                null,
                true,
                null,
                null));
        }

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    private static CreateCustomerIdentityRequest CreateRequest() => new(
        "customer@example.com",
        "customer@example.com",
        "correct-password",
        true,
        null,
        null,
        null);

    public class AuthApiFactory : WebApplicationFactory<Program>
    {
        private readonly string privateKeyPem;
        private readonly RsaAccessTokenIssuer tokenIssuer;

        public AuthApiFactory()
        {
            privateKeyPem = CreatePrivateKeyPem();
            tokenIssuer = CreateIssuer(privateKeyPem);
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["IdentityStorage:Provider"] = "PostgreSql",
                    ["ConnectionStrings:CustomerIdentity"] = "Host=localhost;Database=unused;Username=unused;Password=unused",
                    ["ConnectionStrings:EmployeeIdentity"] = "Host=localhost;Database=unused;Username=unused;Password=unused",
                    ["ConnectionStrings:RefreshSessions"] = "Host=localhost;Database=unused;Username=unused;Password=unused",
                    ["Jwt:Issuer"] = "https://auth.authorization.test",
                    ["Jwt:Audience"] = "legacy-authorization-test",
                    ["Jwt:PrivateKeyPem"] = privateKeyPem,
                    ["Jwt:KeyId"] = "customer-identity-authorization-test",
                    ["Jwt:AccessTokenLifetimeSeconds"] = "900"
                }));
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<ICustomerIdentityAdminService>();
                services.AddSingleton<ICustomerIdentityAdminService, StubCustomerIdentityAdminService>();
                services.RemoveAll<IEmployeeIdentityAdminService>();
                services.AddSingleton<IEmployeeIdentityAdminService, StubEmployeeIdentityAdminService>();
            });
        }

        public HttpClient CreateAuthorizedClient(string token)
        {
            var client = CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                BaseAddress = new Uri("https://localhost")
            });
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return client;
        }

        public string IssueEmployee()
        {
            return tokenIssuer.Issue(
                new LegacyIdentity("employee-7", "employee@maliev.com", "employee@maliev.com", IdentityKind.Employee, 7, "stamp"),
                Now).Value;
        }

        public string IssueCustomer()
        {
            return tokenIssuer.Issue(
                new LegacyIdentity("customer-42", "customer@maliev.com", "customer@maliev.com", IdentityKind.Customer, 42, "stamp"),
                Now).Value;
        }

        public string IssueService(IReadOnlyList<string> permissions)
        {
            return tokenIssuer.IssueService("legacy-intranet", permissions, Now).Value;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                tokenIssuer.Dispose();
            }

            base.Dispose(disposing);
        }

        private static RsaAccessTokenIssuer CreateIssuer(string privateKeyPem) => new(Options.Create(new JwtOptions
        {
            Issuer = "https://auth.authorization.test",
            Audience = "legacy-authorization-test",
            PrivateKeyPem = privateKeyPem,
            KeyId = "customer-identity-authorization-test",
            AccessTokenLifetimeSeconds = 900
        }));

        private static string CreatePrivateKeyPem()
        {
            using var signingKey = RSA.Create(2048);
            return signingKey.ExportPkcs8PrivateKeyPem();
        }
    }

    private sealed class StubCustomerIdentityAdminService : ICustomerIdentityAdminService
    {
        public Task<CustomerIdentityResponse?> CreateAsync(
            int databaseId,
            CreateCustomerIdentityRequest request,
            CancellationToken cancellationToken) => Task.FromResult<CustomerIdentityResponse?>(new(
                "customer-identity-42",
                request.UserName,
                request.Email,
                request.EmailConfirmed,
                request.PhoneNumber,
                false,
                false,
                null,
                true,
                0,
                databaseId,
                request.FaxNumber,
                request.MobileNumber));

        public Task<CustomerIdentityResponse?> GetAsync(int databaseId, CancellationToken cancellationToken) =>
            Task.FromResult<CustomerIdentityResponse?>(null);

        public Task<bool> UpdateAsync(
            int databaseId,
            UpdateCustomerIdentityRequest request,
            CancellationToken cancellationToken) => Task.FromResult(false);

        public Task<bool> DeleteAsync(int databaseId, CancellationToken cancellationToken) => Task.FromResult(false);
    }

    private sealed class StubEmployeeIdentityAdminService : IEmployeeIdentityAdminService
    {
        public Task<EmployeeIdentityResponse?> CreateAsync(
            int databaseId,
            CreateEmployeeIdentityRequest request,
            CancellationToken cancellationToken) => Task.FromResult<EmployeeIdentityResponse?>(new(
                "employee-identity-42",
                request.UserName,
                request.Email,
                request.EmailConfirmed,
                request.PhoneNumber,
                false,
                false,
                null,
                true,
                0,
                databaseId));

        public Task<EmployeeIdentityResponse?> GetAsync(int databaseId, CancellationToken cancellationToken) =>
            Task.FromResult<EmployeeIdentityResponse?>(null);

        public Task<bool> UpdateAsync(
            int databaseId,
            UpdateEmployeeIdentityRequest request,
            CancellationToken cancellationToken) => Task.FromResult(false);

        public Task<bool> DeleteAsync(int databaseId, CancellationToken cancellationToken) => Task.FromResult(false);
    }
}
