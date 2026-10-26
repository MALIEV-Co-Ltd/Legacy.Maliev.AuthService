using Legacy.Maliev.AuthService.Api.Controllers;
using Legacy.Maliev.AuthService.Application;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Microsoft.AspNetCore.Authorization;
using System.Net;
using System.Net.Http.Json;
using System.Reflection;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>
/// Exercises employee identity permissions and employee-only administration through signed HTTP principals.
/// </summary>
/// <param name="factory">The shared application factory that issues signed principals for authorization cases.</param>
public sealed class EmployeeIdentityAuthorizationTests(
    CustomerIdentityAuthorizationTests.AuthApiFactory factory)
    : IClassFixture<CustomerIdentityAuthorizationTests.AuthApiFactory>
{
    private const string EmployeeIdentitiesCreate = "legacy-auth.employee-identities.create";
    private const string EmployeeIdentitiesRead = "legacy-auth.employee-identities.read";
    private const string EmployeeIdentitiesUpdate = "legacy-auth.employee-identities.update";
    private const string EmployeeIdentitiesDelete = "legacy-auth.employee-identities.delete";

    /// <summary>
    /// Checks that employee creation uses its dedicated grant while other actions retain the employee policy.
    /// </summary>
    [Fact]
    public void Controller_PostUsesCreatePermission_WhileOtherOperationsRemainEmployeeOnly()
    {
        var controller = typeof(EmployeeIdentitiesController);
        Assert.Null(controller.GetCustomAttribute<AuthorizeAttribute>());

        var create = controller.GetMethod(nameof(EmployeeIdentitiesController.Create))!;
        Assert.Equal(
            EmployeeIdentitiesCreate,
            Assert.Single(create.GetCustomAttributes<RequirePermissionAttribute>()).Permission);

        foreach (var methodName in new[]
                 {
                     nameof(EmployeeIdentitiesController.Get),
                     nameof(EmployeeIdentitiesController.Update),
                     nameof(EmployeeIdentitiesController.Delete)
                 })
        {
            Assert.Equal(
                "LegacyEmployee",
                Assert.Single(controller.GetMethod(methodName)!.GetCustomAttributes<AuthorizeAttribute>(),
                    attribute => attribute.Policy == "LegacyEmployee").Policy);
        }
    }

    /// <summary>
    /// Checks exact employee read, update, and delete grants alongside the employee policy.
    /// </summary>
    [Fact]
    public void Controller_AdminOperationsRequireGranularPermissionsAndRetainEmployeePolicy()
    {
        var controller = typeof(EmployeeIdentitiesController);
        var expectedPermissions = new Dictionary<string, string>
        {
            [nameof(EmployeeIdentitiesController.Get)] = EmployeeIdentitiesRead,
            [nameof(EmployeeIdentitiesController.Update)] = EmployeeIdentitiesUpdate,
            [nameof(EmployeeIdentitiesController.Delete)] = EmployeeIdentitiesDelete
        };

        foreach (var (methodName, expectedPermission) in expectedPermissions)
        {
            var method = controller.GetMethod(methodName)!;

            Assert.Equal(
                expectedPermission,
                Assert.Single(method.GetCustomAttributes<RequirePermissionAttribute>()).Permission);
            Assert.Equal(
                "LegacyEmployee",
                Assert.Single(method.GetCustomAttributes<AuthorizeAttribute>(),
                    attribute => attribute.Policy == "LegacyEmployee").Policy);
        }
    }

    /// <summary>
    /// Checks that an intranet service with the create grant receives a created employee response.
    /// </summary>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Fact]
    public async Task Post_ConfiguredIntranetServiceToken_ReturnsCreated()
    {
        using var client = factory.CreateAuthorizedClient(factory.IssueService([EmployeeIdentitiesCreate]));

        using var response = await client.PostAsJsonAsync("/auth/v1/employee-identities/42", CreateRequest());

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal(42, (await response.Content.ReadFromJsonAsync<EmployeeIdentityResponse>())?.DatabaseID);
    }

    /// <summary>
    /// Checks that an interactive employee can create an employee identity.
    /// </summary>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Fact]
    public async Task Post_EmployeeInteractiveToken_ReturnsCreated()
    {
        using var client = factory.CreateAuthorizedClient(factory.IssueEmployee());

        using var response = await client.PostAsJsonAsync("/auth/v1/employee-identities/42", CreateRequest());

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    /// <summary>
    /// Checks that a customer or unprivileged service cannot create an employee identity.
    /// </summary>
    /// <param name="tokenKind">The customer or service principal that lacks the create grant.</param>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Theory]
    [InlineData("customer")]
    [InlineData("service-without-permission")]
    public async Task Post_TokenWithoutCreatePermission_ReturnsForbidden(string tokenKind)
    {
        var token = tokenKind == "customer" ? factory.IssueCustomer() : factory.IssueService([]);
        using var client = factory.CreateAuthorizedClient(token);

        using var response = await client.PostAsJsonAsync("/auth/v1/employee-identities/42", CreateRequest());

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// Checks that a create-only service cannot read, update, or delete employee identities.
    /// </summary>
    /// <param name="method">The HTTP administration verb under test.</param>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Theory]
    [InlineData("GET")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    public async Task ExistingAdminOperations_ServiceTokenWithCreatePermission_RemainForbidden(string method)
    {
        using var client = factory.CreateAuthorizedClient(factory.IssueService([EmployeeIdentitiesCreate]));
        using var request = new HttpRequestMessage(new HttpMethod(method), "/auth/v1/employee-identities/42");
        if (method == "PUT")
        {
            request.Content = JsonContent.Create(new UpdateEmployeeIdentityRequest(
                "employee@example.com",
                "employee@example.com",
                true,
                null,
                false,
                false,
                null,
                true));
        }

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// Checks that matching operation grants do not let a service bypass the employee policy.
    /// </summary>
    /// <param name="method">The HTTP administration verb under test.</param>
    /// <param name="permission">The exact operation grant assigned to the test principal.</param>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Theory]
    [InlineData("GET", EmployeeIdentitiesRead)]
    [InlineData("PUT", EmployeeIdentitiesUpdate)]
    [InlineData("DELETE", EmployeeIdentitiesDelete)]
    public async Task AdminOperations_ServiceTokenWithMatchingPermissionStillRequiresEmployeePolicy(
        string method,
        string permission)
    {
        using var client = factory.CreateAuthorizedClient(factory.IssueService([permission]));
        using var request = new HttpRequestMessage(new HttpMethod(method), "/auth/v1/employee-identities/42");
        if (method == "PUT")
        {
            request.Content = JsonContent.Create(new UpdateEmployeeIdentityRequest(
                "employee@example.com",
                "employee@example.com",
                true,
                null,
                false,
                false,
                null,
                true));
        }

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// Checks that an employee passes both authorization layers and reaches the missing-record stub.
    /// </summary>
    /// <param name="method">The HTTP administration verb under test.</param>
    /// <returns>A task that completes when the asynchronous assertions finish.</returns>
    [Theory]
    [InlineData("GET")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    public async Task AdminOperations_EmployeeTokenPassesPermissionAndEmployeePolicies(string method)
    {
        using var client = factory.CreateAuthorizedClient(factory.IssueEmployee());
        using var request = new HttpRequestMessage(new HttpMethod(method), "/auth/v1/employee-identities/42");
        if (method == "PUT")
        {
            request.Content = JsonContent.Create(new UpdateEmployeeIdentityRequest(
                "employee@example.com",
                "employee@example.com",
                true,
                null,
                false,
                false,
                null,
                true));
        }

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    private static CreateEmployeeIdentityRequest CreateRequest() => new(
        "employee@example.com",
        "employee@example.com",
        "correct-password",
        true,
        null);
}
