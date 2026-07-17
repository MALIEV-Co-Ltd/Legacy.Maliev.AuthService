using Legacy.Maliev.AuthService.Api.Controllers;
using Legacy.Maliev.AuthService.Application;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Microsoft.AspNetCore.Authorization;
using System.Net;
using System.Net.Http.Json;
using System.Reflection;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class EmployeeIdentityAuthorizationTests(
    CustomerIdentityAuthorizationTests.AuthApiFactory factory)
    : IClassFixture<CustomerIdentityAuthorizationTests.AuthApiFactory>
{
    private const string EmployeeIdentitiesCreate = "legacy-auth.employee-identities.create";

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
                controller.GetMethod(methodName)!.GetCustomAttribute<AuthorizeAttribute>()?.Policy);
        }
    }

    [Fact]
    public async Task Post_ConfiguredIntranetServiceToken_ReturnsCreated()
    {
        using var client = factory.CreateAuthorizedClient(factory.IssueService([EmployeeIdentitiesCreate]));

        using var response = await client.PostAsJsonAsync("/auth/v1/employee-identities/42", CreateRequest());

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal(42, (await response.Content.ReadFromJsonAsync<EmployeeIdentityResponse>())?.DatabaseID);
    }

    [Fact]
    public async Task Post_EmployeeInteractiveToken_ReturnsCreated()
    {
        using var client = factory.CreateAuthorizedClient(factory.IssueEmployee());

        using var response = await client.PostAsJsonAsync("/auth/v1/employee-identities/42", CreateRequest());

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

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

    private static CreateEmployeeIdentityRequest CreateRequest() => new(
        "employee@example.com",
        "employee@example.com",
        "correct-password",
        true,
        null);
}
