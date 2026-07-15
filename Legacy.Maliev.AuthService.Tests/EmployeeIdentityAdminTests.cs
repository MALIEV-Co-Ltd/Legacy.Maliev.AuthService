using System.Reflection;
using Legacy.Maliev.AuthService.Api.Controllers;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class EmployeeIdentityAdminTests
{
    [Fact]
    public async Task Create_PersistsCompatibleHashWithoutCustomerOnlyColumns()
    {
        await using var context = CreateContext();
        var hasher = new PasswordHasher<LegacyIdentityRow>();
        var service = new EmployeeIdentityAdminService(context, hasher);

        var response = await service.CreateAsync(
            7,
            new CreateEmployeeIdentityRequest("employee@maliev.com", "employee@maliev.com", "correct-password", true, null),
            default);

        Assert.NotNull(response);
        Assert.Equal(7, response.DatabaseID);
        var stored = await context.Users.SingleAsync();
        Assert.Equal(PasswordVerificationResult.Success,
            hasher.VerifyHashedPassword(stored, stored.PasswordHash!, "correct-password"));
        var responseFields = typeof(EmployeeIdentityResponse).GetProperties().Select(property => property.Name);
        Assert.DoesNotContain("PasswordHash", responseFields);
        Assert.DoesNotContain("SecurityStamp", responseFields);
        Assert.DoesNotContain("FaxNumber", responseFields);
        Assert.DoesNotContain("MobileNumber", responseFields);
    }

    [Fact]
    public void Controller_RequiresEmployeePolicyAndPasswordNeverAppearsInRoute()
    {
        var controller = typeof(EmployeeIdentitiesController);
        Assert.Equal("LegacyEmployee", controller.GetCustomAttribute<AuthorizeAttribute>()?.Policy);
        var create = controller.GetMethod(nameof(EmployeeIdentitiesController.Create))!;
        var route = create.GetCustomAttribute<HttpPostAttribute>()?.Template;

        Assert.Equal("{databaseId:int}", route);
        Assert.DoesNotContain("password", route, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(create.GetParameters(), parameter => parameter.ParameterType == typeof(CreateEmployeeIdentityRequest));
        Assert.DoesNotContain(create.GetParameters(), parameter =>
            string.Equals(parameter.Name, "password", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Update_RotatesSecurityStampAndDoesNotAcceptCustomerOnlyFields()
    {
        await using var context = CreateContext();
        var service = new EmployeeIdentityAdminService(context, new PasswordHasher<LegacyIdentityRow>());
        await service.CreateAsync(
            7,
            new CreateEmployeeIdentityRequest("employee@maliev.com", "employee@maliev.com", "correct-password", true, null),
            default);
        var before = (await context.Users.AsNoTracking().SingleAsync()).SecurityStamp;

        var updated = await service.UpdateAsync(
            7,
            new UpdateEmployeeIdentityRequest(
                "updated@maliev.com", "updated@maliev.com", true, null, false, false, null, true),
            default);
        var after = (await context.Users.AsNoTracking().SingleAsync()).SecurityStamp;

        Assert.True(updated);
        Assert.NotEqual(before, after);
        var requestFields = typeof(UpdateEmployeeIdentityRequest).GetProperties().Select(property => property.Name);
        Assert.DoesNotContain("FaxNumber", requestFields);
        Assert.DoesNotContain("MobileNumber", requestFields);
    }

    [Fact]
    public void EmployeeIdentityContext_HasNoMigrationsInAuthRepository()
    {
        var infrastructure = Path.Combine(FindRoot(), "Legacy.Maliev.AuthService.Infrastructure");
        var migrations = Directory.GetFiles(Path.Combine(infrastructure, "Migrations"), "*.cs");
        var combined = string.Join('\n', migrations.Select(File.ReadAllText));

        Assert.DoesNotContain(nameof(EmployeeIdentityDbContext), combined, StringComparison.Ordinal);
        Assert.DoesNotContain("AspNetUsers", combined, StringComparison.Ordinal);
    }

    private static EmployeeIdentityDbContext CreateContext() => new(
        new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
            .UseInMemoryDatabase($"employee-admin-{Guid.NewGuid()}")
            .Options);

    private static string FindRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Legacy.Maliev.AuthService.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException();
    }
}
