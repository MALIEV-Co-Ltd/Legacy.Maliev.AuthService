using Legacy.Maliev.AuthService.Api.Controllers;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Reflection;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class CustomerIdentityAdminTests(PostgresFixture postgres)
{
    [Fact]
    public async Task Create_PersistsCompatiblePasswordHashAndReturnsNoSecurityMaterial()
    {
        await using var context = await postgres.CreateCustomerContextAsync();
        var hasher = new PasswordHasher<LegacyIdentityRow>();
        var service = new CustomerIdentityAdminService(context, hasher);

        var response = await service.CreateAsync(
            42,
            new CreateCustomerIdentityRequest(
                "customer@example.com",
                "customer@example.com",
                "correct-password",
                true,
                null,
                null,
                null),
            default);

        Assert.NotNull(response);
        Assert.Equal(42, response.DatabaseID);
        var stored = await context.Users.SingleAsync();
        Assert.NotEqual("correct-password", stored.PasswordHash);
        Assert.Equal(
            PasswordVerificationResult.Success,
            hasher.VerifyHashedPassword(stored, stored.PasswordHash!, "correct-password"));
        var responseFields = typeof(CustomerIdentityResponse).GetProperties().Select(property => property.Name);
        Assert.DoesNotContain("Password", responseFields);
        Assert.DoesNotContain("PasswordHash", responseFields);
        Assert.DoesNotContain("SecurityStamp", responseFields);
        Assert.DoesNotContain("ConcurrencyStamp", responseFields);
    }

    [Fact]
    public async Task Update_ChangesSecurityStampSoExistingRefreshFamiliesBecomeInvalid()
    {
        await using var context = await postgres.CreateCustomerContextAsync();
        var service = new CustomerIdentityAdminService(context, new PasswordHasher<LegacyIdentityRow>());
        await service.CreateAsync(
            42,
            new CreateCustomerIdentityRequest(
                "customer@example.com", "customer@example.com", "correct-password", true, null, null, null),
            default);
        var before = (await context.Users.AsNoTracking().SingleAsync()).SecurityStamp;

        var updated = await service.UpdateAsync(
            42,
            new UpdateCustomerIdentityRequest(
                "new@example.com", "new@example.com", true, null, false, false, null, true, null, null),
            default);
        var after = (await context.Users.AsNoTracking().SingleAsync()).SecurityStamp;

        Assert.True(updated);
        Assert.NotEqual(before, after);
    }

    [Fact]
    public void Controller_UsesEmployeePolicyAndNeverCarriesPasswordInRoute()
    {
        var controller = typeof(CustomerIdentitiesController);
        Assert.Equal("LegacyEmployee", controller.GetCustomAttribute<AuthorizeAttribute>()?.Policy);
        var create = controller.GetMethod(nameof(CustomerIdentitiesController.Create))!;
        var route = create.GetCustomAttribute<HttpPostAttribute>()?.Template;

        Assert.Equal("{databaseId:int}", route);
        Assert.DoesNotContain("password", route, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(create.GetParameters(), parameter => parameter.ParameterType == typeof(CreateCustomerIdentityRequest));
        Assert.DoesNotContain(create.GetParameters(), parameter =>
            string.Equals(parameter.Name, "password", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CustomerIdentityContext_HasIsolatedPostgresMigration()
    {
        var infrastructure = Path.Combine(FindRoot(), "Legacy.Maliev.AuthService.Infrastructure");
        var migrations = Directory.GetFiles(
            Path.Combine(infrastructure, "Migrations", "CustomerIdentityPostgres"), "*.cs");
        var combined = string.Join('\n', migrations.Select(File.ReadAllText));

        Assert.Contains(nameof(CustomerIdentityDbContext), combined, StringComparison.Ordinal);
        Assert.Contains("AspNetUsers", combined, StringComparison.Ordinal);
    }

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
