using Legacy.Maliev.AuthService.Api.Controllers;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Maliev.Aspire.ServiceDefaults.Authorization;
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
                null,
                PasswordSetupRequired: true),
            default);

        Assert.NotNull(response);
        Assert.Equal(42, response.DatabaseID);
        var stored = await context.Users.SingleAsync();
        Assert.NotEqual("correct-password", stored.PasswordHash);
        Assert.Equal(
            PasswordVerificationResult.Success,
            hasher.VerifyHashedPassword(stored, stored.PasswordHash!, "correct-password"));
        Assert.True(stored.PasswordSetupRequired);
        var responseFields = typeof(CustomerIdentityResponse).GetProperties().Select(property => property.Name);
        Assert.DoesNotContain("Password", responseFields);
        Assert.DoesNotContain("PasswordHash", responseFields);
        Assert.DoesNotContain("SecurityStamp", responseFields);
        Assert.DoesNotContain("ConcurrencyStamp", responseFields);
    }

    [Fact]
    public async Task KeyedCreate_LostResponseReplaysOnlyForSameOwnerKeyAndPayload()
    {
        await using var context = await postgres.CreateCustomerContextAsync();
        var service = new CustomerIdentityAdminService(context, new PasswordHasher<LegacyIdentityRow>());
        var request = new CreateCustomerIdentityRequest(
            "customer@example.com", "customer@example.com", "correct-password", true, null, null, null);
        var key = Guid.NewGuid();

        Assert.Equal(CustomerIdentityCreateOutcome.Created,
            (await service.CreateOrReconcileAsync(42, "service:legacy-intranet", key, request, default)).Outcome);
        context.ChangeTracker.Clear();
        Assert.Equal(CustomerIdentityCreateOutcome.Replayed,
            (await service.CreateOrReconcileAsync(42, "service:legacy-intranet", key, request, default)).Outcome);
        Assert.Equal(CustomerIdentityCreateOutcome.Conflict,
            (await service.CreateOrReconcileAsync(42, "service:other", key, request, default)).Outcome);
        Assert.Equal(CustomerIdentityCreateOutcome.Conflict,
            (await service.CreateOrReconcileAsync(42, "service:legacy-intranet", Guid.NewGuid(), request, default)).Outcome);
        Assert.Single(await context.Users.ToListAsync());
        var receipt = Assert.Single(await context.CreateOperations.ToListAsync());
        Assert.Equal("service:legacy-intranet", receipt.ServiceSubject);
        Assert.Equal(32, receipt.PayloadHash.Length);
        Assert.Equal(16, receipt.PayloadSalt.Length);
    }

    [Fact]
    public async Task KeyedCreate_ChangedPayloadOrDatabaseIdConflictsWithoutMutatingIdentity()
    {
        await using var context = await postgres.CreateCustomerContextAsync();
        var service = new CustomerIdentityAdminService(context, new PasswordHasher<LegacyIdentityRow>());
        var request = new CreateCustomerIdentityRequest(
            "customer@example.com", "customer@example.com", "correct-password", true, null, null, null);
        var key = Guid.NewGuid();
        await service.CreateOrReconcileAsync(42, "service:legacy-intranet", key, request, default);

        Assert.Equal(CustomerIdentityCreateOutcome.Conflict,
            (await service.CreateOrReconcileAsync(42, "service:legacy-intranet", key,
                request with { Password = "changed-password" }, default)).Outcome);
        Assert.Equal(CustomerIdentityCreateOutcome.Conflict,
            (await service.CreateOrReconcileAsync(43, "service:legacy-intranet", key, request, default)).Outcome);
        Assert.Single(await context.Users.ToListAsync());
        Assert.Single(await context.CreateOperations.ToListAsync());
    }

    [Fact]
    public async Task KeyedCreate_UnrelatedExistingIdentityDoesNotGainOwnershipReceipt()
    {
        await using var context = await postgres.CreateCustomerContextAsync();
        var service = new CustomerIdentityAdminService(context, new PasswordHasher<LegacyIdentityRow>());
        var request = new CreateCustomerIdentityRequest(
            "customer@example.com", "customer@example.com", "correct-password", true, null, null, null);
        Assert.NotNull(await service.CreateAsync(42, request, default));

        var result = await service.CreateOrReconcileAsync(
            42, "service:legacy-intranet", Guid.NewGuid(), request, default);

        Assert.Equal(CustomerIdentityCreateOutcome.Conflict, result.Outcome);
        Assert.Empty(await context.CreateOperations.ToListAsync());
    }

    [Fact]
    public async Task KeyedCreate_DeletedOrReplacedIdentityCannotBeReplayed()
    {
        await using var context = await postgres.CreateCustomerContextAsync();
        var service = new CustomerIdentityAdminService(context, new PasswordHasher<LegacyIdentityRow>());
        var request = new CreateCustomerIdentityRequest(
            "customer@example.com", "customer@example.com", "correct-password", true, null, null, null);
        var key = Guid.NewGuid();
        Assert.Equal(CustomerIdentityCreateOutcome.Created,
            (await service.CreateOrReconcileAsync(42, "service:legacy-intranet", key, request, default)).Outcome);
        var originalIdentityId = (await context.Users.AsNoTracking().SingleAsync()).Id;

        Assert.True(await service.DeleteAsync(42, default));
        Assert.Equal(CustomerIdentityCreateOutcome.Conflict,
            (await service.CreateOrReconcileAsync(42, "service:legacy-intranet", key, request, default)).Outcome);

        var replacement = await service.CreateAsync(42, request, default);
        Assert.NotNull(replacement);
        Assert.NotEqual(originalIdentityId, replacement.Id);
        Assert.Equal(CustomerIdentityCreateOutcome.Conflict,
            (await service.CreateOrReconcileAsync(42, "service:legacy-intranet", key, request, default)).Outcome);
        Assert.Single(await context.CreateOperations.AsNoTracking().ToListAsync());
    }

    [Fact]
    public async Task KeyedCreate_ConcurrentSameKeyCommitsOneIdentityAndOneReceipt()
    {
        await using var first = await postgres.CreateCustomerContextAsync();
        await using var second = new CustomerIdentityDbContext(
            new DbContextOptionsBuilder<CustomerIdentityDbContext>()
                .UseNpgsql(first.Database.GetConnectionString()).Options);
        var hasher = new PasswordHasher<LegacyIdentityRow>();
        var request = new CreateCustomerIdentityRequest(
            "customer@example.com", "customer@example.com", "correct-password", true, null, null, null);
        var key = Guid.NewGuid();

        var results = await Task.WhenAll(
            new CustomerIdentityAdminService(first, hasher).CreateOrReconcileAsync(
                42, "service:legacy-intranet", key, request, default),
            new CustomerIdentityAdminService(second, hasher).CreateOrReconcileAsync(
                42, "service:legacy-intranet", key, request, default));

        Assert.Contains(results, result => result.Outcome == CustomerIdentityCreateOutcome.Created);
        Assert.Contains(results, result => result.Outcome == CustomerIdentityCreateOutcome.Replayed);
        Assert.Single(await first.Users.AsNoTracking().ToListAsync());
        Assert.Single(await first.CreateOperations.AsNoTracking().ToListAsync());
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
    public void Controller_UsesLeastPrivilegeCreatePermissionAndNeverCarriesPasswordInRoute()
    {
        var controller = typeof(CustomerIdentitiesController);
        Assert.Null(controller.GetCustomAttribute<AuthorizeAttribute>());
        var create = controller.GetMethod(nameof(CustomerIdentitiesController.Create))!;
        var route = create.GetCustomAttribute<HttpPostAttribute>()?.Template;

        Assert.Equal(
            "legacy-auth.customer-identities.create",
            Assert.Single(create.GetCustomAttributes<RequirePermissionAttribute>()).Permission);
        Assert.Equal("{databaseId:int}", route);
        Assert.DoesNotContain("password", route, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(create.GetParameters(), parameter => parameter.ParameterType == typeof(CreateCustomerIdentityRequest));
        Assert.DoesNotContain(create.GetParameters(), parameter =>
            string.Equals(parameter.Name, "password", StringComparison.OrdinalIgnoreCase));

        var setup = controller.GetMethod(nameof(CustomerIdentitiesController.CreatePasswordSetupChallenge))!;
        Assert.Equal(
            "legacy-auth.customer-identities.create",
            Assert.Single(setup.GetCustomAttributes<RequirePermissionAttribute>()).Permission);
        Assert.Equal(
            "{databaseId:int}/password-setup",
            setup.GetCustomAttribute<HttpPostAttribute>()?.Template);
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
