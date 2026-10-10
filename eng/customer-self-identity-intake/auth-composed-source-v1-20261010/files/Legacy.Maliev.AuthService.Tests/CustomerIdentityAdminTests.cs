using Legacy.Maliev.AuthService.Api.Controllers;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Reflection;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class CustomerIdentityAdminTests(PostgresFixture postgres)
{
    [Theory]
    [InlineData("update")]
    [InlineData("delete")]
    public async Task Delete_WaitsForCurrentOwnerAndPreservesExistingControllerOutcomes(string contender)
    {
        await using var context = await postgres.CreateCustomerContextAsync();
        await using var state = await postgres.CreateStateContextAsync();
        var nameA = "auth-delete-A-" + Guid.NewGuid().ToString("N");
        var nameB = "auth-delete-B-" + Guid.NewGuid().ToString("N");
        var connectionA = new NpgsqlConnectionStringBuilder(context.Database.GetConnectionString()) { ApplicationName = nameA, Pooling = false };
        var connectionB = new NpgsqlConnectionStringBuilder(connectionA.ConnectionString) { ApplicationName = nameB };
        context.Database.SetConnectionString(connectionA.ConnectionString);
        await using var other = new CustomerIdentityDbContext(new DbContextOptionsBuilder<CustomerIdentityDbContext>().UseNpgsql(connectionB.ConnectionString).Options);
        await using var blocker = new CustomerIdentityDbContext(new DbContextOptionsBuilder<CustomerIdentityDbContext>().UseNpgsql(connectionA.ConnectionString).Options);
        var hasher = new PasswordHasher<LegacyIdentityRow>();
        context.Users.Add(new() { Id = "owner", DatabaseID = 42, UserName = "owner@example.com", Email = "owner@example.com",
            SecurityStamp = "original-security", ConcurrencyStamp = "original-concurrency" });
        context.Users.Add(new() { Id = "other", DatabaseID = 43, UserName = "other@example.com", Email = "other@example.com",
            SecurityStamp = "other-security", ConcurrencyStamp = "other-concurrency" });
        await context.SaveChangesAsync();
        var untouched = System.Text.Json.JsonSerializer.Serialize(await context.Users.AsNoTracking().SingleAsync(row => row.Id == "other"));
        var first = new CustomerIdentitiesController(new CustomerIdentityAdminService(context, hasher, StoredProfile()),
            new CustomerSelfService(context, state, hasher, TimeProvider.System));
        var second = new CustomerIdentitiesController(new CustomerIdentityAdminService(other, hasher, StoredProfile()),
            new CustomerSelfService(other, state, hasher, TimeProvider.System));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<IActionResult>? pendingA = null, pendingB = null;
        System.Runtime.ExceptionServices.ExceptionDispatchInfo? primary = null;
        var cleanupFailures = new List<Exception>();
        var transaction = await blocker.Database.BeginTransactionAsync(timeout.Token);
        try
        {
            await blocker.Database.ExecuteSqlRawAsync("SELECT * FROM \"AspNetUsers\" WHERE \"DatabaseID\" = 42 FOR UPDATE", timeout.Token);
            pendingA = first.Delete(42, timeout.Token);
            if (contender == "delete") pendingB = second.Delete(42, timeout.Token);
            var expected = contender == "delete" ? 2 : 1;
            var waiters = 0;
            for (var attempt = 0; attempt < 500 && waiters != expected; attempt++)
            {
                waiters = await blocker.Database.SqlQuery<int>($"""
                    SELECT count(*)::integer AS "Value" FROM pg_stat_activity
                    WHERE datname = current_database() AND pid <> pg_backend_pid()
                      AND application_name IN ({nameA}, {nameB}) AND wait_event_type = 'Lock'
                      AND query LIKE '%AspNetUsers%' AND query LIKE '%FOR UPDATE%'
                    """).SingleAsync(timeout.Token);
                if (waiters != expected) await Task.Delay(10, timeout.Token);
            }
            Assert.Equal(expected, waiters);
            Assert.False(pendingA.IsCompleted);
            if (pendingB is not null) Assert.False(pendingB.IsCompleted);
            if (contender == "update")
            {
                await blocker.Users.Where(row => row.DatabaseID == 42).ExecuteUpdateAsync(setters => setters
                    .SetProperty(row => row.SecurityStamp, "updated-security")
                    .SetProperty(row => row.ConcurrencyStamp, "updated-concurrency"), timeout.Token);
            }
            await transaction.CommitAsync(timeout.Token);
            if (pendingB is null) Assert.IsType<NoContentResult>(await pendingA);
            else
            {
                var results = await Task.WhenAll(pendingA, pendingB);
                Assert.Single(results, result => result is NoContentResult);
                Assert.Single(results, result => result is NotFoundResult);
            }
            Assert.False(await context.Users.AsNoTracking().AnyAsync(row => row.DatabaseID == 42));
            Assert.Equal(untouched, System.Text.Json.JsonSerializer.Serialize(await context.Users.AsNoTracking().SingleAsync(row => row.Id == "other")));
            Assert.IsType<NotFoundResult>(await first.Delete(42, timeout.Token));
        }
        catch (Exception failure) { primary = System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure); }
        finally
        {
            try { await transaction.DisposeAsync(); } catch (Exception failure) { cleanupFailures.Add(failure); }
            if ((pendingA is { IsCompleted: false } || pendingB is { IsCompleted: false }) && (primary is not null || cleanupFailures.Count > 0))
            {
                try { timeout.Cancel(); } catch (Exception failure) { cleanupFailures.Add(failure); }
            }
            async Task JoinAsync(Task? pending)
            {
                if (pending is null) return;
                try { await pending; }
                catch (OperationCanceledException) when (timeout.IsCancellationRequested) { }
                catch (Exception failure) { if (!ReferenceEquals(primary?.SourceException, failure)) cleanupFailures.Add(failure); }
            }
            await JoinAsync(pendingA);
            await JoinAsync(pendingB);
        }
        if (primary is not null)
        {
            if (cleanupFailures.Count > 0)
            {
                try { primary.SourceException.Data["OwnedDeleteCleanupFailures"] = new AggregateException(cleanupFailures); } catch { }
            }
            primary.Throw();
        }
        if (cleanupFailures.Count > 0) throw new AggregateException("Owned delete cleanup failed.", cleanupFailures);
    }

    [Fact]
    public void Delete_PreservesExistingPermissionEmployeePolicyAndRoute()
    {
        var method = typeof(CustomerIdentitiesController).GetMethod(nameof(CustomerIdentitiesController.Delete))!;
        Assert.Equal("{databaseId:int}", method.GetCustomAttribute<HttpDeleteAttribute>()!.Template);
        Assert.Equal("LegacyEmployee", Assert.Single(method.GetCustomAttributes<AuthorizeAttribute>()).Policy);
        Assert.Equal("legacy-auth.customer-identities.delete", Assert.Single(method.GetCustomAttributes<RequirePermissionAttribute>()).Permission);
    }

    [Fact]
    public async Task Create_PersistsCompatiblePasswordHashAndReturnsNoSecurityMaterial()
    {
        await using var context = await postgres.CreateCustomerContextAsync();
        var hasher = new PasswordHasher<LegacyIdentityRow>();
        var service = new CustomerIdentityAdminService(context, hasher, StoredProfile());

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
        var service = new CustomerIdentityAdminService(context, new PasswordHasher<LegacyIdentityRow>(), StoredProfile());
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
        var service = new CustomerIdentityAdminService(context, new PasswordHasher<LegacyIdentityRow>(), StoredProfile());
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
        var service = new CustomerIdentityAdminService(context, new PasswordHasher<LegacyIdentityRow>(), StoredProfile());
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
        var service = new CustomerIdentityAdminService(context, new PasswordHasher<LegacyIdentityRow>(), StoredProfile());
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
            new CustomerIdentityAdminService(first, hasher, StoredProfile()).CreateOrReconcileAsync(
                42, "service:legacy-intranet", key, request, default),
            new CustomerIdentityAdminService(second, hasher, StoredProfile()).CreateOrReconcileAsync(
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
        var service = new CustomerIdentityAdminService(context, new PasswordHasher<LegacyIdentityRow>(), StoredProfile());
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

    private static FixedCustomerProfileBinding StoredProfile() => new(new CustomerProfileBinding(42, "customer@example.com", null, null, null));

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
