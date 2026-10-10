using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.AuthService.Api.Authorization;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class RefreshSessionIdentityBoundaryHttpTests(PostgresFixture postgres)
{
    private const string SharedId = "independently-owned-same-id";
    private const string CustomerRoot = "/auth/v1/customer-self-service/";
    private const string Password = "session-boundary-original-password";
    private const string ReplacementPassword = "session-boundary-replacement-password";

    [Theory]
    [InlineData("invalid-token")]
    [InlineData("invalid-password")]
    [InlineData("database-failure")]
    public async Task PersistedMarker_FailedReplacementRetainsMarkersHashAndStamp(string failureMode)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.Client();
        await PrepareSessionsAsync(stores, client);
        stores.Customers.Set<IdentityUserClaim<string>>().Add(new() { UserId = SharedId, ClaimType = "maliev:credential_state", ClaimValue = "temporary_password" });
        await stores.Customers.SaveChangesAsync();
        using var login = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest("customer@example.com", Password, IdentityKind.Customer));
        Assert.Equal(HttpStatusCode.Conflict, login.StatusCode);
        var action = Assert.IsType<AuthenticationRequiredAction>(await login.Content.ReadFromJsonAsync<AuthenticationRequiredAction>());
        var identityBefore = JsonSerializer.Serialize(await stores.Customers.Users.AsNoTracking().SingleAsync(row => row.Id == SharedId));
        var claimsBefore = JsonSerializer.Serialize(await stores.Customers.Set<IdentityUserClaim<string>>().AsNoTracking().OrderBy(claim => claim.Id).ToListAsync());
        if (failureMode == "database-failure")
        {
            await stores.Customers.Database.ExecuteSqlRawAsync("""
                CREATE FUNCTION reject_password_replacement() RETURNS trigger LANGUAGE plpgsql AS $body$
                BEGIN RAISE EXCEPTION 'synthetic password write failure'; END; $body$;
                CREATE TRIGGER reject_password_replacement BEFORE UPDATE ON "AspNetUsers"
                FOR EACH ROW EXECUTE FUNCTION reject_password_replacement();
                """);
        }
        using var bff = await factory.ServiceClientAsync();
        using var response = await bff.PostAsJsonAsync(CustomerRoot + "initial-password/complete",
            new CompleteInitialPasswordRequest("customer@example.com", failureMode == "invalid-token" ? "invalid" : action.Token,
                failureMode == "invalid-password" ? "" : ReplacementPassword));
        Assert.Equal(failureMode == "database-failure" ? HttpStatusCode.InternalServerError : HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(identityBefore, JsonSerializer.Serialize(await stores.Customers.Users.AsNoTracking().SingleAsync(row => row.Id == SharedId)));
        Assert.Equal(claimsBefore, JsonSerializer.Serialize(await stores.Customers.Set<IdentityUserClaim<string>>().AsNoTracking().OrderBy(claim => claim.Id).ToListAsync()));
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(action.Token, body);
        Assert.DoesNotContain("temporary_password", body);
    }

    [Theory]
    [InlineData("initial-password")]
    [InlineData("password-reset")]
    public async Task PersistedMarker_ReplacementRechecksStampAfterWaitingForLockedOwner(string operation)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.Client();
        stores.Customers.Set<IdentityUserClaim<string>>().Add(new() { UserId = SharedId, ClaimType = "maliev:credential_state", ClaimValue = "temporary_password" });
        await stores.Customers.SaveChangesAsync();
        using var bff = await factory.ServiceClientAsync();
        string token;
        if (operation == "initial-password")
        {
            using var login = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest("customer@example.com", Password, IdentityKind.Customer));
            token = Assert.IsType<AuthenticationRequiredAction>(await login.Content.ReadFromJsonAsync<AuthenticationRequiredAction>()).Token;
        }
        else
        {
            using var issued = await bff.PostAsJsonAsync(CustomerRoot + "password-reset/request", new CustomerActionRequest("customer@example.com"));
            token = Assert.IsType<CustomerActionChallenge>(await issued.Content.ReadFromJsonAsync<CustomerActionChallenge>()).Token!;
        }
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<HttpResponseMessage>? completion = null;
        HttpResponseMessage? response = null;
        System.Runtime.ExceptionServices.ExceptionDispatchInfo? primary = null;
        var cleanupFailures = new List<Exception>();
        var transaction = await stores.Customers.Database.BeginTransactionAsync(timeout.Token);
        try
        {
            await stores.Customers.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT * FROM \"AspNetUsers\" WHERE \"Id\" = {SharedId} FOR UPDATE", timeout.Token);
            completion = operation == "initial-password"
                ? bff.PostAsJsonAsync(CustomerRoot + "initial-password/complete", new CompleteInitialPasswordRequest("customer@example.com", token, ReplacementPassword), timeout.Token)
                : bff.PostAsJsonAsync(CustomerRoot + "password-reset/complete", new CompletePasswordResetRequest("customer@example.com", token, ReplacementPassword), timeout.Token);
            var blocked = false;
            for (var attempt = 0; attempt < 500 && !blocked; attempt++)
            {
                blocked = await stores.Customers.Database.SqlQueryRaw<int>("""
                    SELECT count(*)::integer AS "Value" FROM pg_stat_activity
                    WHERE datname = current_database() AND pid <> pg_backend_pid()
                      AND wait_event_type = 'Lock' AND query LIKE '%AspNetUsers%' AND query LIKE '%FOR UPDATE%'
                    """).SingleAsync(timeout.Token) > 0;
                if (!blocked) await Task.Delay(10, timeout.Token);
            }
            Assert.True(blocked, "Actual replacement must wait for the owned user-row lock.");
            await stores.Customers.Users.Where(row => row.Id == SharedId)
                .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.SecurityStamp, "new-owner-generation"), timeout.Token);
            await transaction.CommitAsync(timeout.Token);
            response = await completion;
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Single(await stores.Customers.Set<IdentityUserClaim<string>>().AsNoTracking().ToListAsync());
            var row = await stores.Customers.Users.AsNoTracking().SingleAsync(value => value.Id == SharedId);
            Assert.Equal("new-owner-generation", row.SecurityStamp);
            Assert.Equal(PasswordVerificationResult.Success, new PasswordHasher<LegacyIdentityRow>().VerifyHashedPassword(row, row.PasswordHash!, Password));
        }
        catch (Exception failure)
        {
            primary = System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure);
        }
        finally
        {
            try { await transaction.DisposeAsync(); }
            catch (Exception failure) { cleanupFailures.Add(failure); }
            if (completion is not null && !completion.IsCompleted && (primary is not null || cleanupFailures.Count > 0))
            {
                try { timeout.Cancel(); }
                catch (Exception failure) { cleanupFailures.Add(failure); }
            }
            if (completion is not null && response is null)
            {
                try { response = await completion; }
                catch (OperationCanceledException) when (timeout.IsCancellationRequested) { }
                catch (Exception failure)
                {
                    if (!ReferenceEquals(primary?.SourceException, failure)) cleanupFailures.Add(failure);
                }
            }
            try { response?.Dispose(); }
            catch (Exception failure) { cleanupFailures.Add(failure); }
        }
        if (primary is not null)
        {
            if (cleanupFailures.Count > 0)
            {
                try { primary.SourceException.Data["OwnedRaceCleanupFailures"] = new AggregateException(cleanupFailures); }
                catch { /* Secondary reporting must not replace the primary failure. */ }
            }
            primary.Throw();
        }
        if (cleanupFailures.Count > 0) throw new AggregateException("Owned race cleanup failed.", cleanupFailures);
    }

    [Theory]
    [InlineData("exact", true)]
    [InlineData("flag", true)]
    [InlineData("wrong-type", false)]
    [InlineData("wrong-value", false)]
    [InlineData("other-owner", false)]
    [InlineData("employee-only", false)]
    [InlineData("user-input", false)]
    public async Task PersistedMarker_CustomerLoginAndRefreshRequireOnlyExactOwnedState(string scenario, bool required)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.Client();
        var sessions = await PrepareSessionsAsync(stores, client);
        if (scenario == "flag")
            await stores.Customers.Users.Where(row => row.Id == SharedId).ExecuteUpdateAsync(setters => setters.SetProperty(row => row.PasswordSetupRequired, true));
        if (scenario != "employee-only" && scenario != "flag" && scenario != "user-input")
        {
            stores.Customers.Set<IdentityUserClaim<string>>().Add(new()
            {
                UserId = scenario == "other-owner" ? "unrelated-customer" : SharedId,
                ClaimType = scenario == "wrong-type" ? "maliev:credential_state:other" : "maliev:credential_state",
                ClaimValue = scenario == "wrong-value" ? "Temporary_Password" : "temporary_password",
            });
            await stores.Customers.SaveChangesAsync();
        }
        stores.Employees.Set<IdentityUserClaim<string>>().Add(new() { UserId = SharedId, ClaimType = "maliev:credential_state", ClaimValue = "temporary_password" });
        await stores.Employees.SaveChangesAsync();
        var claimsBefore = JsonSerializer.Serialize(await stores.Customers.Set<IdentityUserClaim<string>>().AsNoTracking().OrderBy(claim => claim.Id).ToListAsync());
        var sessionsBefore = await stores.State.RefreshSessions.CountAsync();
        using var login = scenario == "user-input"
            ? await client.PostAsJsonAsync("/auth/v1/login", new { UserName = "customer@example.com", Password, IdentityKind = IdentityKind.Customer,
                PasswordSetupRequired = true, Claims = new[] { new { Type = "maliev:credential_state", Value = "temporary_password" } } })
            : await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest("customer@example.com", Password, IdentityKind.Customer));
        Assert.Equal(required ? HttpStatusCode.Conflict : HttpStatusCode.OK, login.StatusCode);
        if (required)
        {
            var action = Assert.IsType<AuthenticationRequiredAction>(await login.Content.ReadFromJsonAsync<AuthenticationRequiredAction>());
            Assert.Equal("set_initial_password", action.Action);
            Assert.False(string.IsNullOrWhiteSpace(action.Token));
            Assert.Equal(sessionsBefore, await stores.State.RefreshSessions.CountAsync());
            var persisted = await stores.State.IdentityActionTokens.AsNoTracking().SingleAsync(value => value.Purpose == "initial-password");
            Assert.InRange(persisted.ExpiresAt, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));
        }
        using var refresh = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(sessions.Customer.RefreshToken));
        Assert.Equal(required ? HttpStatusCode.Unauthorized : HttpStatusCode.OK, refresh.StatusCode);
        using var currentCustomer = factory.Client(sessions.Customer.AccessToken);
        using var identityResponse = await currentCustomer.GetAsync(CustomerRoot + "identity");
        Assert.Equal(required ? HttpStatusCode.Forbidden : HttpStatusCode.OK, identityResponse.StatusCode);
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var setup = await scope.ServiceProvider.GetRequiredService<CustomerSelfService>()
                .IssueInitialPasswordChallengeForDatabaseIdAsync(42, default);
            Assert.Equal(required, setup.Accepted);
            Assert.Equal(required, !string.IsNullOrWhiteSpace(setup.Token));
        }
        Assert.Equal(claimsBefore, JsonSerializer.Serialize(await stores.Customers.Set<IdentityUserClaim<string>>().AsNoTracking().OrderBy(claim => claim.Id).ToListAsync()));
        using var employeeRefresh = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(sessions.Employee.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, employeeRefresh.StatusCode);
    }

    [Theory]
    [InlineData("initial-password")]
    [InlineData("password-reset")]
    public async Task PersistedMarker_SuccessfulPasswordReplacementClearsOnlyExactOwnedMarkers(string operation)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.Client();
        var sessions = await PrepareSessionsAsync(stores, client);
        stores.Customers.Set<IdentityUserClaim<string>>().AddRange(
            new() { UserId = SharedId, ClaimType = "maliev:credential_state", ClaimValue = "temporary_password" },
            new() { UserId = SharedId, ClaimType = "maliev:credential_state", ClaimValue = "temporary_password" },
            new() { UserId = SharedId, ClaimType = "maliev:credential_state", ClaimValue = "other" },
            new() { UserId = "unrelated-customer", ClaimType = "maliev:credential_state", ClaimValue = "temporary_password" });
        await stores.Customers.SaveChangesAsync();
        var retained = JsonSerializer.Serialize(await stores.Customers.Set<IdentityUserClaim<string>>().AsNoTracking()
            .Where(claim => claim.UserId != SharedId || claim.ClaimValue != "temporary_password").OrderBy(claim => claim.Id).ToListAsync());
        using var bff = await factory.ServiceClientAsync();
        string token;
        if (operation == "initial-password")
        {
            using var login = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest("customer@example.com", Password, IdentityKind.Customer));
            Assert.Equal(HttpStatusCode.Conflict, login.StatusCode);
            token = Assert.IsType<AuthenticationRequiredAction>(await login.Content.ReadFromJsonAsync<AuthenticationRequiredAction>()).Token;
        }
        else
        {
            using var issued = await bff.PostAsJsonAsync(CustomerRoot + "password-reset/request", new CustomerActionRequest("customer@example.com"));
            Assert.Equal(HttpStatusCode.OK, issued.StatusCode);
            token = Assert.IsType<CustomerActionChallenge>(await issued.Content.ReadFromJsonAsync<CustomerActionChallenge>()).Token!;
        }
        using var completed = operation == "initial-password"
            ? await bff.PostAsJsonAsync(CustomerRoot + "initial-password/complete", new CompleteInitialPasswordRequest("customer@example.com", token, ReplacementPassword))
            : await bff.PostAsJsonAsync(CustomerRoot + "password-reset/complete", new CompletePasswordResetRequest("customer@example.com", token, ReplacementPassword));
        Assert.Equal(HttpStatusCode.NoContent, completed.StatusCode);
        Assert.Equal(retained, JsonSerializer.Serialize(await stores.Customers.Set<IdentityUserClaim<string>>().AsNoTracking().OrderBy(claim => claim.Id).ToListAsync()));
        var current = await stores.Customers.Users.AsNoTracking().SingleAsync(row => row.Id == SharedId);
        Assert.False(current.PasswordSetupRequired);
        Assert.NotEqual("customer-generation", current.SecurityStamp);
        Assert.Equal(PasswordVerificationResult.Success, new PasswordHasher<LegacyIdentityRow>().VerifyHashedPassword(current, current.PasswordHash!, ReplacementPassword));
        using var oldRefresh = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(sessions.Customer.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, oldRefresh.StatusCode);
        using var newLogin = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest("customer@example.com", ReplacementPassword, IdentityKind.Customer));
        Assert.Equal(HttpStatusCode.OK, newLogin.StatusCode);
        using var employeeRefresh = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(sessions.Employee.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, employeeRefresh.StatusCode);
    }

    [Theory]
    [InlineData("initial-password")]
    [InlineData("password-reset")]
    [InlineData("email-change")]
    [InlineData("password-change")]
    [InlineData("password-create")]
    public async Task CustomerMutation_RevokesOnlyCustomerSessions_EmployeeWithSameIdStillRefreshes(string operation)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var anonymous = factory.Client();
        var sessions = await PrepareSessionsAsync(stores, anonymous);
        using var customer = factory.Client(sessions.Customer.AccessToken);
        using var bff = await factory.ServiceClientAsync();
        using var changed = await ApplyCustomerOperationAsync(stores, anonymous, customer, bff, operation);
        Assert.Equal(HttpStatusCode.NoContent, changed.StatusCode);

        var currentCustomer = await stores.Customers.Users.AsNoTracking().SingleAsync(row => row.Id == SharedId);
        Assert.NotEqual("customer-generation", currentCustomer.SecurityStamp);
        Assert.Equal(operation == "email-change" ? "new@example.com" : "customer@example.com", currentCustomer.Email);
        Assert.True(currentCustomer.EmailConfirmed);
        Assert.False(currentCustomer.PasswordSetupRequired);
        Assert.Equal(PasswordVerificationResult.Success,
            new PasswordHasher<LegacyIdentityRow>().VerifyHashedPassword(currentCustomer, currentCustomer.PasswordHash!, operation == "email-change" ? Password : ReplacementPassword));

        var rows = await stores.State.RefreshSessions.AsNoTracking().ToListAsync();
        Assert.All(rows.Where(row => sessions.ActiveCustomerIds.Contains(row.Id)), row => Assert.NotNull(row.RevokedAt));
        Assert.Equal(sessions.PreviouslyRevoked.RevokedAt, rows.Single(row => row.Id == sessions.PreviouslyRevoked.Id).RevokedAt);
        Assert.Equal(JsonSerializer.Serialize(sessions.OtherCustomer), JsonSerializer.Serialize(rows.Single(row => row.Id == sessions.OtherCustomer.Id)));
        Assert.Equal(sessions.EmployeeIdentity, JsonSerializer.Serialize(await stores.Employees.Users.AsNoTracking().SingleAsync()));
        using var customerRefresh = await anonymous.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(sessions.Customer.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, customerRefresh.StatusCode);

        // This reaches actual registered rotation, current identity/stamp checks and RS256 issuance.
        using var employeeRefresh = await anonymous.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(sessions.Employee.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, employeeRefresh.StatusCode);
        var refreshed = Assert.IsType<TokenResponse>(await employeeRefresh.Content.ReadFromJsonAsync<TokenResponse>());
        Assert.NotEqual(sessions.Employee.RefreshToken, refreshed.RefreshToken);
        var employeeRows = await stores.State.RefreshSessions.AsNoTracking().Where(row => row.IdentityKind == IdentityKind.Employee).ToListAsync();
        Assert.Equal(2, employeeRows.Count);
        Assert.All(employeeRows, row => Assert.Null(row.RevokedAt));
        Assert.All(employeeRows, row => Assert.Equal(SharedId, row.IdentityId));
        Assert.All(employeeRows, row => Assert.Equal("employee-generation", row.SecurityStamp));
    }

    [Fact]
    public async Task EmployeeReset_RevokesEmployeeGenerationOnly_CustomerWithSameIdStillRefreshes()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores, employeeRecovery: true);
        using var anonymous = factory.Client();
        var sessions = await PrepareSessionsAsync(stores, anonymous);
        using var bff = await factory.ServiceClientAsync();
        using var issued = await bff.PostAsJsonAsync("/auth/v1/employee-self-service/password-reset/request", new EmployeeActionRequest("employee@example.com"));
        Assert.Equal(HttpStatusCode.OK, issued.StatusCode);
        var challenge = Assert.IsType<EmployeeActionChallenge>(await issued.Content.ReadFromJsonAsync<EmployeeActionChallenge>());
        using var completed = await bff.PostAsJsonAsync("/auth/v1/employee-self-service/password-reset/complete",
            new CompleteEmployeePasswordResetRequest("employee@example.com", challenge.Token!, ReplacementPassword));
        Assert.Equal(HttpStatusCode.NoContent, completed.StatusCode);
        var rows = await stores.State.RefreshSessions.AsNoTracking().ToListAsync();
        Assert.NotNull(rows.Single(row => row.IdentityKind == IdentityKind.Employee).RevokedAt);
        Assert.All(rows.Where(row => sessions.ActiveCustomerIds.Contains(row.Id)), row => Assert.Null(row.RevokedAt));
        Assert.Equal(JsonSerializer.Serialize(sessions.OtherCustomer), JsonSerializer.Serialize(rows.Single(row => row.Id == sessions.OtherCustomer.Id)));
        using var customerRefresh = await anonymous.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(sessions.Customer.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, customerRefresh.StatusCode);
        using var employeeRefresh = await anonymous.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(sessions.Employee.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, employeeRefresh.StatusCode);
        Assert.Single(await stores.Employees.RecoveryEffects.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData(IdentityKind.Customer)]
    [InlineData(IdentityKind.Employee)]
    public async Task FamilyRevoke_WithSameIdentityId_DoesNotRevokeOtherKindOrOtherFamily(IdentityKind revokedKind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.Client();
        var customer = await LoginAsync(client, IdentityKind.Customer);
        var employee = await LoginAsync(client, IdentityKind.Employee);
        var peer = await LoginAsync(client, revokedKind);
        var revoked = revokedKind == IdentityKind.Customer ? customer : employee;
        var untouched = revokedKind == IdentityKind.Customer ? employee : customer;
        using var response = await client.PostAsJsonAsync("/auth/v1/revoke", new RevokeRequest(revoked.RefreshToken));
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        using var denied = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(revoked.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        using var otherKind = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(untouched.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, otherKind.StatusCode);
        using var otherFamily = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(peer.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, otherFamily.StatusCode);
        Assert.Single(await stores.State.RefreshSessions.AsNoTracking().ToListAsync(), row => row.RevokedAt is not null);
    }

    [Theory]
    [InlineData("anonymous", HttpStatusCode.Unauthorized)]
    [InlineData("employee", HttpStatusCode.Forbidden)]
    [InlineData("service", HttpStatusCode.Forbidden)]
    [InlineData("bad-signature", HttpStatusCode.Unauthorized)]
    public async Task CredentialRoute_InvalidCaller_PreservesBothKinds(string caller, HttpStatusCode expected)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var anonymous = factory.Client();
        var sessions = await PrepareSessionsAsync(stores, anonymous);
        var token = caller == "employee" ? sessions.Employee.AccessToken : sessions.Customer.AccessToken;
        if (caller == "bad-signature")
        {
            var parts = token.Split('.');
            token = parts[0] + "." + parts[1] + "." + Convert.ToBase64String(RandomNumberGenerator.GetBytes(256)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
        using var client = caller == "service" ? await factory.ServiceClientAsync() : factory.Client(caller == "anonymous" ? null : token);
        var before = await SnapshotAsync(stores);
        using var response = await client.PostAsJsonAsync(CustomerRoot + "password/change", new ChangeCustomerPasswordRequest(Password, ReplacementPassword));
        Assert.Equal(expected, response.StatusCode);
        Assert.Equal(before, await SnapshotAsync(stores));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InvalidCurrentPassword_PreservesBothIdentityKindsAndSessions(bool emailChange)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var anonymous = factory.Client();
        var sessions = await PrepareSessionsAsync(stores, anonymous);
        using var customer = factory.Client(sessions.Customer.AccessToken);
        var before = await SnapshotAsync(stores);
        using var response = emailChange
            ? await customer.PostAsJsonAsync(CustomerRoot + "email/change", new ChangeCustomerEmailRequest("wrong-password", "new@example.com"))
            : await customer.PostAsJsonAsync(CustomerRoot + "password/change", new ChangeCustomerPasswordRequest("wrong-password", ReplacementPassword));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(before, await SnapshotAsync(stores));
    }

    [Fact]
    public async Task RegisteredService_PrecancelledMutation_PreservesBothKindsAndPropagatesCancellation()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.Client();
        await PrepareSessionsAsync(stores, client);
        var before = await SnapshotAsync(stores);
        await using var scope = factory.Services.CreateAsyncScope();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => scope.ServiceProvider.GetRequiredService<CustomerSelfService>()
            .ChangePasswordAsync(SharedId, new ChangeCustomerPasswordRequest(Password, ReplacementPassword), cancellation.Token));
        Assert.Equal(before, await SnapshotAsync(stores));
    }

    private static async Task<HttpResponseMessage> ApplyCustomerOperationAsync(Stores stores, HttpClient anonymous, HttpClient customer, HttpClient bff, string operation)
    {
        if (operation == "password-change") return await customer.PostAsJsonAsync(CustomerRoot + "password/change", new ChangeCustomerPasswordRequest(Password, ReplacementPassword));
        if (operation == "password-create")
        {
            // Represent an already-authenticated migrated passwordless account, without fabricating its JWT or session.
            await stores.Customers.Users.Where(row => row.Id == SharedId).ExecuteUpdateAsync(setters => setters.SetProperty(row => row.PasswordHash, (string?)null));
            return await customer.PostAsJsonAsync(CustomerRoot + "password/create", new CreateCustomerPasswordRequest(ReplacementPassword));
        }
        if (operation == "initial-password")
        {
            // Existing sessions precede the controlled bootstrap-state transition. The challenge is genuinely issued by login.
            await stores.Customers.Users.Where(row => row.Id == SharedId).ExecuteUpdateAsync(setters => setters.SetProperty(row => row.PasswordSetupRequired, true));
            using var login = await anonymous.PostAsJsonAsync("/auth/v1/login", new LoginRequest("customer@example.com", Password, IdentityKind.Customer));
            Assert.Equal(HttpStatusCode.Conflict, login.StatusCode);
            var action = Assert.IsType<AuthenticationRequiredAction>(await login.Content.ReadFromJsonAsync<AuthenticationRequiredAction>());
            Assert.Equal("set_initial_password", action.Action);
            return await bff.PostAsJsonAsync(CustomerRoot + "initial-password/complete", new CompleteInitialPasswordRequest("customer@example.com", action.Token, ReplacementPassword));
        }
        using var issued = operation == "email-change"
            ? await customer.PostAsJsonAsync(CustomerRoot + "email/change", new ChangeCustomerEmailRequest(Password, "new@example.com"))
            : await bff.PostAsJsonAsync(CustomerRoot + "password-reset/request", new CustomerActionRequest("customer@example.com"));
        Assert.Equal(HttpStatusCode.OK, issued.StatusCode);
        var challenge = Assert.IsType<CustomerActionChallenge>(await issued.Content.ReadFromJsonAsync<CustomerActionChallenge>());
        Assert.True(challenge.Accepted);
        Assert.NotNull(challenge.Token);
        return operation == "email-change"
            ? await bff.PostAsJsonAsync(CustomerRoot + "email-change/complete", new CompleteCustomerActionRequest("new@example.com", challenge.Token))
            : await bff.PostAsJsonAsync(CustomerRoot + "password-reset/complete", new CompletePasswordResetRequest("customer@example.com", challenge.Token, ReplacementPassword));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CustomerRefresh_CurrentInitialPasswordState_ControlsFamilyAdmissionOnly(bool setupRequired)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.Client();
        var sessions = await PrepareSessionsAsync(stores, client);
        await stores.Customers.Users.Where(row => row.Id == SharedId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.PasswordSetupRequired, setupRequired));
        var identityBefore = JsonSerializer.Serialize(
            await stores.Customers.Users.AsNoTracking().OrderBy(row => row.Id).ToListAsync());
        var rowsBefore = await stores.State.RefreshSessions.AsNoTracking().ToListAsync();
        var currentHash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(sessions.Customer.RefreshToken)));
        var original = rowsBefore.Single(row => row.TokenHash == currentHash);
        var otherRows = rowsBefore.Where(row => row.FamilyId != original.FamilyId).OrderBy(row => row.Id).ToList();

        using var refresh = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(sessions.Customer.RefreshToken));

        Assert.Equal(setupRequired ? HttpStatusCode.Unauthorized : HttpStatusCode.OK, refresh.StatusCode);
        var rowsAfter = await stores.State.RefreshSessions.AsNoTracking().ToListAsync();
        var family = rowsAfter.Where(row => row.FamilyId == original.FamilyId).ToList();
        if (setupRequired)
        {
            Assert.Single(family);
            Assert.NotNull(family[0].RevokedAt);
            Assert.Null(family[0].RotatedAt);
            Assert.Null(family[0].ReplacedById);
            Assert.Equal(rowsBefore.Count, rowsAfter.Count);
            var body = await refresh.Content.ReadAsStringAsync();
            Assert.DoesNotContain("accessToken", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("refreshToken", body, StringComparison.OrdinalIgnoreCase);
            Assert.False(refresh.Headers.Contains("Set-Cookie"));
        }
        else
        {
            var token = Assert.IsType<TokenResponse>(await refresh.Content.ReadFromJsonAsync<TokenResponse>());
            Assert.NotEqual(sessions.Customer.RefreshToken, token.RefreshToken);
            Assert.Equal(2, family.Count);
            Assert.All(family, row => Assert.Null(row.RevokedAt));
        }
        Assert.Equal(JsonSerializer.Serialize(otherRows), JsonSerializer.Serialize(
            rowsAfter.Where(row => row.FamilyId != original.FamilyId).OrderBy(row => row.Id).ToList()));
        Assert.Equal(identityBefore, JsonSerializer.Serialize(
            await stores.Customers.Users.AsNoTracking().OrderBy(row => row.Id).ToListAsync()));
        Assert.Equal(sessions.EmployeeIdentity, JsonSerializer.Serialize(await stores.Employees.Users.AsNoTracking().SingleAsync()));
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
        using var employeeRefresh = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(sessions.Employee.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, employeeRefresh.StatusCode);
    }

    private static async Task<Sessions> PrepareSessionsAsync(Stores stores, HttpClient client)
    {
        var customer = await LoginAsync(client, IdentityKind.Customer);
        await LoginAsync(client, IdentityKind.Customer);
        var old = await LoginAsync(client, IdentityKind.Customer);
        var employee = await LoginAsync(client, IdentityKind.Employee);
        await LoginAsync(client, IdentityKind.Customer, unrelated: true);
        using var revoke = await client.PostAsJsonAsync("/auth/v1/revoke", new RevokeRequest(old.RefreshToken));
        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        var rows = await stores.State.RefreshSessions.AsNoTracking().ToListAsync();
        var active = rows.Where(row => row.IdentityKind == IdentityKind.Customer && row.IdentityId == SharedId && row.RevokedAt is null).Select(row => row.Id).ToArray();
        Assert.Equal(2, active.Length);
        return new(customer, employee, active, rows.Single(row => row.RevokedAt is not null), rows.Single(row => row.IdentityId == "unrelated-customer"),
            JsonSerializer.Serialize(await stores.Employees.Users.AsNoTracking().SingleAsync()));
    }

    private static async Task<TokenResponse> LoginAsync(HttpClient client, IdentityKind kind, bool unrelated = false)
    {
        using var response = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest(unrelated ? "unrelated@example.com" : kind == IdentityKind.Employee ? "employee@example.com" : "customer@example.com", Password, kind));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return Assert.IsType<TokenResponse>(await response.Content.ReadFromJsonAsync<TokenResponse>());
    }

    private static async Task<string> SnapshotAsync(Stores stores) => JsonSerializer.Serialize(new
    {
        Customers = await stores.Customers.Users.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
        Employees = await stores.Employees.Users.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
        Sessions = await stores.State.RefreshSessions.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
        Actions = await stores.State.IdentityActionTokens.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
    });

    private sealed record Sessions(TokenResponse Customer, TokenResponse Employee, Guid[] ActiveCustomerIds, RefreshSession PreviouslyRevoked, RefreshSession OtherCustomer, string EmployeeIdentity);

    private sealed class Factory(Stores stores, bool employeeRecovery = false) : WebApplicationFactory<Program>
    {
        private readonly RSA signing = RSA.Create(2048);
        private readonly string secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:CustomerIdentity"] = stores.Customers.Database.GetConnectionString(),
                ["ConnectionStrings:EmployeeIdentity"] = stores.Employees.Database.GetConnectionString(),
                ["ConnectionStrings:RefreshSessions"] = stores.State.Database.GetConnectionString(),
                ["Jwt:Issuer"] = "https://session-boundary.test",
                ["Jwt:Audience"] = "session-boundary-test",
                ["Jwt:PrivateKeyPem"] = signing.ExportPkcs8PrivateKeyPem(),
                ["Jwt:KeyId"] = "session-boundary-test",
                ["ServiceClients:Clients:legacy-intranet:SecretSha256"] = ServiceClientCredential.HashSecret(secret),
                ["ServiceClients:Clients:legacy-intranet:Permissions:0"] = CustomerSelfServicePermissions.Use,
                ["ServiceClients:Clients:legacy-intranet:Permissions:1"] = EmployeeSelfServicePermissions.Use,
                ["EmployeeRecovery:Enabled"] = employeeRecovery.ToString(),
            }));
        }
        public HttpClient Client(string? token = null)
        {
            var client = CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
            if (token is not null) client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return client;
        }
        public async Task<HttpClient> ServiceClientAsync()
        {
            using var client = Client();
            using var response = await client.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest("legacy-intranet", secret));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return Client(Assert.IsType<ServiceTokenResponse>(await response.Content.ReadFromJsonAsync<ServiceTokenResponse>()).AccessToken);
        }
        public override async ValueTask DisposeAsync()
        {
            var connections = new List<NpgsqlConnection>();
            await using (var scope = Services.CreateAsyncScope())
            {
                var contexts = new DbContext[] { scope.ServiceProvider.GetRequiredService<CustomerIdentityDbContext>(), scope.ServiceProvider.GetRequiredService<EmployeeIdentityDbContext>(), scope.ServiceProvider.GetRequiredService<RefreshSessionDbContext>() };
                foreach (var context in contexts)
                {
                    await context.Database.OpenConnectionAsync();
                    connections.Add((NpgsqlConnection)context.Database.GetDbConnection());
                    await context.Database.CloseConnectionAsync();
                }
            }
            await base.DisposeAsync();
            signing.Dispose();
            foreach (var connection in connections) NpgsqlConnection.ClearPool(connection);
        }
    }

    private sealed class Stores(CustomerIdentityDbContext customers, EmployeeIdentityDbContext employees, RefreshSessionDbContext state) : IAsyncDisposable
    {
        public CustomerIdentityDbContext Customers { get; } = customers;
        public EmployeeIdentityDbContext Employees { get; } = employees;
        public RefreshSessionDbContext State { get; } = state;
        public static async Task<Stores> CreateAsync(PostgresFixture postgres)
        {
            var stores = new Stores(await postgres.CreateCustomerContextAsync(), await postgres.CreateEmployeeContextAsync(), await postgres.CreateStateContextAsync());
            stores.Customers.Users.Add(Identity(SharedId, "customer@example.com", "customer-generation"));
            stores.Customers.Users.Add(Identity("unrelated-customer", "unrelated@example.com", "unrelated-generation"));
            stores.Employees.Users.Add(Identity(SharedId, "employee@example.com", "employee-generation"));
            await stores.Customers.SaveChangesAsync();
            await stores.Employees.SaveChangesAsync();
            return stores;
        }
        private static LegacyIdentityRow Identity(string id, string email, string stamp)
        {
            var row = new LegacyIdentityRow { Id = id, DatabaseID = id == SharedId ? 42 : 43, UserName = email, NormalizedUserName = email.ToUpperInvariant(), Email = email, NormalizedEmail = email.ToUpperInvariant(), EmailConfirmed = true, SecurityStamp = stamp, ConcurrencyStamp = Guid.NewGuid().ToString() };
            row.PasswordHash = new PasswordHasher<LegacyIdentityRow>().HashPassword(row, Password);
            return row;
        }
        public async ValueTask DisposeAsync()
        {
            var connections = new[] { Customers.Database.GetDbConnection(), Employees.Database.GetDbConnection(), State.Database.GetDbConnection() };
            await Customers.DisposeAsync();
            await Employees.DisposeAsync();
            await State.DisposeAsync();
            foreach (var connection in connections) NpgsqlConnection.ClearPool((NpgsqlConnection)connection);
        }
    }
}
