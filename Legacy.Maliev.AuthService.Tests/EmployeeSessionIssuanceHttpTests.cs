using System.IdentityModel.Tokens.Jwt;
using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Legacy.Maliev.AuthService.Api.Authorization;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Npgsql;
using Maliev.Aspire.ServiceDefaults.LegacyAuth;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class EmployeeSessionIssuanceHttpTests(PostgresFixture postgres)
{
    [Fact]
    public async Task NormalEmployeeProfileBinding_SupplementaryUnicodeUsesProducerScalarBoundsAndStoredCopy()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        var storedEmail = string.Concat(Enumerable.Repeat("\U0001f600", 249)) + "@x.test";
        var storedPhone = string.Concat(Enumerable.Repeat("\U0001f600", 256));
        Assert.Equal(256, storedEmail.EnumerateRunes().Count());
        Assert.True(storedEmail.Length > 320);
        Assert.True(new System.ComponentModel.DataAnnotations.EmailAddressAttribute().IsValid(storedEmail));
        Assert.Equal(storedEmail, new System.Net.Mail.MailAddress(storedEmail).Address);
        Assert.Equal(256, storedPhone.EnumerateRunes().Count());
        Assert.True(storedPhone.Length > 256);
        factory.Profiles[72] = new(72, storedEmail, storedPhone);
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, false);
        using var created = await client.PostAsJsonAsync("/auth/v1/employee-identities/72",
            new CreateEmployeeIdentityRequest("caller-name@profile.test", "untrusted@request.test", "abcdef", true, "+66999999999"));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var identity = await stores.Employees.Users.AsNoTracking().SingleAsync(value => value.DatabaseID == 72);
        Assert.Equal(storedEmail, identity.Email);
        Assert.Equal(storedPhone, identity.PhoneNumber);
        Assert.Equal(1, factory.ProfileReads);
    }

    [Theory]
    [InlineData(65)]
    [InlineData(256)]
    public async Task NormalEmployeeProfileBinding_PersistedPhonePreservesProducerLengthsBeyondRequestLimit(int length)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        var storedPhone = new string('1', length);
        factory.Profiles[72] = new(72, "persisted@profile.test", storedPhone);
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, false);
        using var created = await client.PostAsJsonAsync("/auth/v1/employee-identities/72",
            new CreateEmployeeIdentityRequest("caller-name@profile.test", "untrusted@request.test", "abcdef", true, "+66999999999"));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var identity = await stores.Employees.Users.AsNoTracking().SingleAsync(value => value.DatabaseID == 72);
        Assert.Equal(storedPhone, identity.PhoneNumber);
        Assert.Equal("persisted@profile.test", identity.Email);
        Assert.Equal(1, factory.ProfileReads);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NormalEmployeeProfileBinding_CreateUsesPersistedFieldsWithOwnWorkloadAuthority(bool serviceCaller)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        factory.Profiles[72] = new(72, "cafe\u0301@profile.test", "+66812345678");
        using var client = factory.CreateClient();
        if (serviceCaller)
        {
            using var login = await client.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest("profile-create-test", Factory.ServiceSecret));
            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
            client.DefaultRequestHeaders.Authorization = new("Bearer", (await login.Content.ReadFromJsonAsync<ServiceTokenResponse>())!.AccessToken);
        }
        else await AuthorizeAdministrationAsync(client, false);
        var beforeSessions = await stores.State.RefreshSessions.CountAsync();
        using var response = await client.PostAsJsonAsync("/auth/v1/employee-identities/72",
            new CreateEmployeeIdentityRequest("caller-name@profile.test", "untrusted@request.test", "abcdef", false, "+66999999999"));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var identity = await stores.Employees.Users.AsNoTracking().SingleAsync(value => value.DatabaseID == 72);
        Assert.Equal("caller-name@profile.test", identity.UserName);
        Assert.Equal("cafe\u0301@profile.test", identity.Email);
        Assert.Equal("CAF\u00c9@PROFILE.TEST", identity.NormalizedEmail);
        Assert.Equal("+66812345678", identity.PhoneNumber);
        Assert.False(identity.EmailConfirmed);
        Assert.Equal(beforeSessions, await stores.State.RefreshSessions.CountAsync());
        Assert.Equal(1, factory.ProfileReads);
        Assert.Empty(await stores.Customers.CreateOperations.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.Employees.RecoveryEffects.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData("missing", 404)]
    [InlineData("unavailable", 503)]
    [InlineData("forbidden", 503)]
    [InlineData("redirect", 503)]
    [InlineData("malformed", 503)]
    [InlineData("wrong-id", 503)]
    [InlineData("duplicate-id", 503)]
    [InlineData("wrong-case", 503)]
    [InlineData("invalid-email", 503)]
    [InlineData("wrong-phone-type", 503)]
    [InlineData("beyond-phone-schema", 503)]
    [InlineData("beyond-email-schema", 503)]
    [InlineData("oversized", 503)]
    [InlineData("missing-own-grant", 503)]
    public async Task NormalEmployeeProfileBinding_FailedAuthorityHasNoIdentityOrSessionEffects(string failure, int expected)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        factory.Profiles[72] = new(72, "persisted@profile.test", null);
        factory.ProfileStatus = failure switch
        {
            "missing" => HttpStatusCode.NotFound,
            "unavailable" => HttpStatusCode.ServiceUnavailable,
            "forbidden" => HttpStatusCode.Forbidden,
            "redirect" => HttpStatusCode.Redirect,
            _ => HttpStatusCode.OK,
        };
        factory.ProfileReadGrant = failure != "missing-own-grant";
        factory.ProfileBody = failure switch
        {
            "malformed" => "{",
            "wrong-id" => "{\"Id\":73,\"Email\":\"persisted@profile.test\"}",
            "duplicate-id" => "{\"Id\":72,\"Id\":72,\"Email\":\"persisted@profile.test\"}",
            "wrong-case" => "{\"id\":72,\"email\":\"persisted@profile.test\"}",
            "invalid-email" => "{\"Id\":72,\"Email\":\"invalid\"}",
            "wrong-phone-type" => "{\"Id\":72,\"Email\":\"persisted@profile.test\",\"PhoneNumber\":42}",
            "beyond-email-schema" => JsonSerializer.Serialize(new { Id = 72, Email = new string('a', 250) + "@x.test" }),
            "beyond-phone-schema" => JsonSerializer.Serialize(new { Id = 72, Email = "persisted@profile.test", PhoneNumber = new string('1', 257) }),
            "oversized" => new string('x', 32769),
            _ => null,
        };
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, false);
        var before = await AdministrativeSnapshotAsync(stores);
        using var response = await client.PostAsJsonAsync("/auth/v1/employee-identities/72",
            new CreateEmployeeIdentityRequest("caller-name@profile.test", "untrusted@request.test", "abcdef", true, "+66999999999"));
        Assert.Equal(expected, (int)response.StatusCode);
        Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
        Assert.Equal(failure == "missing-own-grant" ? 0 : 1, factory.ProfileReads);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("persisted@profile.test", body, StringComparison.Ordinal);
        Assert.DoesNotContain("untrusted@request.test", body, StringComparison.Ordinal);
        Assert.Empty(await stores.Employees.RecoveryEffects.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
    }

    [Fact]
    public async Task NormalEmployeeProfileBinding_NullStoredPhoneClearsPostedPhoneAndStoredCollisionDeniesCreate()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        factory.Profiles[72] = new(72, "persisted@profile.test", null);
        factory.Profiles[73] = new(73, "PERSISTED@PROFILE.TEST", "+66812345678");
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, false);
        using var created = await client.PostAsJsonAsync("/auth/v1/employee-identities/72",
            new CreateEmployeeIdentityRequest("first@profile.test", "untrusted@request.test", "abcdef", true, "+66999999999"));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Null((await stores.Employees.Users.AsNoTracking().SingleAsync(value => value.DatabaseID == 72)).PhoneNumber);
        var before = await AdministrativeSnapshotAsync(stores);
        using var conflict = await client.PostAsJsonAsync("/auth/v1/employee-identities/73",
            new CreateEmployeeIdentityRequest("second@profile.test", "different@request.test", "abcdef", true, null));
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
        Assert.Equal(2, factory.ProfileReads);
    }

    [Theory]
    [InlineData(IdentityKind.Employee)]
    [InlineData(IdentityKind.Customer)]
    public async Task NormalLoginAccounting_FiveFailuresPersistLockoutAndExpiryAllowsRealPassword(IdentityKind kind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));
        await using var factory = new Factory(stores, clock: clock);
        using var client = factory.CreateClient();
        var before = await SnapshotIdentitiesAsync(stores);
        for (int attempt = 1; attempt <= 5; attempt++)
        {
            using var denied = await client.PostAsJsonAsync("/auth/v1/login", Login(kind) with { Password = "wrong-accounting-password" });
            Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
            Assert.DoesNotContain("wrong-accounting-password", await denied.Content.ReadAsStringAsync(), StringComparison.Ordinal);
            await AssertOnlyLoginAccountingChangedAsync(before, stores, kind, attempt == 5 ? 0 : attempt,
                attempt == 5 ? clock.GetUtcNow().AddMinutes(5) : null);
        }
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
        var locked = await SnapshotIdentitiesAsync(stores);
        using var refused = await client.PostAsJsonAsync("/auth/v1/login", Login(kind));
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        Assert.Equal(locked, await SnapshotIdentitiesAsync(stores));
        clock.Advance(TimeSpan.FromMinutes(5));
        using var equalDeadline = await client.PostAsJsonAsync("/auth/v1/login", Login(kind));
        Assert.Equal(HttpStatusCode.Unauthorized, equalDeadline.StatusCode);
        Assert.Equal(locked, await SnapshotIdentitiesAsync(stores));
        clock.Advance(TimeSpan.FromMilliseconds(1));
        var tokens = await LoginAsync(client, kind);
        Assert.Equal(locked, await SnapshotIdentitiesAsync(stores));
        var session = Assert.Single(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Equal(kind, session.IdentityKind);
        Assert.Equal(Hash(tokens.RefreshToken), session.TokenHash);
    }

    [Theory]
    [InlineData(IdentityKind.Employee)]
    [InlineData(IdentityKind.Customer)]
    public async Task NormalLoginAccounting_ConcurrentRequestsPersistFiveAttemptsWithoutLostUpdates(IdentityKind kind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));
        await using var factory = new Factory(stores, clock: clock);
        using var client = factory.CreateClient();
        var before = await SnapshotIdentitiesAsync(stores);
        var responses = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ =>
            client.PostAsJsonAsync("/auth/v1/login", Login(kind) with { Password = "concurrent-wrong-password" })));
        foreach (var response in responses)
        {
            using (response) Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
        await AssertOnlyLoginAccountingChangedAsync(before, stores, kind, 0, clock.GetUtcNow().AddMinutes(5));
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
    }

    [Fact]
    public async Task NormalLoginAccounting_DisabledLockoutStillRecordsSourceAttemptsAndSuccessfulPasswordResets()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var row = await stores.Customers.Users.SingleAsync();
        row.LockoutEnabled = false;
        row.AccessFailedCount = 4;
        await stores.Customers.SaveChangesAsync();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));
        await using var factory = new Factory(stores, clock: clock);
        using var client = factory.CreateClient();
        var before = await SnapshotIdentitiesAsync(stores);
        using var wrong = await client.PostAsJsonAsync("/auth/v1/login", Login(IdentityKind.Customer) with { Password = "disabled-wrong-password" });
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        await AssertOnlyLoginAccountingChangedAsync(before, stores, IdentityKind.Customer, 0, clock.GetUtcNow().AddMinutes(5));
        using var another = await client.PostAsJsonAsync("/auth/v1/login", Login(IdentityKind.Customer) with { Password = "disabled-wrong-password" });
        Assert.Equal(HttpStatusCode.Unauthorized, another.StatusCode);
        await AssertOnlyLoginAccountingChangedAsync(before, stores, IdentityKind.Customer, 1, clock.GetUtcNow().AddMinutes(5));
        _ = await LoginAsync(client, IdentityKind.Customer);
        await AssertOnlyLoginAccountingChangedAsync(before, stores, IdentityKind.Customer, 0, clock.GetUtcNow().AddMinutes(5));
    }

    [Fact]
    public async Task NormalLoginAccounting_UnconfirmedEmployeeAndUnknownAccountHaveNoIdentityOrSessionEffects()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var row = await stores.Employees.Users.SingleAsync();
        row.EmailConfirmed = false;
        row.AccessFailedCount = 2;
        await stores.Employees.SaveChangesAsync();
        var before = await SnapshotIdentitiesAsync(stores);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        foreach (var request in new[] { Login(IdentityKind.Employee), Login(IdentityKind.Employee) with { Password = "wrong-unconfirmed" },
                     new LoginRequest("missing-account@example.com", "wrong-unknown", IdentityKind.Customer) })
        {
            using var denied = await client.PostAsJsonAsync("/auth/v1/login", request);
            Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
            Assert.Equal(before, await SnapshotIdentitiesAsync(stores));
        }
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
    }

    [Fact]
    public async Task NormalLoginAccounting_UnconfirmedCustomerResetsVerifiedPasswordBeforeRecoveryWithoutSession()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var row = await stores.Customers.Users.SingleAsync();
        row.EmailConfirmed = false;
        row.TwoFactorEnabled = true;
        row.AccessFailedCount = 2;
        await stores.Customers.SaveChangesAsync();
        var before = await SnapshotIdentitiesAsync(stores);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        using var recovered = await client.PostAsJsonAsync("/auth/v1/login", Login(IdentityKind.Customer));
        Assert.Equal(HttpStatusCode.Conflict, recovered.StatusCode);
        var action = await recovered.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("confirm_email", action.GetProperty("action").GetString());
        await AssertOnlyLoginAccountingChangedAsync(before, stores, IdentityKind.Customer, 0);
        Assert.Single(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData(IdentityKind.Employee)]
    [InlineData(IdentityKind.Customer)]
    public async Task NormalLoginAccounting_FailedResetPersistenceCannotIssueSession(IdentityKind kind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var context = kind == IdentityKind.Employee ? (LegacyIdentityDbContext)stores.Employees : stores.Customers;
        var row = await context.Users.SingleAsync();
        row.AccessFailedCount = 2;
        await context.SaveChangesAsync();
        await context.Database.ExecuteSqlRawAsync("""
            CREATE FUNCTION reject_login_accounting() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'synthetic accounting persistence failure'; END; $$;
            CREATE TRIGGER reject_login_accounting BEFORE UPDATE OF "AccessFailedCount" ON "AspNetUsers"
            FOR EACH ROW EXECUTE FUNCTION reject_login_accounting();
            """);
        var before = await SnapshotIdentitiesAsync(stores);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        foreach (var request in new[] { Login(kind), Login(kind) with { Password = "failed-accounting-wrong" } })
        {
            using var failed = await client.PostAsJsonAsync("/auth/v1/login", request);
            Assert.Equal(HttpStatusCode.InternalServerError, failed.StatusCode);
            Assert.DoesNotContain("synthetic accounting persistence failure", await failed.Content.ReadAsStringAsync(), StringComparison.Ordinal);
            Assert.Equal(before, await SnapshotIdentitiesAsync(stores));
        }
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData(IdentityKind.Employee)]
    [InlineData(IdentityKind.Customer)]
    public async Task NormalLoginAccounting_ConcurrentFailureAndSuccessPreserveOneOrderedCounterOutcome(IdentityKind kind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        var before = await SnapshotIdentitiesAsync(stores);
        var deniedTask = client.PostAsJsonAsync("/auth/v1/login", Login(kind) with { Password = "concurrent-wrong" });
        var acceptedTask = client.PostAsJsonAsync("/auth/v1/login", Login(kind));
        using var denied = await deniedTask;
        using var accepted = await acceptedTask;
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        _ = await ReadTokensAsync(accepted);
        var context = kind == IdentityKind.Employee ? (LegacyIdentityDbContext)stores.Employees : stores.Customers;
        var count = (await context.Users.AsNoTracking().SingleAsync()).AccessFailedCount;
        Assert.Contains(count, new[] { 0, 1 });
        await AssertOnlyLoginAccountingChangedAsync(before, stores, kind, count);
        Assert.Single(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData(IdentityKind.Employee)]
    [InlineData(IdentityKind.Customer)]
    public async Task NormalLoginAccounting_ConcurrentPasswordReplacementIsReadAfterRowFence(IdentityKind kind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var context = kind == IdentityKind.Employee ? (LegacyIdentityDbContext)stores.Employees : stores.Customers;
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        await using var replacement = await context.Database.BeginTransactionAsync();
        var row = await context.Users.FromSqlRaw("SELECT * FROM \"AspNetUsers\" FOR UPDATE").SingleAsync();
        row.PasswordHash = new PasswordHasher<LegacyIdentityRow>().HashPassword(row, "replacement-accounting-password");
        row.SecurityStamp = "replacement-accounting-stamp";
        row.ConcurrencyStamp = "replacement-accounting-concurrency";
        await context.SaveChangesAsync();
        var before = await SnapshotIdentitiesAsync(stores);
        var attempted = client.PostAsJsonAsync("/auth/v1/login", Login(kind));
        var committed = false;
        try
        {
            var waiting = 0;
            for (int attempt = 0; attempt < 100 && waiting == 0; attempt++)
            {
                // The row-fence transaction otherwise retains its first activity snapshot.
                await context.Database.ExecuteSqlRawAsync("SELECT pg_stat_clear_snapshot()");
                waiting = await context.Database.SqlQueryRaw<int>("""
                    SELECT count(*)::integer AS "Value" FROM pg_stat_activity
                    WHERE datname = current_database() AND wait_event_type = 'Lock'
                    """).SingleAsync();
                if (waiting == 0) await Task.Delay(50);
            }
            Assert.True(waiting > 0, "The actual login query must wait for the competing identity row transaction.");
            Assert.False(attempted.IsCompleted);
            await replacement.CommitAsync();
            committed = true;
        }
        finally
        {
            if (!committed)
            {
                try { await replacement.DisposeAsync(); }
                catch (Exception) { /* Preserve the original fence failure; the context still owns final disposal. */ }
                await DrainFailedFenceRequestsAsync([attempted]);
            }
            else await replacement.DisposeAsync();
        }
        using var denied = await attempted;
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        await AssertOnlyLoginAccountingChangedAsync(before, stores, kind, 1);
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        using var accepted = await client.PostAsJsonAsync("/auth/v1/login", Login(kind) with { Password = "replacement-accounting-password" });
        var tokens = await ReadTokensAsync(accepted);
        _ = ReadJwt(tokens.AccessToken, factory);
        await AssertOnlyLoginAccountingChangedAsync(before, stores, kind, 0);
        Assert.Equal("replacement-accounting-stamp", (await stores.State.RefreshSessions.AsNoTracking().SingleAsync()).SecurityStamp);
    }

    [Fact]
    public async Task NormalLoginAccounting_ConfirmedTfaSuccessRetainsDeferredCounterContract()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var row = await stores.Employees.Users.SingleAsync();
        row.TwoFactorEnabled = true;
        row.AccessFailedCount = 2;
        await stores.Employees.SaveChangesAsync();
        var before = await SnapshotIdentitiesAsync(stores);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        _ = await LoginAsync(client, IdentityKind.Employee);
        Assert.Equal(before, await SnapshotIdentitiesAsync(stores));
        Assert.Single(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData(IdentityKind.Employee)]
    [InlineData(IdentityKind.Customer)]
    public async Task NormalLoginAccounting_TwoConnectionPoolMakesProgressWithoutSecondaryReaderAcquisition(IdentityKind kind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));
        await using var factory = new Factory(stores, clock: clock, tinyIdentityPool: true);
        using var client = factory.CreateClient();
        var context = kind == IdentityKind.Employee ? (LegacyIdentityDbContext)stores.Employees : stores.Customers;
        var before = await SnapshotIdentitiesAsync(stores);
        await using var fence = await context.Database.BeginTransactionAsync();
        _ = await context.Users.FromSqlRaw("SELECT * FROM \"AspNetUsers\" FOR UPDATE").SingleAsync();
        var requests = Enumerable.Range(0, 8).Select(_ => client.PostAsJsonAsync("/auth/v1/login",
            Login(kind) with { Password = "tiny-pool-wrong-password" })).ToArray();
        var committed = false;
        try
        {
            var waiting = 0;
            for (int attempt = 0; attempt < 100 && waiting < 2; attempt++)
            {
                // The row-fence transaction otherwise retains its first activity snapshot.
                await context.Database.ExecuteSqlRawAsync("SELECT pg_stat_clear_snapshot()");
                waiting = await context.Database.SqlQueryRaw<int>("""
                    SELECT count(*)::integer AS "Value" FROM pg_stat_activity WHERE datname = current_database()
                    AND application_name = 'login-accounting-tiny-pool' AND wait_event_type = 'Lock'
                    """).SingleAsync();
                if (waiting < 2) await Task.Delay(50);
            }
            Assert.True(waiting >= 2, "Both configured pool connections must be occupied by actual waiting login queries.");
            await fence.CommitAsync();
            committed = true;
        }
        finally
        {
            if (!committed)
            {
                try { await fence.DisposeAsync(); }
                catch (Exception) { /* Preserve the original fence failure; the context still owns final disposal. */ }
                await DrainFailedFenceRequestsAsync(requests);
            }
            else await fence.DisposeAsync();
        }
        foreach (var response in await Task.WhenAll(requests).WaitAsync(TimeSpan.FromSeconds(15)))
        {
            using (response) Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
        await AssertOnlyLoginAccountingChangedAsync(before, stores, kind, 0, clock.GetUtcNow().AddMinutes(5));
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
    }

    private static async Task DrainFailedFenceRequestsAsync(IEnumerable<Task<HttpResponseMessage>> requests)
    {
        foreach (var request in requests)
        {
            try
            {
                using var response = await request.WaitAsync(TimeSpan.FromSeconds(15));
            }
            catch (Exception)
            {
                // Cleanup must observe every sibling without replacing the primary test assertion.
                _ = request.ContinueWith(completed =>
                {
                    if (completed.Status == TaskStatus.RanToCompletion) completed.Result.Dispose();
                    else _ = completed.Exception;
                }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }
    }

    [Theory]
    [InlineData(IdentityKind.Employee, false)]
    [InlineData(IdentityKind.Customer, false)]
    [InlineData(IdentityKind.Customer, true)]
    public async Task NormalAdministrativePasswordPolicy_NewCreationRejectsLowDistinctAndAcceptsSixCharacterBoundary(
        IdentityKind kind, bool reconcile)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores, identityAdministration: true);
        factory.Profiles[71] = new(71, "new-admin@example.com", null);
        factory.CustomerProfiles[71] = new(71, "new-admin@example.com", null, null, null);
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, reconcile);
        var identities = await SnapshotIdentitiesAsync(stores);
        var sessionCount = await stores.State.RefreshSessions.CountAsync();
        var key = Guid.NewGuid();
        var route = $"/auth/v1/{kind.ToString().ToLowerInvariant()}-identities/71" + (reconcile ? "/reconcile-create" : "");
        if (reconcile) client.DefaultRequestHeaders.Add("Idempotency-Key", key.ToString());
        const string email = "new-admin@example.com";
        foreach (var invalid in new string?[] { "aaabbbccc", "abcde", string.Empty, null, "abcdef" + new string('a', 1019) })
        {
            await using var scope = factory.Services.CreateAsyncScope();
            if (kind == IdentityKind.Employee)
                Assert.Null(await scope.ServiceProvider.GetRequiredService<IEmployeeIdentityAdminService>()
                    .CreateAsync(71, (CreateEmployeeIdentityRequest)AdministrativeRequest(kind, email, invalid), default));
            else if (reconcile)
                Assert.Equal(CustomerIdentityCreateOutcome.InvalidPassword,
                    (await scope.ServiceProvider.GetRequiredService<ICustomerIdentityAdminService>().CreateOrReconcileAsync(
                        71, "service:issuance-test", key, (CreateCustomerIdentityRequest)AdministrativeRequest(kind, email, invalid), default)).Outcome);
            else
                Assert.Null(await scope.ServiceProvider.GetRequiredService<ICustomerIdentityAdminService>()
                    .CreateAsync(71, (CreateCustomerIdentityRequest)AdministrativeRequest(kind, email, invalid), default));
            using var rejected = await client.PostAsJsonAsync(route, AdministrativeRequest(kind, email, invalid));
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
            var body = await rejected.Content.ReadAsStringAsync();
            Assert.DoesNotContain(email, body, StringComparison.Ordinal);
            if (!string.IsNullOrEmpty(invalid)) Assert.DoesNotContain(invalid, body, StringComparison.Ordinal);
            Assert.Equal(identities, await SnapshotIdentitiesAsync(stores));
            Assert.Empty(await stores.Customers.CreateOperations.AsNoTracking().ToListAsync());
            Assert.Equal(sessionCount, await stores.State.RefreshSessions.CountAsync());
        }
        using var created = await client.PostAsJsonAsync(route, AdministrativeRequest(kind, email, "abcdef"));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        if (reconcile)
        {
            using var replay = await client.PostAsJsonAsync(route, AdministrativeRequest(kind, email, "abcdef"));
            Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
            var receipt = await replay.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal(["databaseId", "status"], receipt.EnumerateObject().Select(value => value.Name).Order().ToArray());
            Assert.Equal(71, receipt.GetProperty("databaseId").GetInt32());
            Assert.Equal("replayed", receipt.GetProperty("status").GetString());
        }
        var users = kind == IdentityKind.Employee ? stores.Employees.Users : stores.Customers.Users;
        var identity = await users.AsNoTracking().SingleAsync(value => value.DatabaseID == 71);
        Assert.Equal(PasswordVerificationResult.Success,
            new PasswordHasher<LegacyIdentityRow>().VerifyHashedPassword(identity, identity.PasswordHash!, "abcdef"));
        client.DefaultRequestHeaders.Authorization = null;
        using var login = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest(email, "abcdef", kind));
        var tokens = await ReadTokensAsync(login);
        var jwt = ReadJwt(tokens.AccessToken, factory);
        Assert.Equal(identity.Id, Assert.Single(jwt.Claims, value => value.Type == "sub").Value);
        Assert.Equal(kind.ToString().ToLowerInvariant(), Assert.Single(jwt.Claims, value => value.Type == "identity_kind").Value);
        Assert.Equal(kind == IdentityKind.Employee ? "Employee" : "Customer", Assert.Single(jwt.Claims, value => value.Type == ClaimTypes.Role).Value);
        var session = await stores.State.RefreshSessions.AsNoTracking().SingleAsync(value => value.IdentityId == identity.Id);
        Assert.Equal(kind, session.IdentityKind);
        Assert.Equal(identity.SecurityStamp, session.SecurityStamp);
        Assert.Equal(Hash(tokens.RefreshToken), session.TokenHash);
    }

    [Fact]
    public async Task NormalAdministrativePasswordPolicy_WebRegistrationKeepsEightCharacterLowDistinctPolicy()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores, identityAdministration: true);
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, service: true);
        await using (var scope = factory.Services.CreateAsyncScope())
            Assert.True(scope.ServiceProvider.GetRequiredService<CustomerIdentityDbContext>().Database.CreateExecutionStrategy().RetriesOnFailure);
        using var registered = await client.PostAsJsonAsync("/auth/v1/customer-self-service/register",
            new RegisterCustomerIdentityRequest(72, "web-policy@example.com", "aabbccdd"));
        if (registered.StatusCode != HttpStatusCode.Created)
        {
            var classification = "non-validation-response";
            try
            {
                var problem = await registered.Content.ReadFromJsonAsync<JsonElement>();
                if (problem.TryGetProperty("errors", out var errors) && errors.ValueKind == JsonValueKind.Object)
                {
                    var fields = errors.EnumerateObject().Take(8).Select(error => error.Name switch
                    {
                        "DatabaseId" or "databaseId" => "DatabaseId",
                        "Email" or "email" => "Email",
                        "Password" or "password" => "Password",
                        _ => "other-field",
                    }).ToArray();
                    classification = "validation-fields:" + string.Join(",", fields);
                }
            }
            catch (JsonException) { classification = "non-json-response"; }
            Assert.Fail($"Registration did not return Created: HTTP {(int)registered.StatusCode}; {classification}.");
        }
        var identity = await stores.Customers.Users.AsNoTracking().SingleAsync(value => value.DatabaseID == 72);
        Assert.Equal(PasswordVerificationResult.Success,
            new PasswordHasher<LegacyIdentityRow>().VerifyHashedPassword(identity, identity.PasswordHash!, "aabbccdd"));
        Assert.False(identity.EmailConfirmed);
        Assert.Empty(await stores.Customers.CreateOperations.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        var committed = await SnapshotIdentitiesAsync(stores);
        using var wrongLink = await client.PostAsJsonAsync("/auth/v1/customer-self-service/register/resolve",
            new ResolveCustomerIdentityRequest(73, "web-policy@example.com", "aabbccdd"));
        Assert.Equal(HttpStatusCode.NotFound, wrongLink.StatusCode);
        using var wrongPassword = await client.PostAsJsonAsync("/auth/v1/customer-self-service/register/resolve",
            new ResolveCustomerIdentityRequest(72, "web-policy@example.com", "wrong-password"));
        Assert.Equal(HttpStatusCode.NotFound, wrongPassword.StatusCode);
        using var resolved = await client.PostAsJsonAsync("/auth/v1/customer-self-service/register/resolve",
            new ResolveCustomerIdentityRequest(72, "web-policy@example.com", "aabbccdd"));
        Assert.Equal(HttpStatusCode.OK, resolved.StatusCode);
        var result = (await resolved.Content.ReadFromJsonAsync<CustomerSelfServiceResult>())!;
        Assert.True(result.Succeeded);
        Assert.True(result.Created);
        Assert.Equal(identity.Id, result.IdentityId);
        Assert.Equal(72, result.DatabaseId);
        Assert.Equal(committed, await SnapshotIdentitiesAsync(stores));
        Assert.Empty(await stores.Customers.CreateOperations.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    [Fact]
    public async Task NormalAdministrativePasswordPolicy_PreviouslyCommittedWeakPasswordReceiptRemainsReplayable()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        const string email = "legacy-admin@example.com";
        var identity = new LegacyIdentityRow
        {
            Id = "legacy-admin-policy",
            DatabaseID = 73,
            UserName = email,
            NormalizedUserName = email.ToUpperInvariant(),
            Email = email,
            NormalizedEmail = email.ToUpperInvariant(),
            EmailConfirmed = true,
            SecurityStamp = "legacy-admin-stamp",
            ConcurrencyStamp = "legacy-admin-concurrency",
            LockoutEnabled = true,
        };
        identity.PasswordHash = new PasswordHasher<LegacyIdentityRow>().HashPassword(identity, "aaaaaaaa");
        var key = Guid.NewGuid();
        stores.Customers.Users.Add(identity);
        stores.Customers.CreateOperations.Add(new CustomerIdentityCreateOperation
        {
            ServiceSubject = "service:issuance-test",
            OperationKey = key,
            DatabaseId = 73,
            IdentityId = identity.Id,
            PayloadSalt = Enumerable.Range(0, 16).Select(value => (byte)value).ToArray(),
            // Independent Python PBKDF2-SHA256/210000/32 fixture over the original Pascal-case request JSON.
            PayloadHash = Convert.FromHexString("10971819444ebc3d554c2229c8840bb783dab70386418b83b39d5d6c03a755bb"),
        });
        await stores.Customers.SaveChangesAsync();
        var before = await SnapshotIdentitiesAsync(stores);
        var operationBefore = JsonSerializer.Serialize(await stores.Customers.CreateOperations.AsNoTracking().SingleAsync());
        await using var factory = new Factory(stores, identityAdministration: true);
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, service: true);
        client.DefaultRequestHeaders.Add("Idempotency-Key", key.ToString());
        const string route = "/auth/v1/customer-identities/73/reconcile-create";
        using var replay = await client.PostAsJsonAsync(route, AdministrativeRequest(IdentityKind.Customer, email, "aaaaaaaa"));
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        var receipt = await replay.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(["databaseId", "status"], receipt.EnumerateObject().Select(value => value.Name).Order().ToArray());
        Assert.Equal("replayed", receipt.GetProperty("status").GetString());
        using var conflict = await client.PostAsJsonAsync(route, AdministrativeRequest(IdentityKind.Customer, email, "abcdef"));
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        Assert.Equal(before, await SnapshotIdentitiesAsync(stores));
        Assert.Equal(operationBefore, JsonSerializer.Serialize(await stores.Customers.CreateOperations.AsNoTracking().SingleAsync()));
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NormalAdministrativePasswordPolicy_LengthMaximumAndUtf16DistinctBoundaryUseActualWrite(bool unicode)
    {
        var password = unicode ? "abc\uD83D\uDE00d" : "abcdef" + new string('a', 1018);
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        factory.Profiles[74] = new(74, "boundary-admin@example.com", null);
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, service: false);
        using var created = await client.PostAsJsonAsync("/auth/v1/employee-identities/74",
            AdministrativeRequest(IdentityKind.Employee, "boundary-admin@example.com", password));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var identity = await stores.Employees.Users.AsNoTracking().SingleAsync(value => value.DatabaseID == 74);
        Assert.Equal(PasswordVerificationResult.Success,
            new PasswordHasher<LegacyIdentityRow>().VerifyHashedPassword(identity, identity.PasswordHash!, password));
        Assert.Equal(unicode ? 6 : 1024, password.Length);
    }

    private static object AdministrativeRequest(IdentityKind kind, string email, string? password) => kind == IdentityKind.Employee
        ? new CreateEmployeeIdentityRequest(email, email, password!, true, null)
        : new CreateCustomerIdentityRequest(email, email, password!, true, null, null, null);

    [Theory]
    [InlineData(IdentityKind.Employee, false)]
    [InlineData(IdentityKind.Customer, false)]
    [InlineData(IdentityKind.Customer, true)]
    public async Task NormalAdministrativeIdentityPolicy_NewCreationUsesDefaultAlphabetWithoutEffects(IdentityKind kind, bool reconcile)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores, identityAdministration: true);
        factory.Profiles[72] = new(72, "new@example.com", null);
        factory.CustomerProfiles[72] = new(72, "new@example.com", null, null, null);
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, reconcile);
        var before = await AdministrativeSnapshotAsync(stores);
        var route = $"/auth/v1/{kind.ToString().ToLowerInvariant()}-identities/72" + (reconcile ? "/reconcile-create" : "");
        if (reconcile) client.DefaultRequestHeaders.Add("Idempotency-Key", Guid.NewGuid().ToString());
        foreach (var fields in new[] { ("\u0e01@example.com", "new@example.com"), ("a!b@example.com", "new@example.com"), ("valid@example.com", "not-an-email") })
        {
            var userName = fields.Item1;
            var request = AdministrativeIdentityRequest(kind, userName, fields.Item2);
            using var rejected = await client.PostAsJsonAsync(route, request);
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
            Assert.DoesNotContain(userName, await rejected.Content.ReadAsStringAsync(), StringComparison.Ordinal);
            Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
            await using var scope = factory.Services.CreateAsyncScope();
            if (kind == IdentityKind.Employee)
                await Assert.ThrowsAsync<AdministrativeIdentityValidationException>(() => scope.ServiceProvider.GetRequiredService<IEmployeeIdentityAdminService>().CreateAsync(72, (CreateEmployeeIdentityRequest)request, default));
            else if (reconcile)
                Assert.Equal(CustomerIdentityCreateOutcome.InvalidIdentity, (await scope.ServiceProvider.GetRequiredService<ICustomerIdentityAdminService>().CreateOrReconcileAsync(72, "service:issuance-test", Guid.NewGuid(), (CreateCustomerIdentityRequest)request, default)).Outcome);
            else
                await Assert.ThrowsAsync<AdministrativeIdentityValidationException>(() => scope.ServiceProvider.GetRequiredService<ICustomerIdentityAdminService>().CreateAsync(72, (CreateCustomerIdentityRequest)request, default));
            Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
        }
        using var created = await client.PostAsJsonAsync(route, AdministrativeIdentityRequest(kind, "a+._-b@example.com", "new@example.com"));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var users = kind == IdentityKind.Employee ? stores.Employees.Users : stores.Customers.Users;
        var row = await users.AsNoTracking().SingleAsync(value => value.DatabaseID == 72);
        Assert.Equal("A+._-B@EXAMPLE.COM", row.NormalizedUserName);
        Assert.Equal(PasswordVerificationResult.Success, new PasswordHasher<LegacyIdentityRow>().VerifyHashedPassword(row, row.PasswordHash!, "abcdef"));
        var committed = await AdministrativeSnapshotAsync(stores);
        if (reconcile)
        {
            client.DefaultRequestHeaders.Remove("Idempotency-Key");
            client.DefaultRequestHeaders.Add("Idempotency-Key", Guid.NewGuid().ToString());
        }
        using var duplicate = await client.PostAsJsonAsync(route, AdministrativeIdentityRequest(kind, "a+._-b@example.com", "new@example.com"));
        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
        Assert.Equal(committed, await AdministrativeSnapshotAsync(stores));
        if (reconcile)
        {
            var legacy = new LegacyIdentityRow
            {
                Id = "legacy-invalid-user-name",
                DatabaseID = 74,
                UserName = "a!b@example.com",
                NormalizedUserName = "A!B@EXAMPLE.COM",
                Email = "legacy-invalid@example.com",
                NormalizedEmail = "LEGACY-INVALID@EXAMPLE.COM",
                EmailConfirmed = true,
                SecurityStamp = "legacy-name-stamp",
                ConcurrencyStamp = "legacy-name-concurrency",
                LockoutEnabled = true,
            };
            legacy.PasswordHash = new PasswordHasher<LegacyIdentityRow>().HashPassword(legacy, "abcdef");
            var key = Guid.NewGuid();
            stores.Customers.Users.Add(legacy);
            stores.Customers.CreateOperations.Add(new CustomerIdentityCreateOperation
            {
                ServiceSubject = "service:issuance-test",
                OperationKey = key,
                DatabaseId = 74,
                IdentityId = legacy.Id,
                PayloadSalt = Enumerable.Range(0, 16).Select(value => (byte)value).ToArray(),
                // Independent Python PBKDF2-SHA256/210000/32 over the fixed Pascal-case request JSON.
                PayloadHash = Convert.FromHexString("fffbc2b5e4a580c6561adf8cf52c3a7c066e4ced75396faca14217218adf531c"),
            });
            await stores.Customers.SaveChangesAsync();
            var grandfathered = await AdministrativeSnapshotAsync(stores);
            client.DefaultRequestHeaders.Remove("Idempotency-Key");
            client.DefaultRequestHeaders.Add("Idempotency-Key", key.ToString());
            using var replay = await client.PostAsJsonAsync("/auth/v1/customer-identities/74/reconcile-create", AdministrativeIdentityRequest(kind, legacy.UserName!, legacy.Email!));
            Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
            using var changed = await client.PostAsJsonAsync("/auth/v1/customer-identities/74/reconcile-create", AdministrativeIdentityRequest(kind, "other@example.com", legacy.Email!));
            Assert.Equal(HttpStatusCode.Conflict, changed.StatusCode);
            Assert.Equal(grandfathered, await AdministrativeSnapshotAsync(stores));
        }
    }

    [Theory]
    [InlineData(IdentityKind.Employee)]
    [InlineData(IdentityKind.Customer)]
    public async Task NormalAdministrativeIdentityPolicy_UpdatePreservesRejectionsAndAcceptsSameOwner(IdentityKind kind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores, identityAdministration: true, identityValidation: true);
        factory.Profiles[72] = new(72, "target72@example.com", null);
        factory.CustomerProfiles[72] = new(72, "target72@example.com", null, null, null);
        factory.Profiles[73] = new(73, "target73@example.com", null);
        factory.CustomerProfiles[73] = new(73, "target73@example.com", null, null, null);
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, false);
        var route = $"/auth/v1/{kind.ToString().ToLowerInvariant()}-identities/";
        foreach (var id in new[] { 72, 73 })
        {
            using var created = await client.PostAsJsonAsync(route + id, AdministrativeIdentityRequest(kind, $"target{id}@example.com", $"target{id}@example.com"));
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        }
        var users = kind == IdentityKind.Employee ? stores.Employees.Users : stores.Customers.Users;
        var old = await users.AsNoTracking().SingleAsync(value => value.DatabaseID == 72);
        var before = await AdministrativeSnapshotAsync(stores);
        foreach (var fields in new[] { ("\u0e01@example.com", "next@example.com"), ("target73@example.com", "next@example.com"), ("next@example.com", "TARGET73@EXAMPLE.COM") })
        {
            using var rejected = await client.PutAsJsonAsync(route + "72", AdministrativeUpdateRequest(kind, fields.Item1, fields.Item2));
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
            var body = await rejected.Content.ReadAsStringAsync();
            Assert.DoesNotContain(fields.Item1, body, StringComparison.Ordinal);
            Assert.DoesNotContain(fields.Item2, body, StringComparison.Ordinal);
            Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
        }
        using var missing = await client.PutAsJsonAsync(route + "999", AdministrativeUpdateRequest(kind, "valid@example.com", "valid@example.com"));
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
        using var same = await client.PutAsJsonAsync(route + "72", AdministrativeUpdateRequest(kind, "TARGET72@example.com", "TARGET72@example.com"));
        Assert.Equal(HttpStatusCode.NoContent, same.StatusCode);
        var changed = await users.AsNoTracking().SingleAsync(value => value.DatabaseID == 72);
        Assert.Equal(old.Id, changed.Id);
        Assert.Equal(old.DatabaseID, changed.DatabaseID);
        Assert.Equal(old.PasswordHash, changed.PasswordHash);
        Assert.Equal(old.AccessFailedCount, changed.AccessFailedCount);
        Assert.NotEqual(old.SecurityStamp, changed.SecurityStamp);
        Assert.NotEqual(old.ConcurrencyStamp, changed.ConcurrencyStamp);
        using var renamed = await client.PutAsJsonAsync(route + "72", AdministrativeUpdateRequest(kind, "a+._-b@example.com", "renamed@example.com"));
        Assert.Equal(HttpStatusCode.NoContent, renamed.StatusCode);
        Assert.Empty(await stores.Employees.RecoveryEffects.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData(IdentityKind.Employee)]
    [InlineData(IdentityKind.Customer)]
    public async Task NormalAdministrativeIdentityPolicy_VersionedConcurrentWritesAcceptOneAndNeverOverwriteStaleEdit(IdentityKind kind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores, identityAdministration: true, identityValidation: true);
        factory.Profiles[72] = new(72, "versioned@example.com", null);
        factory.CustomerProfiles[72] = new(72, "versioned@example.com", null, null, null);
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, false);
        var route = $"/auth/v1/{kind.ToString().ToLowerInvariant()}-identities/72";
        using var created = await client.PostAsJsonAsync(route, AdministrativeIdentityRequest(kind, "versioned@example.com", "versioned@example.com"));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        using var projected = await client.GetAsync(route);
        Assert.Equal(HttpStatusCode.OK, projected.StatusCode);
        var wire = await projected.Content.ReadFromJsonAsync<JsonElement>();
        var version = wire.GetProperty("version").GetString()!;
        Assert.Equal(64, version.Length);
        Assert.All(version, value => Assert.True(char.IsAsciiHexDigit(value)));
        var etag = projected.Headers.ETag!.ToString();
        Assert.Equal("\"" + version + "\"", etag);
        Assert.False(projected.Headers.ETag.IsWeak);
        foreach (var field in new[] { "passwordHash", "securityStamp", "concurrencyStamp", "normalizedUserName", "normalizedEmail" })
            Assert.False(wire.TryGetProperty(field, out _));
        var before = await AdministrativeSnapshotAsync(stores);
        using var anonymous = factory.CreateClient();
        using var unauthorized = await anonymous.PutAsJsonAsync(route + "/versioned", AdministrativeUpdateRequest(kind, "valid@example.com", "valid@example.com"));
        Assert.Equal(HttpStatusCode.Unauthorized, unauthorized.StatusCode);
        using var missingVersion = await client.PutAsJsonAsync(route + "/versioned", AdministrativeUpdateRequest(kind, "valid@example.com", "valid@example.com"));
        Assert.Equal((HttpStatusCode)428, missingVersion.StatusCode);
        Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
        using var serviceOnly = factory.CreateClient();
        await AuthorizeAdministrationAsync(serviceOnly, true);
        using var forbidden = await serviceOnly.PutAsJsonAsync(route + "/versioned", AdministrativeUpdateRequest(kind, "valid@example.com", "valid@example.com"));
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        using var absent = new HttpRequestMessage(HttpMethod.Put, route.Replace("72", "999", StringComparison.Ordinal) + "/versioned")
        {
            Content = JsonContent.Create(AdministrativeUpdateRequest(kind, "valid@example.com", "valid@example.com")),
        };
        absent.Headers.TryAddWithoutValidation("If-Match", etag);
        using var missing = await client.SendAsync(absent);
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        using var wildcard = new HttpRequestMessage(HttpMethod.Put, route + "/versioned")
        {
            Content = JsonContent.Create(AdministrativeUpdateRequest(kind, "valid@example.com", "valid@example.com")),
        };
        wildcard.Headers.TryAddWithoutValidation("If-Match", "*");
        using var malformed = await client.SendAsync(wildcard);
        Assert.Equal(HttpStatusCode.PreconditionFailed, malformed.StatusCode);
        Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
        using var invalid = new HttpRequestMessage(HttpMethod.Put, route + "/versioned")
        {
            Content = JsonContent.Create(AdministrativeUpdateRequest(kind, "a!b@example.com", "valid@example.com")),
        };
        invalid.Headers.TryAddWithoutValidation("If-Match", etag);
        using var invalidResponse = await client.SendAsync(invalid);
        Assert.Equal(HttpStatusCode.BadRequest, invalidResponse.StatusCode);
        Assert.DoesNotContain("a!b@example.com", await invalidResponse.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
        if (kind == IdentityKind.Employee)
        {
            var recovery = factory.Services.GetRequiredService<EmployeeRecoveryOptions>();
            recovery.Enabled = false;
            try
            {
                using var gated = new HttpRequestMessage(HttpMethod.Put, route + "/versioned")
                {
                    Content = JsonContent.Create(AdministrativeUpdateRequest(kind, "valid@example.com", "valid@example.com")),
                };
                gated.Headers.TryAddWithoutValidation("If-Match", etag);
                using var unavailable = await client.SendAsync(gated);
                Assert.Equal(HttpStatusCode.ServiceUnavailable, unavailable.StatusCode);
                Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
            }
            finally { recovery.Enabled = true; }
        }
        using var first = new HttpRequestMessage(HttpMethod.Put, route + "/versioned")
        {
            Content = JsonContent.Create(AdministrativeUpdateRequest(kind, "first@example.com", "first@example.com")),
        };
        using var second = new HttpRequestMessage(HttpMethod.Put, route + "/versioned")
        {
            Content = JsonContent.Create(AdministrativeUpdateRequest(kind, "second@example.com", "second@example.com")),
        };
        first.Headers.TryAddWithoutValidation("If-Match", etag);
        second.Headers.TryAddWithoutValidation("If-Match", etag);
        var context = kind == IdentityKind.Employee ? (LegacyIdentityDbContext)stores.Employees : stores.Customers;
        await using var fence = await context.Database.BeginTransactionAsync();
        _ = await context.Users.FromSqlInterpolated($"SELECT * FROM \"AspNetUsers\" WHERE \"DatabaseID\" = {72} FOR UPDATE").SingleAsync();
        var pending = new[] { client.SendAsync(first), client.SendAsync(second) };
        var released = false;
        try
        {
            var waiting = 0;
            for (int attempt = 0; attempt < 200 && waiting < 2; attempt++)
            {
                await context.Database.ExecuteSqlRawAsync("SELECT pg_stat_clear_snapshot()");
                waiting = await context.Database.SqlQueryRaw<int>("""
                    SELECT count(*)::integer AS "Value" FROM pg_stat_activity
                    WHERE datname = current_database() AND wait_event_type = 'Lock'
                    """).SingleAsync();
                if (waiting < 2) await Task.Delay(50);
            }
            Assert.True(waiting >= 2, "Both actual administrative writes must reach the identity row fence before release.");
            Assert.All(pending, value => Assert.False(value.IsCompleted));
            await fence.CommitAsync();
            released = true;
        }
        finally
        {
            if (!released)
            {
                try { await fence.DisposeAsync(); }
                catch (Exception) { /* Preserve the primary fence assertion; the context retains disposal ownership. */ }
                await DrainFailedFenceRequestsAsync(pending);
            }
            else await fence.DisposeAsync();
        }
        var outcomes = await Task.WhenAll(pending).WaitAsync(TimeSpan.FromSeconds(15));
        try
        {
            Assert.Single(outcomes, value => value.StatusCode == HttpStatusCode.NoContent);
            Assert.Single(outcomes, value => value.StatusCode == HttpStatusCode.PreconditionFailed);
        }
        finally { foreach (var outcome in outcomes) outcome.Dispose(); }
        var committed = await AdministrativeSnapshotAsync(stores);
        using var stale = new HttpRequestMessage(HttpMethod.Put, route + "/versioned")
        {
            Content = JsonContent.Create(AdministrativeUpdateRequest(kind, "stale@example.com", "stale@example.com")),
        };
        stale.Headers.TryAddWithoutValidation("If-Match", etag);
        using var rejected = await client.SendAsync(stale);
        Assert.Equal(HttpStatusCode.PreconditionFailed, rejected.StatusCode);
        Assert.Equal(committed, await AdministrativeSnapshotAsync(stores));
        using var current = await client.GetAsync(route);
        Assert.NotEqual(etag, current.Headers.ETag!.ToString());
        var users = kind == IdentityKind.Employee ? stores.Employees.Users : stores.Customers.Users;
        var row = await users.AsNoTracking().SingleAsync(value => value.DatabaseID == 72);
        Assert.Contains(row.UserName, new[] { "first@example.com", "second@example.com" });
        Assert.Equal(PasswordVerificationResult.Success, new PasswordHasher<LegacyIdentityRow>().VerifyHashedPassword(row, row.PasswordHash!, "abcdef"));
    }

    [Theory]
    [InlineData(IdentityKind.Employee)]
    [InlineData(IdentityKind.Customer)]
    public async Task NormalAdministrativeIdentityPolicy_CommittedAcknowledgmentLossReturnsUnavailableWithoutRetryingAsStale(IdentityKind kind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var control = new ConditionalAckState(kind);
        await using var factory = new Factory(stores, identityAdministration: true, identityValidation: true,
            conditionalFaults: [new ConditionalCommandAckLoss(control), new ConditionalCommitAckLoss(control)]);
        factory.Profiles[72] = new(72, "before-ack@example.com", null);
        factory.CustomerProfiles[72] = new(72, "before-ack@example.com", null, null, null);
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, false);
        var route = $"/auth/v1/{kind.ToString().ToLowerInvariant()}-identities/72";
        using var created = await client.PostAsJsonAsync(route, AdministrativeIdentityRequest(kind, "before-ack@example.com", "before-ack@example.com"));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        using var projected = await client.GetAsync(route);
        var version = projected.Headers.ETag!.ToString();
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var normal = kind == IdentityKind.Employee
                ? (LegacyIdentityDbContext)scope.ServiceProvider.GetRequiredService<EmployeeIdentityDbContext>()
                : scope.ServiceProvider.GetRequiredService<CustomerIdentityDbContext>();
            Assert.True(normal.Database.CreateExecutionStrategy().RetriesOnFailure);
        }
        var users = kind == IdentityKind.Employee ? stores.Employees.Users : stores.Customers.Users;
        var original = await users.AsNoTracking().SingleAsync(value => value.DatabaseID == 72);
        control.Enabled = true;
        using var request = new HttpRequestMessage(HttpMethod.Put, route + "/versioned")
        {
            Content = JsonContent.Create(AdministrativeUpdateRequest(kind, "after-ack@example.com", "after-ack@example.com")),
        };
        request.Headers.TryAddWithoutValidation("If-Match", version);
        using var uncertain = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, uncertain.StatusCode);
        Assert.True(control.Injected);
        Assert.False(control.ObservedRetries ?? true);
        Assert.Equal(1, control.Attempts);
        Assert.Equal(1, control.CompletedWrites);
        var body = await uncertain.Content.ReadAsStringAsync();
        Assert.DoesNotContain("after-ack@example.com", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Synthetic", body, StringComparison.Ordinal);
        var actual = await users.AsNoTracking().SingleAsync(value => value.DatabaseID == 72);
        Assert.Equal("after-ack@example.com", actual.UserName);
        Assert.Equal(original.PasswordHash, actual.PasswordHash);
        Assert.Equal(original.Id, actual.Id);
        Assert.Equal(original.DatabaseID, actual.DatabaseID);
        Assert.Equal(original.AccessFailedCount, actual.AccessFailedCount);
        Assert.NotEqual(original.SecurityStamp, actual.SecurityStamp);
        Assert.NotEqual(original.ConcurrencyStamp, actual.ConcurrencyStamp);
        var committed = await AdministrativeSnapshotAsync(stores);
        control.Enabled = false;
        using var retry = new HttpRequestMessage(HttpMethod.Put, route + "/versioned")
        {
            Content = JsonContent.Create(AdministrativeUpdateRequest(kind, "replayed@example.com", "replayed@example.com")),
        };
        retry.Headers.TryAddWithoutValidation("If-Match", version);
        using var stale = await client.SendAsync(retry);
        Assert.Equal(HttpStatusCode.PreconditionFailed, stale.StatusCode);
        Assert.Equal(committed, await AdministrativeSnapshotAsync(stores));
        Assert.Equal(1, control.Attempts);
    }

    [Theory]
    [InlineData(IdentityKind.Employee)]
    [InlineData(IdentityKind.Customer)]
    public async Task NormalCanonicalIdentityWriter_HistoricalCollisionDeniesEffectsAndSameOwnerUsesCanonicalKey(IdentityKind kind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores, identityAdministration: true, identityValidation: true);
        factory.Profiles[72] = new(72, "cafe\u0301@identity.test", null);
        factory.CustomerProfiles[72] = new(72, "cafe\u0301@identity.test", null, null, null);
        factory.Profiles[73] = new(73, "\u01fa@identity.test", null);
        factory.CustomerProfiles[73] = new(73, "\u01fa@identity.test", null, null, null);
        factory.Profiles[74] = new(74, "otherwise-unique@identity.test", null);
        factory.CustomerProfiles[74] = new(74, "otherwise-unique@identity.test", null, null, null);
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, false);
        LegacyIdentityDbContext identity = kind == IdentityKind.Employee ? stores.Employees : stores.Customers;
        const string historicalEmail = "A\u030a\u0301@identity.test";
        identity.Users.Add(new()
        {
            Id = "historical-canonical-collision",
            DatabaseID = 17,
            UserName = "\u212a-user@identity.test",
            NormalizedUserName = "\u212a-USER@IDENTITY.TEST",
            Email = historicalEmail,
            NormalizedEmail = historicalEmail.ToUpperInvariant(),
            SecurityStamp = "retained-security",
            ConcurrencyStamp = "retained-concurrency",
        });
        await identity.SaveChangesAsync();
        identity.ChangeTracker.Clear();
        var route = $"/auth/v1/{kind.ToString().ToLowerInvariant()}-identities";
        const string rawEmail = "cafe\u0301@identity.test";
        using var created = await client.PostAsJsonAsync(route + "/72",
            AdministrativeIdentityRequest(kind, "new-user@identity.test", rawEmail));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var newRow = await identity.Users.AsNoTracking().SingleAsync(value => value.DatabaseID == 72);
        Assert.Equal(rawEmail, newRow.Email);
        Assert.Equal("CAF\u00c9@IDENTITY.TEST", newRow.NormalizedEmail);
        using var projected = await client.GetAsync(route + "/72");
        var version = projected.Headers.ETag!.ToString();
        var before = await AdministrativeSnapshotAsync(stores);
        using var conflictingCreate = await client.PostAsJsonAsync(route + "/73",
            AdministrativeIdentityRequest(kind, "another-user@identity.test", "\u01fa@identity.test"));
        Assert.Equal(HttpStatusCode.Conflict, conflictingCreate.StatusCode);
        Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
        using var conflictingUserName = await client.PostAsJsonAsync(route + "/74",
            AdministrativeIdentityRequest(kind, "k-user@identity.test", "otherwise-unique@identity.test"));
        Assert.Equal(HttpStatusCode.Conflict, conflictingUserName.StatusCode);
        Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
        using var conflictingUpdate = new HttpRequestMessage(HttpMethod.Put, route + "/72/versioned")
        {
            Content = JsonContent.Create(AdministrativeUpdateRequest(kind, "new-user@identity.test", "\u01fa@identity.test")),
        };
        conflictingUpdate.Headers.TryAddWithoutValidation("If-Match", version);
        using var rejected = await client.SendAsync(conflictingUpdate);
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
        using var sameOwner = new HttpRequestMessage(HttpMethod.Put, route + "/72/versioned")
        {
            Content = JsonContent.Create(AdministrativeUpdateRequest(kind, "new-user@identity.test", rawEmail)),
        };
        sameOwner.Headers.TryAddWithoutValidation("If-Match", version);
        using var updated = await client.SendAsync(sameOwner);
        Assert.Equal(HttpStatusCode.NoContent, updated.StatusCode);
        var after = await identity.Users.AsNoTracking().SingleAsync(value => value.DatabaseID == 72);
        Assert.Equal(rawEmail, after.Email);
        Assert.Equal("CAF\u00c9@IDENTITY.TEST", after.NormalizedEmail);
        Assert.Equal(newRow.PasswordHash, after.PasswordHash);
        var retained = await identity.Users.AsNoTracking().SingleAsync(value => value.DatabaseID == 17);
        Assert.Equal(historicalEmail.ToUpperInvariant(), retained.NormalizedEmail);
        Assert.Equal("retained-security", retained.SecurityStamp);
        Assert.Equal("retained-concurrency", retained.ConcurrencyStamp);
    }

    [Fact]
    public async Task NormalCanonicalIdentityWriter_RawCustomerReceiptReplayRejectsEquivalentChangedPayload()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores, identityAdministration: true, identityValidation: true);
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, true);
        var key = Guid.NewGuid();
        var route = "/auth/v1/customer-identities/72/reconcile-create";
        factory.CustomerProfiles[72] = new(72, "cafe\u0301@identity.test", null, null, null);
        var payload = new CreateCustomerIdentityRequest("receipt-user@identity.test", "cafe\u0301@identity.test", "abcdef", true, null, null, null);
        async Task<HttpResponseMessage> SendAsync(CreateCustomerIdentityRequest request)
        {
            using var message = new HttpRequestMessage(HttpMethod.Post, route) { Content = JsonContent.Create(request) };
            message.Headers.TryAddWithoutValidation("Idempotency-Key", key.ToString("D"));
            return await client.SendAsync(message);
        }
        using var created = await SendAsync(payload);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var before = await AdministrativeSnapshotAsync(stores);
        using var replay = await SendAsync(payload);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
        using var changed = await SendAsync(payload with { Email = "caf\u00e9@identity.test" });
        Assert.Equal(HttpStatusCode.Conflict, changed.StatusCode);
        Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
        Assert.Equal("CAF\u00c9@IDENTITY.TEST",
            (await stores.Customers.Users.AsNoTracking().SingleAsync(value => value.DatabaseID == 72)).NormalizedEmail);
    }

    [Fact]
    public async Task NormalCanonicalIdentityWriter_UnversionedCustomerUnknownCommitReturns503WithoutRetry()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var control = new ConditionalAckState(IdentityKind.Customer);
        await using var factory = new Factory(stores, identityAdministration: true, identityValidation: true,
            conditionalFaults: [new ConditionalCommandAckLoss(control), new ConditionalCommitAckLoss(control)]);
        using var client = factory.CreateClient();
        await AuthorizeAdministrationAsync(client, false);
        const string route = "/auth/v1/customer-identities/72";
        factory.CustomerProfiles[72] = new(72, "before-ack@identity.test", null, null, null);
        using var created = await client.PostAsJsonAsync(route,
            AdministrativeIdentityRequest(IdentityKind.Customer, "before-ack@identity.test", "before-ack@identity.test"));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var before = await stores.Customers.Users.AsNoTracking().SingleAsync(value => value.DatabaseID == 72);
        control.Enabled = true;
        using var response = await client.PutAsJsonAsync(route,
            AdministrativeUpdateRequest(IdentityKind.Customer, "after-ack@identity.test", "cafe\u0301@identity.test"));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.True(control.Injected);
        Assert.False(control.ObservedRetries ?? true);
        Assert.Equal(1, control.Attempts);
        Assert.Equal(1, control.CompletedWrites);
        var after = await stores.Customers.Users.AsNoTracking().SingleAsync(value => value.DatabaseID == 72);
        Assert.Equal("after-ack@identity.test", after.UserName);
        Assert.Equal("CAF\u00c9@IDENTITY.TEST", after.NormalizedEmail);
        Assert.Equal(before.PasswordHash, after.PasswordHash);
        Assert.NotEqual(before.SecurityStamp, after.SecurityStamp);
        Assert.NotEqual(before.ConcurrencyStamp, after.ConcurrencyStamp);
        Assert.DoesNotContain("Synthetic", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    private sealed class ConditionalAckState(IdentityKind kind)
    {
        public IdentityKind Kind { get; } = kind;
        public bool Enabled { get; set; }
        public bool Injected { get; set; }
        public bool? ObservedRetries { get; set; }
        public int Attempts { get; set; }
        public int CompletedWrites { get; set; }
        public static NpgsqlException Failure() => new("Synthetic conditional acknowledgment loss", new TimeoutException("Synthetic acknowledgment failure"));
    }

    private sealed class ConditionalCommandAckLoss(ConditionalAckState state) : DbCommandInterceptor
    {
        private bool Matches(DbCommand command) => state.Enabled && state.Kind == IdentityKind.Customer &&
            command.CommandText.StartsWith("UPDATE \"AspNetUsers\"", StringComparison.Ordinal) &&
            command.CommandText.Contains("\"UserName\"", StringComparison.Ordinal);
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (Matches(command))
            {
                state.Attempts++;
                state.ObservedRetries = eventData.Context?.Database.CreateExecutionStrategy().RetriesOnFailure;
            }
            return ValueTask.FromResult(result);
        }
    }

    private sealed class ConditionalCommitAckLoss(ConditionalAckState state) : DbTransactionInterceptor
    {
        public override ValueTask<InterceptionResult<DbTransaction>> TransactionStartingAsync(DbConnection connection,
            TransactionStartingEventData eventData, InterceptionResult<DbTransaction> result, CancellationToken cancellationToken = default)
        {
            if (state.Enabled && state.Kind == IdentityKind.Employee)
            {
                state.Attempts++;
                state.ObservedRetries = eventData.Context?.Database.CreateExecutionStrategy().RetriesOnFailure;
            }
            return ValueTask.FromResult(result);
        }
        public override Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData eventData,
            CancellationToken cancellationToken = default)
        {
            if (state.Enabled)
            {
                state.CompletedWrites++;
                state.Injected = true;
                throw ConditionalAckState.Failure();
            }
            return Task.CompletedTask;
        }
    }

    private static object AdministrativeIdentityRequest(IdentityKind kind, string userName, string email) => kind == IdentityKind.Employee
        ? new CreateEmployeeIdentityRequest(userName, email, "abcdef", true, null)
        : new CreateCustomerIdentityRequest(userName, email, "abcdef", true, null, null, null);

    private static object AdministrativeUpdateRequest(IdentityKind kind, string userName, string email) => kind == IdentityKind.Employee
        ? new UpdateEmployeeIdentityRequest(userName, email, true, null, false, false, null, true)
        : new UpdateCustomerIdentityRequest(userName, email, true, null, false, false, null, true, null, null);

    private static async Task<string> AdministrativeSnapshotAsync(Stores stores) => JsonSerializer.Serialize(new
    {
        Identities = await SnapshotIdentitiesAsync(stores),
        Receipts = await stores.Customers.CreateOperations.AsNoTracking().OrderBy(value => value.OperationKey).ToListAsync(),
        Effects = await stores.Employees.RecoveryEffects.AsNoTracking().OrderBy(value => value.ActionId).ToListAsync(),
        Actions = await stores.State.IdentityActionTokens.AsNoTracking().OrderBy(value => value.Id).ToListAsync(),
        Sessions = await stores.State.RefreshSessions.AsNoTracking().OrderBy(value => value.Id).ToListAsync(),
    });

    private static async Task AuthorizeAdministrationAsync(HttpClient client, bool service)
    {
        string token;
        if (service)
        {
            using var response = await client.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest("issuance-test", Factory.ServiceSecret));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            token = (await response.Content.ReadFromJsonAsync<ServiceTokenResponse>())!.AccessToken;
        }
        else token = (await LoginAsync(client, IdentityKind.Employee)).AccessToken;
        client.DefaultRequestHeaders.Authorization = new("Bearer", token);
    }

    [Theory]
    [InlineData(IdentityKind.Employee, false)]
    [InlineData(IdentityKind.Customer, false)]
    [InlineData(IdentityKind.Employee, true)]
    [InlineData(IdentityKind.Customer, true)]
    public async Task NormalHistoricalPasswordFormat_LegacyHashAuthenticatesWithoutRehashOrUnrelatedIdentityMutation(IdentityKind kind, bool versionThree)
    {
        // Independently constructed PBKDF2 fixtures: salt bytes 00..0f, password issuance-password.
        // V2: marker 00, SHA1/1000/32. V3: marker 01, big-endian PRF=1/iterations=10000/saltLength=16, SHA256/32.
        var storedHash = versionThree
            ? "AQAAAAEAACcQAAAAEAABAgMEBQYHCAkKCwwNDg/L+ligzuuNDfC4puJ7/XESuifEOqBUSJqj0uubEuaNLQ=="
            : "AAABAgMEBQYHCAkKCwwNDg9XcaRSqhkwK0f7PnHfbpe/YYjZAgTebgJbfRuJrkU1dQ==";
        await using var stores = await Stores.CreateAsync(postgres);
        var context = kind == IdentityKind.Employee ? (LegacyIdentityDbContext)stores.Employees : stores.Customers;
        var row = await context.Users.SingleAsync();
        row.PasswordHash = storedHash;
        await context.SaveChangesAsync();
        var identities = await SnapshotIdentitiesAsync(stores);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var login = Login(kind);
        using (var scope = factory.Services.CreateScope())
        {
            var hasher = Assert.IsType<PasswordHasher<LegacyIdentityRow>>(scope.ServiceProvider.GetRequiredService<IPasswordHasher<LegacyIdentityRow>>());
            Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, hasher.VerifyHashedPassword(row, storedHash, login.Password));
        }
        using var denied = await client.PostAsJsonAsync("/auth/v1/login", login with { Password = "synthetic-wrong-password" });
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        var problem = await denied.Content.ReadAsStringAsync();
        foreach (var sensitive in new[] { row.Id, login.UserName, login.Password, "synthetic-wrong-password", storedHash, "accessToken" })
            Assert.DoesNotContain(sensitive, problem, StringComparison.Ordinal);
        await AssertOnlyLoginAccountingChangedAsync(identities, stores, kind, 1);
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());

        var tokens = await LoginAsync(client, kind);
        var jwt = ReadJwt(tokens.AccessToken, factory);
        Assert.Equal(row.Id, Assert.Single(jwt.Claims, claim => claim.Type == "sub").Value);
        Assert.Equal(kind.ToString().ToLowerInvariant(), Assert.Single(jwt.Claims, claim => claim.Type == "identity_kind").Value);
        var role = kind == IdentityKind.Employee ? "Employee" : "Customer";
        Assert.Equal(role, Assert.Single(jwt.Claims, claim => claim.Type == ClaimTypes.Role).Value);
        Assert.Equal(role, Assert.Single(jwt.Claims, claim => claim.Type == "role").Value);
        var session = Assert.Single(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Equal(row.Id, session.IdentityId);
        Assert.Equal(kind, session.IdentityKind);
        Assert.Equal(Hash(tokens.RefreshToken), session.TokenHash);
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
        await AssertOnlyLoginAccountingChangedAsync(identities, stores, kind, 0);
        Assert.Equal(storedHash, (await context.Users.AsNoTracking().SingleAsync()).PasswordHash);
    }

    [Theory]
    [InlineData(IdentityKind.Employee)]
    [InlineData(IdentityKind.Customer)]
    public async Task NormalHistoricalSecurity_IdentityIdPasswordDeniesWithOnlyAccounting_RealPasswordIssuesBoundActor(IdentityKind kind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var identities = await SnapshotIdentitiesAsync(stores);
        var id = kind == IdentityKind.Employee ? "issuance-employee" : "issuance-customer";
        var login = Login(kind);
        using var denied = await client.PostAsJsonAsync("/auth/v1/login", login with { Password = id });
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        var problem = await denied.Content.ReadAsStringAsync();
        Assert.DoesNotContain(id, problem, StringComparison.Ordinal);
        Assert.DoesNotContain(login.UserName, problem, StringComparison.Ordinal);
        Assert.DoesNotContain(login.Password, problem, StringComparison.Ordinal);
        Assert.DoesNotContain("accessToken", problem, StringComparison.Ordinal);
        await AssertOnlyLoginAccountingChangedAsync(identities, stores, kind, 1);
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());

        var tokens = await LoginAsync(client, kind);
        var jwt = ReadJwt(tokens.AccessToken, factory);
        var role = kind == IdentityKind.Employee ? "Employee" : "Customer";
        Assert.Equal(id, Assert.Single(jwt.Claims, claim => claim.Type == "sub").Value);
        Assert.Equal(kind.ToString().ToLowerInvariant(), Assert.Single(jwt.Claims, claim => claim.Type == "identity_kind").Value);
        Assert.Equal(role, Assert.Single(jwt.Claims, claim => claim.Type == ClaimTypes.Role).Value);
        Assert.Equal(role, Assert.Single(jwt.Claims, claim => claim.Type == "role").Value);
        var session = Assert.Single(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Equal(id, session.IdentityId);
        Assert.Equal(kind, session.IdentityKind);
        Assert.Equal(Hash(tokens.RefreshToken), session.TokenHash);
        await AssertOnlyLoginAccountingChangedAsync(identities, stores, kind, 0);
    }

    [Theory]
    [InlineData("validate")]
    [InlineData("longlived")]
    public async Task NormalHistoricalSecurity_RetiredCredentialRoutesRemainAbsentWithoutIdentityOrSessionMutation(string route)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var identities = await SnapshotIdentitiesAsync(stores);
        var login = Login(IdentityKind.Employee);
        using var request = route == "validate"
            ? new HttpRequestMessage(HttpMethod.Get, "/auth/validate?username=" + Uri.EscapeDataString(login.UserName)
                + "&password=" + Uri.EscapeDataString(login.Password))
            : new HttpRequestMessage(HttpMethod.Post, "/auth/token/longlived");
        if (route == "longlived")
            request.Headers.Authorization = new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(login.UserName + ":" + login.Password)));
        using var absent = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NotFound, absent.StatusCode);
        var body = await absent.Content.ReadAsStringAsync();
        Assert.DoesNotContain(login.UserName, body, StringComparison.Ordinal);
        Assert.DoesNotContain(login.Password, body, StringComparison.Ordinal);
        Assert.DoesNotContain("accessToken", body, StringComparison.Ordinal);
        if (request.Headers.Authorization is not null)
            Assert.DoesNotContain(request.Headers.Authorization.Parameter!, body, StringComparison.Ordinal);
        Assert.Equal(identities, await SnapshotIdentitiesAsync(stores));
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
        var tokens = await LoginAsync(client, IdentityKind.Employee);
        Assert.Equal("employee", Assert.Single(ReadJwt(tokens.AccessToken, factory).Claims, claim => claim.Type == "identity_kind").Value);
        Assert.Single(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData(IdentityKind.Employee)]
    [InlineData(IdentityKind.Customer)]
    public async Task NormalHistoricalIdentityNormalization_CanonicalCredentialsPreserveRowsAndBindSelectedActor(IdentityKind kind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var context = kind == IdentityKind.Employee ? (LegacyIdentityDbContext)stores.Employees : stores.Customers;
        var row = await context.Users.SingleAsync();
        row.UserName = "caf\u00e9@identity.test";
        row.NormalizedUserName = "CAF\u00c9@IDENTITY.TEST";
        await context.SaveChangesAsync();
        var before = await SnapshotIdentitiesAsync(stores);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        using var scope = factory.Services.CreateScope();
        var reader = scope.ServiceProvider.GetRequiredService<LegacyIdentityReader>();
        var framework = new UpperInvariantLookupNormalizer();
        var login = Login(kind);
        foreach (var alias in new[] { "caf\u00e9@identity.test", "cafe\u0301@identity.test" })
        {
            Assert.Equal("CAF\u00c9@IDENTITY.TEST", framework.NormalizeName(alias));
            var direct = await reader.ValidateAsync(alias, login.Password, kind, default);
            Assert.NotNull(direct);
            Assert.Equal(row.Id, direct.Id);
            Assert.Equal(before, await SnapshotIdentitiesAsync(stores));
            using var response = await client.PostAsJsonAsync("/auth/v1/login", login with { UserName = alias });
            var tokens = await ReadTokensAsync(response);
            var jwt = ReadJwt(tokens.AccessToken, factory);
            Assert.Equal(row.Id, Assert.Single(jwt.Claims, claim => claim.Type == "sub").Value);
            Assert.Equal(row.UserName, Assert.Single(jwt.Claims, claim => claim.Type == "name").Value);
            Assert.Equal(kind.ToString().ToLowerInvariant(), Assert.Single(jwt.Claims, claim => claim.Type == "identity_kind").Value);
            Assert.Equal(kind.ToString(), Assert.Single(jwt.Claims, claim => claim.Type == "role").Value);
            Assert.Equal(kind.ToString(), Assert.Single(jwt.Claims, claim => claim.Type == ClaimTypes.Role).Value);
            var session = await stores.State.RefreshSessions.AsNoTracking().SingleAsync(value => value.TokenHash == Hash(tokens.RefreshToken));
            Assert.Equal(row.Id, session.IdentityId);
            Assert.Equal(kind, session.IdentityKind);
            if (kind == IdentityKind.Employee)
                Assert.Equal(session.Id.ToString("D"), Assert.Single(jwt.Claims, claim => claim.Type == "sid").Value);
            else Assert.DoesNotContain(jwt.Claims, claim => claim.Type is "sid" or "permissions");
            Assert.Equal(before, await SnapshotIdentitiesAsync(stores));
        }
        foreach (var alias in new[] { " cafe\u0301@identity.test", "cafe\u0301@identity.test " })
        {
            // The raw reader does not trim; the existing HTTP coordinator deliberately does.
            Assert.Null(await reader.ValidateAsync(alias, login.Password, kind, default));
            using var response = await client.PostAsJsonAsync("/auth/v1/login", login with { UserName = alias });
            var tokens = await ReadTokensAsync(response);
            Assert.Equal(row.Id, Assert.Single(ReadJwt(tokens.AccessToken, factory).Claims, claim => claim.Type == "sub").Value);
            Assert.Equal(before, await SnapshotIdentitiesAsync(stores));
        }
        const string compatibilityAlias = "\uff43afe\u0301@identity.test";
        Assert.Null(await reader.ValidateAsync(compatibilityAlias, login.Password, kind, default));
        using (var denied = await client.PostAsJsonAsync("/auth/v1/login", login with { UserName = compatibilityAlias }))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
            Assert.DoesNotContain(compatibilityAlias, await denied.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }
        Assert.Equal(before, await SnapshotIdentitiesAsync(stores));
        using (var wrong = await client.PostAsJsonAsync("/auth/v1/login", login with { UserName = "cafe\u0301@identity.test", Password = "synthetic-wrong-password" }))
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        await AssertOnlyLoginAccountingChangedAsync(before, stores, kind, 1);
        using var recovered = await client.PostAsJsonAsync("/auth/v1/login", login with { UserName = "cafe\u0301@identity.test" });
        _ = await ReadTokensAsync(recovered);
        await AssertOnlyLoginAccountingChangedAsync(before, stores, kind, 0);
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
    }

    [Fact]
    public async Task NormalHistoricalIdentityNormalization_GoogleEmailLookupUsesCanonicalKeyWithoutWrites()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var row = await stores.Employees.Users.SingleAsync();
        row.Email = "caf\u00e9@identity.test";
        row.NormalizedEmail = "CAF\u00c9@IDENTITY.TEST";
        await stores.Employees.SaveChangesAsync();
        var before = await AdministrativeSnapshotAsync(stores);
        await using var factory = new Factory(stores, googleReadOnlyBoundary: true);
        using var scope = factory.Services.CreateScope();
        var reader = scope.ServiceProvider.GetRequiredService<IGoogleEmployeeIdentityReader>();
        foreach (var email in new[] { "caf\u00e9@identity.test", "cafe\u0301@identity.test", "  cafe\u0301@identity.test  " })
        {
            Assert.Equal("CAF\u00c9@IDENTITY.TEST", new UpperInvariantLookupNormalizer().NormalizeEmail(email.Trim()));
            var identity = await reader.FindActiveEmployeeByEmailAsync(email, default);
            Assert.NotNull(identity);
            Assert.Equal(row.Id, identity.Id);
            Assert.Equal(row.Email, identity.Email);
            Assert.Equal(IdentityKind.Employee, identity.Kind);
            Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
        }
        Assert.Null(await reader.FindActiveEmployeeByEmailAsync("\uff43afe\u0301@identity.test", default));
        Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
        // Existing Auth writers could persist an uppercase-only decomposed email key.
        row.Email = "cafe\u0301@identity.test";
        row.NormalizedEmail = "CAFE\u0301@IDENTITY.TEST";
        await stores.Employees.SaveChangesAsync();
        var legacy = await AdministrativeSnapshotAsync(stores);
        var retained = await reader.FindActiveEmployeeByEmailAsync(row.Email, default);
        Assert.NotNull(retained);
        Assert.Equal(row.Id, retained.Id);
        Assert.Equal(row.Email, retained.Email);
        Assert.Equal(legacy, await AdministrativeSnapshotAsync(stores));
        stores.Employees.Users.Add(new LegacyIdentityRow
        {
            Id = "canonical-email-collision",
            UserName = "distinct-collision-user",
            NormalizedUserName = "DISTINCT-COLLISION-USER",
            Email = "caf\u00e9@identity.test",
            NormalizedEmail = "CAF\u00c9@IDENTITY.TEST",
            EmailConfirmed = true,
            SecurityStamp = "collision-stamp",
            ConcurrencyStamp = "collision-concurrency",
        });
        await stores.Employees.SaveChangesAsync();
        var ambiguous = await AdministrativeSnapshotAsync(stores);
        await Assert.ThrowsAsync<InvalidOperationException>(() => reader.FindActiveEmployeeByEmailAsync(row.Email, default));
        Assert.Equal(ambiguous, await AdministrativeSnapshotAsync(stores));
    }

    private static async Task<string> SnapshotIdentitiesAsync(Stores stores) => JsonSerializer.Serialize(new
    {
        Employees = await stores.Employees.Users.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
        Customers = await stores.Customers.Users.AsNoTracking().OrderBy(row => row.Id).ToListAsync(),
    });

    private static async Task AssertOnlyLoginAccountingChangedAsync(string before, Stores stores,
        IdentityKind kind, int count, DateTimeOffset? lockoutEnd = null)
    {
        var expected = JsonNode.Parse(before)!;
        var actual = JsonNode.Parse(await SnapshotIdentitiesAsync(stores))!;
        var collection = kind == IdentityKind.Employee ? "Employees" : "Customers";
        var expectedRow = expected[collection]!.AsArray().Single()!;
        var actualRow = actual[collection]!.AsArray().Single()!;
        var stamp = actualRow["ConcurrencyStamp"]!.GetValue<string>();
        Assert.True(Guid.TryParse(stamp, out _));
        Assert.NotEqual(expectedRow["ConcurrencyStamp"]!.GetValue<string>(), stamp);
        expectedRow["ConcurrencyStamp"] = stamp;
        expectedRow["AccessFailedCount"] = count;
        expectedRow["LockoutEnd"] = JsonSerializer.SerializeToNode(lockoutEnd);
        Assert.True(JsonNode.DeepEquals(expected, actual), "Only the selected row's login accounting fields may change.");
    }

    [Theory]
    [InlineData(IdentityKind.Employee, false)]
    [InlineData(IdentityKind.Employee, true)]
    [InlineData(IdentityKind.Customer, false)]
    [InlineData(IdentityKind.Customer, true)]
    public async Task NormalLoginAndRefresh_PersistedActorRole_ReachesNormalRoleAuthorization(IdentityKind kind, bool refresh)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        var tokens = await LoginAsync(client, kind);
        var original = ReadJwt(tokens.AccessToken, factory);
        if (refresh)
        {
            using var response = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(tokens.RefreshToken));
            tokens = await ReadTokensAsync(response);
        }
        var token = ReadJwt(tokens.AccessToken, factory);
        var expectedRole = kind == IdentityKind.Employee ? "Employee" : "Customer";
        var oppositeRole = kind == IdentityKind.Employee ? "Customer" : "Employee";
        await using var consumer = await CreateDefaultsConsumerAsync(factory);
        using var consumerClient = consumer.GetTestClient();
        consumerClient.DefaultRequestHeaders.Authorization = new("Bearer", tokens.AccessToken);
        using var accepted = await consumerClient.GetAsync("/" + expectedRole);
        using var refused = await consumerClient.GetAsync("/" + oppositeRole);
        Assert.Equal(HttpStatusCode.NoContent, accepted.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.Equal(expectedRole, Assert.Single(token.Claims, claim => claim.Type == ClaimTypes.Role).Value);
        Assert.Equal(expectedRole, Assert.Single(token.Claims, claim => claim.Type == "role").Value);
        Assert.Equal(kind.ToString().ToLowerInvariant(), Assert.Single(token.Claims, claim => claim.Type == "identity_kind").Value);
        Assert.Equal(original.Claims.Where(claim => claim.Type == "permissions").Select(claim => claim.Value),
            token.Claims.Where(claim => claim.Type == "permissions").Select(claim => claim.Value));
        var parameters = factory.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters;
        var principal = new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(tokens.AccessToken, parameters, out _);
        Assert.Equal(ClaimTypes.Role, Assert.IsAssignableFrom<ClaimsIdentity>(principal.Identity).RoleClaimType);
        await using var scope = factory.Services.CreateAsyncScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        Assert.True((await authorization.AuthorizeAsync(principal, null,
            new[] { new RolesAuthorizationRequirement([expectedRole]) })).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(principal, null,
            new[] { new RolesAuthorizationRequirement([oppositeRole]) })).Succeeded);
        var persisted = await stores.State.RefreshSessions.AsNoTracking().SingleAsync(row => row.TokenHash == Hash(tokens.RefreshToken));
        Assert.Equal(kind, persisted.IdentityKind);
        Assert.Equal(kind == IdentityKind.Employee ? "issuance-employee" : "issuance-customer", persisted.IdentityId);
        if (kind == IdentityKind.Employee)
            Assert.Equal(persisted.Id.ToString("D"), Assert.Single(token.Claims, claim => claim.Type == "sid").Value);
        else
            Assert.DoesNotContain(token.Claims, claim => claim.Type is "sid" or "permissions");
    }

    private static readonly string[] EmployeeEditGrants =
    [
        "legacy-employee.employees.update", "legacy-employee.addresses.read",
        "legacy-employee.addresses.create", "legacy-employee.addresses.update", "legacy-employee.roles.read",
    ];

    [Theory]
    [InlineData("password")]
    [InlineData("refresh")]
    [InlineData("google")]
    public async Task NormalEmployeeEditGrants_ActualInteractiveIssuerAllowsFiveScopesAndCustomerCannotEscalate(string flow)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores, googleReadOnlyBoundary: flow == "google");
        using var client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        TokenResponse tokens;
        if (flow == "google")
        {
            await AuthorizeAdministrationAsync(client, true);
            using var nonceResponse = await client.PostAsJsonAsync("/auth/v1/exchange/google/nonce", new GoogleIdentityNonceRequest("intranet"));
            Assert.Equal(HttpStatusCode.OK, nonceResponse.StatusCode);
            var nonce = (await nonceResponse.Content.ReadFromJsonAsync<GoogleIdentityNonceResponse>())!;
            using var exchange = await client.PostAsJsonAsync("/auth/v1/exchange/google", new GoogleExchangeRequest(new string('g', 128), "intranet", nonce.Nonce));
            tokens = await ReadTokensAsync(exchange);
        }
        else
        {
            tokens = await LoginAsync(client, IdentityKind.Employee);
            if (flow == "refresh")
            {
                using var refreshed = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(tokens.RefreshToken));
                tokens = await ReadTokensAsync(refreshed);
            }
        }
        var jwt = ReadJwt(tokens.AccessToken, factory);
        Assert.Equal("Employee", Assert.Single(jwt.Claims, value => value.Type == "role").Value);
        Assert.Equal("Employee", Assert.Single(jwt.Claims, value => value.Type == ClaimTypes.Role).Value);
        Assert.Equal("employee", Assert.Single(jwt.Claims, value => value.Type == "identity_kind").Value);
        foreach (var permission in EmployeeEditGrants)
            Assert.Single(jwt.Claims, value => value.Type == "permissions" && value.Value == permission);
        var sid = Guid.Parse(Assert.Single(jwt.Claims, value => value.Type == "sid").Value);
        await AssertStoredBindingAsync(tokens, stores, sid, factory);
        await using var consumer = await CreateDefaultsConsumerAsync(factory);
        using var consumerClient = consumer.GetTestClient();
        consumerClient.DefaultRequestHeaders.Authorization = new("Bearer", tokens.AccessToken);
        foreach (var permission in EmployeeEditGrants)
        {
            using var allowed = await consumerClient.GetAsync("/grant/" + permission);
            Assert.Equal(HttpStatusCode.NoContent, allowed.StatusCode);
        }
        var customer = await LoginAsync(client, IdentityKind.Customer);
        var customerJwt = ReadJwt(customer.AccessToken, factory);
        Assert.DoesNotContain(customerJwt.Claims, value => value.Type == "permissions" && EmployeeEditGrants.Contains(value.Value));
        consumerClient.DefaultRequestHeaders.Authorization = new("Bearer", customer.AccessToken);
        foreach (var permission in EmployeeEditGrants)
        {
            using var denied = await consumerClient.GetAsync("/grant/" + permission);
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        }
    }

    [Fact]
    public async Task NormalServiceExchange_DoesNotBecomeAnInteractiveActor()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest("issuance-test", Factory.ServiceSecret));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var token = (await response.Content.ReadFromJsonAsync<ServiceTokenResponse>())!;
        var parameters = factory.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters;
        var principal = new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(token.AccessToken, parameters, out _);
        Assert.DoesNotContain(principal.Claims, claim => claim.Type is ClaimTypes.Role or "role" or "sid");
        Assert.DoesNotContain(principal.Claims, claim => claim.Type == "permissions" && EmployeeEditGrants.Contains(claim.Value));
        await using var consumer = await CreateDefaultsConsumerAsync(factory);
        using var consumerClient = consumer.GetTestClient();
        consumerClient.DefaultRequestHeaders.Authorization = new("Bearer", token.AccessToken);
        using var denied = await consumerClient.GetAsync("/Employee");
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        foreach (var permission in EmployeeEditGrants)
        {
            using var scopeDenied = await consumerClient.GetAsync("/grant/" + permission);
            Assert.Equal(HttpStatusCode.Forbidden, scopeDenied.StatusCode);
        }
        await using var scope = factory.Services.CreateAsyncScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        Assert.False((await authorization.AuthorizeAsync(principal, null,
            new[] { new RolesAuthorizationRequirement(["Employee", "Customer"]) })).Succeeded);
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NormalScopedIssuers_DoNotBecomeInteractiveActors(bool capability)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        await using var scope = factory.Services.CreateAsyncScope();
        var now = DateTimeOffset.UtcNow;
        var issued = capability
            ? scope.ServiceProvider.GetRequiredService<IQuotationInvoiceCapabilityTokenIssuer>()
                .IssueQuotationInvoiceCapability("issuance-employee", 1, Guid.NewGuid(), now, 60)
            : scope.ServiceProvider.GetRequiredService<IInvoiceDelegationTokenIssuer>()
                .IssueInvoiceDelegation("issuance-employee", 1, Guid.NewGuid(), now);
        var parameters = factory.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters.Clone();
        parameters.ValidAudience = capability ? QuotationInvoiceCapabilityContract.Audience : InvoiceDelegationContract.Audience;
        var principal = new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(issued.Value, parameters, out _);
        Assert.DoesNotContain(principal.Claims, claim => claim.Type is ClaimTypes.Role or "role" or "sid");
        Assert.DoesNotContain(principal.Claims, claim => claim.Type == "permissions" && EmployeeEditGrants.Contains(claim.Value));
        await using var consumer = await CreateDefaultsConsumerAsync(factory, parameters.ValidAudience);
        using var consumerClient = consumer.GetTestClient();
        consumerClient.DefaultRequestHeaders.Authorization = new("Bearer", issued.Value);
        using var denied = await consumerClient.GetAsync("/Employee");
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        foreach (var permission in EmployeeEditGrants)
        {
            using var scopeDenied = await consumerClient.GetAsync("/grant/" + permission);
            Assert.Equal(HttpStatusCode.Forbidden, scopeDenied.StatusCode);
        }
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        Assert.False((await authorization.AuthorizeAsync(principal, null,
            new[] { new RolesAuthorizationRequirement(["Employee", "Customer"]) })).Succeeded);
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    [Fact]
    public async Task NormalIssuer_UndefinedInteractiveKind_RefusesBeforeIssuance()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        await using var scope = factory.Services.CreateAsyncScope();
        var identity = await scope.ServiceProvider.GetRequiredService<ILegacyIdentityReader>()
            .FindActiveAsync("issuance-employee", IdentityKind.Employee, default);
        Assert.NotNull(identity);
        var issuer = scope.ServiceProvider.GetRequiredService<IAccessTokenIssuer>();
        Assert.Throws<ArgumentOutOfRangeException>(() => issuer.Issue(
            identity with { Kind = (IdentityKind)42 }, DateTimeOffset.UtcNow, null));
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    private static async Task<WebApplication> CreateDefaultsConsumerAsync(Factory factory, string audience = "issuance-test")
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Production" });
        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Jwt:Issuer"] = "https://issuance.test",
            ["Jwt:Audience"] = audience,
            ["Jwt:PublicKey"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(factory.PublicKey)),
        });
        builder.AddJwtAuthentication();
        builder.Services.AddAuthorization();
        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/Employee", () => Results.NoContent()).RequireAuthorization(policy => policy.RequireRole("Employee"));
        app.MapGet("/Customer", () => Results.NoContent()).RequireAuthorization(policy => policy.RequireRole("Customer"));
        foreach (var permission in EmployeeEditGrants)
            app.MapGet("/grant/" + permission, () => Results.NoContent()).RequireAuthorization(policy =>
                policy.RequireAuthenticatedUser().RequireRole("Employee").RequireClaim("permissions", permission));
        try
        {
            await app.StartAsync();
            return app;
        }
        catch
        {
            await app.DisposeAsync();
            throw;
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EmployeePasswordAndRefresh_BindExactPersistedRow(bool refresh)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        var tokens = await LoginAsync(client, IdentityKind.Employee);
        var original = await stores.State.RefreshSessions.AsNoTracking().SingleAsync();
        if (refresh)
        {
            using var response = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(tokens.RefreshToken));
            tokens = await ReadTokensAsync(response);
        }
        var jwt = ReadJwt(tokens.AccessToken, factory);
        var sid = Assert.Single(jwt.Claims, claim => claim.Type == "sid").Value;
        Assert.True(Guid.TryParseExact(sid, "D", out var id));
        Assert.NotEqual(Guid.Empty, id);
        Assert.Equal(id.ToString("D"), sid);
        var exact = await AssertStoredBindingAsync(tokens, stores, id, factory);
        if (refresh)
        {
            Assert.NotEqual(original.Id, exact.Id);
            var rotated = await stores.State.RefreshSessions.AsNoTracking().SingleAsync(row => row.Id == original.Id);
            Assert.NotNull(rotated.RotatedAt);
            Assert.Equal(exact.Id, rotated.ReplacedById);
            Assert.Equal(rotated.FamilyId, exact.FamilyId);
            Assert.Equal(2, await stores.State.RefreshSessions.CountAsync());
        }
        else Assert.Equal(original.Id, exact.Id);
        Assert.Contains(jwt.Claims, claim => claim.Type == "permissions" && claim.Value == "legacy.quotation-requests.read");
        Assert.Contains(jwt.Claims, claim => claim.Type == "permissions" && claim.Value == "legacy.quotation-requests.update");
    }

    [Fact]
    public async Task EmployeeGoogleExchange_BindsExactPersistedRow()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var scope = factory.Services.CreateScope();
        var nonce = await scope.ServiceProvider.GetRequiredService<IGoogleIdentityNonceService>()
            .IssueAsync("legacy-intranet", "intranet", default);
        var result = await scope.ServiceProvider.GetRequiredService<GoogleAuthenticationService>()
            .ExchangeAsync(new GoogleExchangeRequest(new string('g', 128), "intranet", nonce.Nonce), "legacy-intranet", default);
        Assert.True(result.Succeeded);
        var tokens = Assert.IsType<TokenResponse>(result.Tokens);
        var sid = Assert.Single(ReadJwt(tokens.AccessToken, factory).Claims, claim => claim.Type == "sid").Value;
        Assert.True(Guid.TryParseExact(sid, "D", out var id));
        Assert.NotEqual(Guid.Empty, id);
        Assert.Equal(id.ToString("D"), sid);
        await AssertStoredBindingAsync(tokens, stores, id, factory);
        Assert.Equal(1, await stores.State.RefreshSessions.CountAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CustomerPasswordAndRefresh_PreserveEnvelopeAndNoEmployeeSidOrGrants(bool refresh)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        var tokens = await LoginAsync(client, IdentityKind.Customer);
        if (refresh)
        {
            using var response = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(tokens.RefreshToken));
            tokens = await ReadTokensAsync(response);
        }
        var jwt = ReadJwt(tokens.AccessToken, factory);
        Assert.Equal("issuance-customer", Assert.Single(jwt.Claims, claim => claim.Type == "sub").Value);
        Assert.Equal("customer", Assert.Single(jwt.Claims, claim => claim.Type == "identity_kind").Value);
        Assert.DoesNotContain(jwt.Claims, claim => claim.Type == "sid");
        Assert.DoesNotContain(jwt.Claims, claim => claim.Type == "permissions");
        var exact = await stores.State.RefreshSessions.AsNoTracking().SingleAsync(row => row.TokenHash == Hash(tokens.RefreshToken));
        Assert.Equal(IdentityKind.Customer, exact.IdentityKind);
        Assert.Equal("issuance-customer", exact.IdentityId);
    }

    [Fact]
    public async Task ServiceCredentialExchange_PreservesEnvelopeAndExactConfiguredGrants_NoEmployeeSid()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var factory = new Factory(stores);
        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest("issuance-test", Factory.ServiceSecret));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(["accessToken", "expiresIn", "tokenType"], json.EnumerateObject().Select(property => property.Name).Order().ToArray());
        var tokens = Assert.IsType<ServiceTokenResponse>(json.Deserialize<ServiceTokenResponse>(new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        Assert.Equal("Bearer", tokens.TokenType);
        Assert.Equal(900, tokens.ExpiresIn);
        var jwt = ReadJwt(tokens.AccessToken, factory);
        Assert.Equal("service:issuance-test", Assert.Single(jwt.Claims, claim => claim.Type == "sub").Value);
        Assert.Equal("service", Assert.Single(jwt.Claims, claim => claim.Type == "identity_kind").Value);
        Assert.DoesNotContain(jwt.Claims, claim => claim.Type == "sid");
        Assert.Equal(["legacy-contact.messages.create"], jwt.Claims.Where(claim => claim.Type == "permissions").Select(claim => claim.Value).ToArray());
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EmployeePasswordOrRefresh_SaveFailure_ReturnsNoAccessResponseOrNewSession(bool refresh)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var fault = new RejectSave();
        await using var factory = new Factory(stores, fault);
        using var client = factory.CreateClient();
        TokenResponse? original = refresh ? await LoginAsync(client, IdentityKind.Employee) : null;
        fault.Enabled = true;
        using var response = refresh
            ? await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(original!.RefreshToken))
            : await client.PostAsJsonAsync("/auth/v1/login", Login(IdentityKind.Employee));
        Assert.True(fault.Injected);
        Assert.False(response.IsSuccessStatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("accessToken", body, StringComparison.Ordinal);
        Assert.DoesNotContain("refreshToken", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Synthetic", body, StringComparison.Ordinal);
        var rows = await stores.State.RefreshSessions.AsNoTracking().ToListAsync();
        if (refresh)
        {
            var row = Assert.Single(rows);
            Assert.Equal(Hash(original!.RefreshToken), row.TokenHash);
            Assert.Null(row.RotatedAt);
            Assert.Null(row.ReplacedById);
            Assert.Null(row.RevokedAt);
        }
        else Assert.Empty(rows);
    }

    [Fact]
    public async Task EmployeeGoogleExchange_SaveFailure_ReturnsNoIssuedResultOrSession()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var fault = new RejectSave();
        await using var factory = new Factory(stores, fault);
        using var scope = factory.Services.CreateScope();
        var nonce = await scope.ServiceProvider.GetRequiredService<IGoogleIdentityNonceService>()
            .IssueAsync("legacy-intranet", "intranet", default);
        fault.Enabled = true;
        await Assert.ThrowsAsync<DbUpdateException>(() => scope.ServiceProvider.GetRequiredService<GoogleAuthenticationService>()
            .ExchangeAsync(new GoogleExchangeRequest(new string('g', 128), "intranet", nonce.Nonce), "legacy-intranet", default));
        Assert.True(fault.Injected);
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData(IdentityKind.Employee)]
    [InlineData(IdentityKind.Customer)]
    public async Task NormalReadOnlyLockout_ExactDeadlineDeniesDirectReadAndRefreshWithoutIdentityWrites(IdentityKind kind)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));
        await using var factory = new Factory(stores, clock: clock);
        using var client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var tokens = await LoginAsync(client, kind);
        var originalTokens = tokens;
        using (var preparedRotation = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(tokens.RefreshToken)))
            tokens = await ReadTokensAsync(preparedRotation);
        var preparedFamily = await stores.State.RefreshSessions.AsNoTracking().OrderBy(value => value.Id).ToListAsync();
        Assert.Equal(2, preparedFamily.Count);
        Assert.Single(preparedFamily.Select(value => value.FamilyId).Distinct());
        var originalSession = Assert.Single(preparedFamily, value => value.TokenHash == Hash(originalTokens.RefreshToken));
        var activeSession = Assert.Single(preparedFamily, value => value.TokenHash == Hash(tokens.RefreshToken));
        Assert.NotNull(originalSession.RotatedAt);
        Assert.Equal(activeSession.Id, originalSession.ReplacedById);
        Assert.Null(originalSession.RevokedAt);
        Assert.Null(activeSession.RevokedAt);
        var context = kind == IdentityKind.Employee ? (LegacyIdentityDbContext)stores.Employees : stores.Customers;
        var row = await context.Users.SingleAsync();
        row.LockoutEnd = clock.GetUtcNow();
        row.AccessFailedCount = 3;
        await context.SaveChangesAsync();
        var identities = await SnapshotIdentitiesAsync(stores);
        using (var scope = factory.Services.CreateScope())
        {
            var reader = scope.ServiceProvider.GetRequiredService<LegacyIdentityReader>();
            Assert.Null(await reader.ValidateAsync(row.UserName!, Login(kind).Password, kind, default));
            Assert.Null(await reader.FindActiveAsync(row.Id, kind, default));
            if (kind == IdentityKind.Employee) Assert.Null(await reader.FindActiveEmployeeByEmailAsync(row.Email!, default));
        }
        using var denied = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(tokens.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        Assert.DoesNotContain("accessToken", await denied.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        var family = await stores.State.RefreshSessions.AsNoTracking().ToListAsync();
        Assert.Equal(2, family.Count);
        Assert.Equal(preparedFamily.Select(value => value.Id), family.OrderBy(value => value.Id).Select(value => value.Id));
        Assert.Equal(preparedFamily.Select(value => value.TokenHash), family.OrderBy(value => value.Id).Select(value => value.TokenHash));
        Assert.All(family, value => Assert.Equal(originalSession.FamilyId, value.FamilyId));
        Assert.All(family, value => Assert.NotNull(value.RevokedAt));
        Assert.Equal(identities, await SnapshotIdentitiesAsync(stores));
        clock.Advance(TimeSpan.FromTicks(10)); // PostgreSQL timestamp precision is one microsecond.
        using (var scope = factory.Services.CreateScope())
        {
            var reader = scope.ServiceProvider.GetRequiredService<LegacyIdentityReader>();
            Assert.NotNull(await reader.ValidateAsync(row.UserName!, Login(kind).Password, kind, default));
            Assert.NotNull(await reader.FindActiveAsync(row.Id, kind, default));
            if (kind == IdentityKind.Employee) Assert.NotNull(await reader.FindActiveEmployeeByEmailAsync(row.Email!, default));
        }
        Assert.Equal(identities, await SnapshotIdentitiesAsync(stores));
        var active = await LoginAsync(client, kind);
        var afterLogin = await SnapshotIdentitiesAsync(stores);
        using var allowed = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(active.RefreshToken));
        _ = await ReadTokensAsync(allowed);
        Assert.Equal(afterLogin, await SnapshotIdentitiesAsync(stores));
        using var oldFamily = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(tokens.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, oldFamily.StatusCode);
        using var oldParent = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(originalTokens.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, oldParent.StatusCode);
        row.LockoutEnabled = false;
        row.LockoutEnd = clock.GetUtcNow().AddMinutes(5);
        await context.SaveChangesAsync();
        var disabled = await SnapshotIdentitiesAsync(stores);
        using var disabledScope = factory.Services.CreateScope();
        var disabledReader = disabledScope.ServiceProvider.GetRequiredService<LegacyIdentityReader>();
        Assert.NotNull(await disabledReader.ValidateAsync(row.UserName!, Login(kind).Password, kind, default));
        Assert.NotNull(await disabledReader.FindActiveAsync(row.Id, kind, default));
        if (kind == IdentityKind.Employee) Assert.NotNull(await disabledReader.FindActiveEmployeeByEmailAsync(row.Email!, default));
        Assert.Equal(disabled, await SnapshotIdentitiesAsync(stores));
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
    }

    [Fact]
    public async Task NormalReadOnlyLockout_CustomerSelfExactDeadlineIsForbiddenThenExpiredOrDisabledIsFound()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));
        var row = await stores.Customers.Users.SingleAsync();
        row.DatabaseID = 42;
        await stores.Customers.SaveChangesAsync();
        await using var factory = new Factory(stores, clock: clock);
        using var client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var tokens = await LoginAsync(client, IdentityKind.Customer);
        client.DefaultRequestHeaders.Authorization = new("Bearer", tokens.AccessToken);
        row.LockoutEnd = clock.GetUtcNow();
        await stores.Customers.SaveChangesAsync();
        var before = await AdministrativeSnapshotAsync(stores);
        using var denied = await client.GetAsync("/auth/v1/customer-self-service/identity");
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
        clock.Advance(TimeSpan.FromTicks(10));
        using var expired = await client.GetAsync("/auth/v1/customer-self-service/identity");
        Assert.Equal(HttpStatusCode.OK, expired.StatusCode);
        var projection = await expired.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(["customerId", "email", "mobile"], projection.EnumerateObject().Select(value => value.Name).Order().ToArray());
        Assert.Equal(42, projection.GetProperty("customerId").GetInt32());
        Assert.Equal(before, await AdministrativeSnapshotAsync(stores));
        row.LockoutEnabled = false;
        row.LockoutEnd = clock.GetUtcNow().AddMinutes(5);
        await stores.Customers.SaveChangesAsync();
        var disabled = await AdministrativeSnapshotAsync(stores);
        using var allowed = await client.GetAsync("/auth/v1/customer-self-service/identity");
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        Assert.Equal(disabled, await AdministrativeSnapshotAsync(stores));
    }

    [Fact]
    public async Task NormalReadOnlyLockout_GoogleExactDeadlineDeniesWithoutSessionThenExpiredOrDisabledIssues()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));
        var row = await stores.Employees.Users.SingleAsync();
        row.LockoutEnd = clock.GetUtcNow();
        row.AccessFailedCount = 3;
        await stores.Employees.SaveChangesAsync();
        var identities = await SnapshotIdentitiesAsync(stores);
        await using var factory = new Factory(stores, clock: clock, googleReadOnlyBoundary: true);
        using var client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        await AuthorizeAdministrationAsync(client, true);
        async Task<GoogleExchangeRequest> NewExchangeAsync()
        {
            using var response = await client.PostAsJsonAsync("/auth/v1/exchange/google/nonce", new GoogleIdentityNonceRequest("intranet"));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var nonce = (await response.Content.ReadFromJsonAsync<GoogleIdentityNonceResponse>())!;
            return new(new string('g', 128), "intranet", nonce.Nonce);
        }
        var request = await NewExchangeAsync();
        using var denied = await client.PostAsJsonAsync("/auth/v1/exchange/google", request);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        Assert.DoesNotContain("accessToken", await denied.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Equal(identities, await SnapshotIdentitiesAsync(stores));
        using var replay = await client.PostAsJsonAsync("/auth/v1/exchange/google", request);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        clock.Advance(TimeSpan.FromTicks(10));
        using var expired = await client.PostAsJsonAsync("/auth/v1/exchange/google", await NewExchangeAsync());
        var tokens = await ReadTokensAsync(expired);
        Assert.Equal(row.Id, Assert.Single(ReadJwt(tokens.AccessToken, factory).Claims, value => value.Type == "sub").Value);
        Assert.Single(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Equal(identities, await SnapshotIdentitiesAsync(stores));
        row.LockoutEnabled = false;
        row.LockoutEnd = clock.GetUtcNow().AddMinutes(5);
        await stores.Employees.SaveChangesAsync();
        var disabled = await SnapshotIdentitiesAsync(stores);
        using var allowed = await client.PostAsJsonAsync("/auth/v1/exchange/google", await NewExchangeAsync());
        _ = await ReadTokensAsync(allowed);
        Assert.Equal(2, await stores.State.RefreshSessions.CountAsync());
        Assert.Equal(disabled, await SnapshotIdentitiesAsync(stores));
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
    }

    private static LoginRequest Login(IdentityKind kind) => new(kind == IdentityKind.Employee ? "issuance@example.com" : "customer@example.com", "issuance-password", kind);
    private static async Task<TokenResponse> LoginAsync(HttpClient client, IdentityKind kind)
    {
        using var response = await client.PostAsJsonAsync("/auth/v1/login", Login(kind));
        return await ReadTokensAsync(response);
    }
    private static async Task<TokenResponse> ReadTokensAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(["accessToken", "expiresIn", "refreshExpiresAt", "refreshToken", "tokenType"], json.EnumerateObject().Select(property => property.Name).Order().ToArray());
        var tokens = Assert.IsType<TokenResponse>(json.Deserialize<TokenResponse>(new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        Assert.Equal("Bearer", tokens.TokenType);
        Assert.Equal(900, tokens.ExpiresIn);
        return tokens;
    }
    private static JwtSecurityToken ReadJwt(string token, Factory factory)
    {
        var parameters = factory.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters;
        new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(token, parameters, out var validated);
        var jwt = Assert.IsType<JwtSecurityToken>(validated);
        Assert.Equal("RS256", jwt.Header.Alg);
        Assert.Equal("https://issuance.test", jwt.Issuer);
        Assert.Equal("issuance-test", Assert.Single(jwt.Audiences));
        return jwt;
    }
    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value)));
    private static async Task<RefreshSession> AssertStoredBindingAsync(TokenResponse tokens, Stores stores, Guid id, Factory factory)
    {
        var row = await stores.State.RefreshSessions.AsNoTracking().SingleAsync(session => session.Id == id);
        Assert.Equal("issuance-employee", row.IdentityId);
        Assert.Equal(IdentityKind.Employee, row.IdentityKind);
        Assert.Equal("issuance-stamp", row.SecurityStamp);
        Assert.Null(row.RevokedAt);
        Assert.Equal(Hash(tokens.RefreshToken), row.TokenHash);
        Assert.Equal("issuance-employee", Assert.Single(ReadJwt(tokens.AccessToken, factory).Claims, claim => claim.Type == "sub").Value);
        Assert.Equal("employee", Assert.Single(ReadJwt(tokens.AccessToken, factory).Claims, claim => claim.Type == "identity_kind").Value);
        return row;
    }

    private sealed class RejectSave : SaveChangesInterceptor
    {
        public bool Enabled { get; set; }
        public bool Injected { get; private set; }
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (Enabled && eventData.Context!.ChangeTracker.Entries<RefreshSession>().Any(entry => entry.State == EntityState.Added))
            {
                Injected = true;
                throw new DbUpdateException("Synthetic session persistence failure");
            }
            return ValueTask.FromResult(result);
        }
    }

    private sealed class Factory(Stores stores, RejectSave? fault = null, TimeProvider? clock = null, bool tinyIdentityPool = false, bool identityAdministration = false, bool identityValidation = false, IInterceptor[]? conditionalFaults = null, bool googleReadOnlyBoundary = false) : WebApplicationFactory<Program>
    {
        public const string ServiceSecret = "issuance-test-only-secret-0123456789";
        private readonly RSA signing = RSA.Create(2048);
        public Dictionary<int, EmployeeProfileBinding> Profiles { get; } = [];
        public Dictionary<int, CustomerProfileBinding> CustomerProfiles { get; } = [];
        public HttpStatusCode? ProfileStatus { get; set; }
        public string? ProfileBody { get; set; }
        public int ProfileReads { get; private set; }
        public bool ProfileReadGrant { get; set; } = true;
        public string PublicKey => signing.ExportSubjectPublicKeyInfoPem();
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                var settings = new Dictionary<string, string?>
                {
                    ["ConnectionStrings:EmployeeIdentity"] = IdentityConnection(stores.Employees, tinyIdentityPool),
                    ["ConnectionStrings:CustomerIdentity"] = IdentityConnection(stores.Customers, tinyIdentityPool),
                    ["ConnectionStrings:RefreshSessions"] = stores.State.Database.GetConnectionString(),
                    ["Jwt:Issuer"] = "https://issuance.test",
                    ["Jwt:Audience"] = "issuance-test",
                    ["Jwt:PrivateKeyPem"] = signing.ExportPkcs8PrivateKeyPem(),
                    ["Jwt:KeyId"] = "issuance-test",
                    ["Jwt:AccessTokenLifetimeSeconds"] = "900",
                    ["ServiceClients:Clients:issuance-test:SecretSha256"] = ServiceClientCredential.HashSecret(ServiceSecret),
                    ["ServiceClients:Clients:issuance-test:Permissions:0"] = "legacy-contact.messages.create",
                    ["Services:Auth:BaseUrl"] = "https://issuance.test",
                    ["Services:EmployeeService:BaseUrl"] = "https://employee-profile.test",
                    ["Services:CustomerService:BaseUrl"] = "https://customer-profile.test",
                    ["ServiceAuthentication:ClientId"] = "legacy-auth",
                    ["ServiceAuthentication:ClientSecret"] = ServiceSecret,
                    ["ServiceClients:Clients:legacy-auth:SecretSha256"] = ServiceClientCredential.HashSecret(ServiceSecret),
                    ["ServiceClients:Clients:legacy-auth:Permissions:0"] = ProfileReadGrant ? EmployeeProfileBindingClient.ReadPermission : "legacy-contact.messages.create",
                    ["ServiceClients:Clients:legacy-auth:Permissions:1"] = CustomerProfileBindingClient.ReadPermission,
                    ["ServiceClients:Clients:profile-create-test:SecretSha256"] = ServiceClientCredential.HashSecret(ServiceSecret),
                    ["ServiceClients:Clients:profile-create-test:Permissions:0"] = LegacyAccessTokenPermissions.EmployeeIdentitiesCreate,
                };
                if (identityAdministration)
                {
                    settings["ServiceClients:Clients:issuance-test:Permissions:1"] = LegacyAccessTokenPermissions.CustomerIdentitiesReconcileCreate;
                    settings["ServiceClients:Clients:issuance-test:Permissions:2"] = CustomerSelfServicePermissions.Use;
                }
                if (googleReadOnlyBoundary) settings["ServiceClients:Clients:issuance-test:Permissions:3"] = LegacyAccessTokenPermissions.GoogleIdentityExchange;
                if (identityValidation) settings["EmployeeRecovery:Enabled"] = "true";
                configuration.AddInMemoryCollection(settings);
            });
            builder.ConfigureTestServices(services =>
            {
                services.AddHttpClient(LegacyServiceAccessTokenProvider.HttpClientName)
                    .ConfigurePrimaryHttpMessageHandler(() => Server.CreateHandler());
                services.AddHttpClient(EmployeeProfileBindingClient.HttpClientName)
                    .ConfigurePrimaryHttpMessageHandler(() => new ProfileBackend(this));
                services.AddHttpClient(CustomerProfileBindingClient.HttpClientName)
                    .ConfigurePrimaryHttpMessageHandler(() => new CustomerProfileBackend(this));
                // Only Google's external credential validation is controlled. The
                // actual nonce, reader, issuer, session store and runtime DI remain.
                services.RemoveAll<IGoogleIdentityTokenValidator>();
                services.AddSingleton<IGoogleIdentityTokenValidator, GoogleValidator>();
                if (clock is not null)
                {
                    services.RemoveAll<TimeProvider>();
                    services.AddSingleton(clock);
                }
                if (identityValidation)
                    foreach (var descriptor in services.Where(value => value.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService) && value.ImplementationType == typeof(EmployeeRecoveryWorker)).ToArray()) services.Remove(descriptor);
                if (conditionalFaults is not null)
                {
                    services.AddDbContext<CustomerIdentityDbContext>(options => options.AddInterceptors(conditionalFaults));
                    services.AddDbContext<EmployeeIdentityDbContext>(options => options.AddInterceptors(conditionalFaults));
                }
                if (fault is not null) services.AddDbContext<RefreshSessionDbContext>(options => options.AddInterceptors(fault));
            });
        }
        private sealed class ProfileBackend(Factory owner) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                owner.ProfileReads++;
                Assert.Equal(HttpMethod.Get, request.Method);
                Assert.Equal("employee-profile.test", request.RequestUri!.Host);
                Assert.True(request.Headers.CacheControl!.NoCache);
                Assert.True(request.Headers.CacheControl.NoStore);
                var jwt = ReadJwt(request.Headers.Authorization!.Parameter!, owner);
                Assert.Equal("Bearer", request.Headers.Authorization.Scheme);
                Assert.Equal("service:legacy-auth", Assert.Single(jwt.Claims, value => value.Type == "sub").Value);
                Assert.Equal("service", Assert.Single(jwt.Claims, value => value.Type == "identity_kind").Value);
                Assert.Single(jwt.Claims, value => value.Type == "permissions" && value.Value == EmployeeProfileBindingClient.ReadPermission);
                Assert.DoesNotContain(jwt.Claims, value => value.Type is "sid" or "employeeId" or "role");
                var id = int.Parse(request.RequestUri.AbsolutePath["/employees/".Length..], System.Globalization.CultureInfo.InvariantCulture);
                var status = owner.ProfileStatus ?? (owner.Profiles.ContainsKey(id) ? HttpStatusCode.OK : HttpStatusCode.NotFound);
                var body = owner.ProfileBody ?? (owner.Profiles.TryGetValue(id, out var profile)
                    ? JsonSerializer.Serialize(new { profile.Id, profile.Email, profile.PhoneNumber, FirstName = "Controlled", LastName = "Profile" }) : "{}");
                return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
            }
        }
        // Predecessor actor cases control only external profile transport; real reader/token/PG writer remain.
        private sealed class CustomerProfileBackend(Factory owner) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                Assert.Equal(HttpMethod.Get, request.Method);
                Assert.Equal("customer-profile.test", request.RequestUri!.Host);
                var jwt = ReadJwt(request.Headers.Authorization!.Parameter!, owner);
                Assert.Equal("service:legacy-auth", Assert.Single(jwt.Claims, value => value.Type == "sub").Value);
                Assert.Single(jwt.Claims, value => value.Type == "permissions" && value.Value == CustomerProfileBindingClient.ReadPermission);
                var id = int.Parse(request.RequestUri.AbsolutePath["/customers/".Length..], System.Globalization.CultureInfo.InvariantCulture);
                var found = owner.CustomerProfiles.TryGetValue(id, out var profile);
                return Task.FromResult(new HttpResponseMessage(found ? HttpStatusCode.OK : HttpStatusCode.NotFound)
                {
                    Content = new StringContent(found ? JsonSerializer.Serialize(profile) : "{}", Encoding.UTF8, "application/json"),
                });
            }
        }
        private static string? IdentityConnection(LegacyIdentityDbContext context, bool tinyPool) => tinyPool
            ? new NpgsqlConnectionStringBuilder(context.Database.GetConnectionString())
            {
                MaxPoolSize = 2,
                MinPoolSize = 1,
                Timeout = 5,
                ApplicationName = "login-accounting-tiny-pool",
            }.ConnectionString
            : context.Database.GetConnectionString();
        public override async ValueTask DisposeAsync()
        {
            var connections = new List<NpgsqlConnection>();
            await using (var scope = Services.CreateAsyncScope())
            {
                var contexts = new DbContext[]
                {
                    scope.ServiceProvider.GetRequiredService<EmployeeIdentityDbContext>(),
                    scope.ServiceProvider.GetRequiredService<CustomerIdentityDbContext>(),
                    scope.ServiceProvider.GetRequiredService<RefreshSessionDbContext>(),
                };
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
    private sealed class GoogleValidator : IGoogleIdentityTokenValidator
    {
        public Task<GoogleIdentityValidationResult> ValidateAsync(string credential, string application, string expectedNonce, CancellationToken cancellationToken) =>
            Task.FromResult(new GoogleIdentityValidationResult(true, new VerifiedGoogleIdentity("controlled-sub", "issuance@example.com", true, "example.com", null, null), null, null));
    }
    private sealed class Stores(EmployeeIdentityDbContext employees, CustomerIdentityDbContext customers, RefreshSessionDbContext state) : IAsyncDisposable
    {
        public EmployeeIdentityDbContext Employees { get; } = employees;
        public CustomerIdentityDbContext Customers { get; } = customers;
        public RefreshSessionDbContext State { get; } = state;
        public static async Task<Stores> CreateAsync(PostgresFixture postgres)
        {
            var stores = new Stores(await postgres.CreateEmployeeContextAsync(), await postgres.CreateCustomerContextAsync(), await postgres.CreateStateContextAsync());
            var employee = Identity("issuance-employee", "issuance@example.com");
            var customer = Identity("issuance-customer", "customer@example.com");
            stores.Employees.Users.Add(employee);
            stores.Customers.Users.Add(customer);
            await stores.Employees.SaveChangesAsync();
            await stores.Customers.SaveChangesAsync();
            return stores;
        }
        private static LegacyIdentityRow Identity(string id, string email)
        {
            var row = new LegacyIdentityRow
            {
                Id = id,
                UserName = email,
                NormalizedUserName = email.ToUpperInvariant(),
                Email = email,
                NormalizedEmail = email.ToUpperInvariant(),
                EmailConfirmed = true,
                SecurityStamp = "issuance-stamp",
                ConcurrencyStamp = "issuance-concurrency",
                LockoutEnabled = true,
            };
            row.PasswordHash = new Microsoft.AspNetCore.Identity.PasswordHasher<LegacyIdentityRow>().HashPassword(row, "issuance-password");
            return row;
        }
        public async ValueTask DisposeAsync()
        {
            var connections = new[] { (NpgsqlConnection)Employees.Database.GetDbConnection(), (NpgsqlConnection)Customers.Database.GetDbConnection(), (NpgsqlConnection)State.Database.GetDbConnection() };
            await Employees.DisposeAsync();
            await Customers.DisposeAsync();
            await State.DisposeAsync();
            foreach (var connection in connections) NpgsqlConnection.ClearPool(connection);
        }
    }
}
