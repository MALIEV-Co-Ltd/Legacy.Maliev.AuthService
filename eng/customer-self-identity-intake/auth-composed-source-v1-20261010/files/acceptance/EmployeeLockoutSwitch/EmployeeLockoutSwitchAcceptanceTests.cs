using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Tests;
using Microsoft.EntityFrameworkCore;
using AuthFactory = Legacy.Maliev.AuthService.Tests.EmployeeSessionIssuanceHttpTests.Factory;
using AuthStores = Legacy.Maliev.AuthService.Tests.EmployeeSessionIssuanceHttpTests.Stores;

namespace Legacy.Maliev.EmployeeLockoutSwitch.Acceptance;

[CollectionDefinition(Name)]
public sealed class SwitchPostgresCollection : ICollectionFixture<PostgresFixture>
{
    public const string Name = "Isolated lockout compatibility switch PostgreSQL";
}

// Execute this assembly in its own test host; never combine its runtime configuration
// with the ordinary Auth suite or mutate the process-wide switch during a test.
[Collection(SwitchPostgresCollection.Name)]
public sealed class EmployeeLockoutSwitchAcceptanceTests(PostgresFixture postgres)
{
    [Theory]
    [InlineData("correct-password", 0)]
    [InlineData("wrong-password", 3)]
    [InlineData("unknown", 2)]
    [InlineData("locked", 2)]
    [InlineData("unconfirmed", 2)]
    public async Task NormalAuthProgram_EnabledSwitchResetsOnlyVerifiedEligiblePassword(string condition, int expectedCount)
    {
        Assert.True(AppContext.TryGetSwitch(
            "Microsoft.AspNetCore.Identity.CheckPasswordSignInAlwaysResetLockoutOnSuccess", out var enabled) && enabled);
        await using var stores = await AuthStores.CreateAsync(postgres);
        var row = await stores.Employees.Users.SingleAsync();
        row.TwoFactorEnabled = true;
        row.AccessFailedCount = 2;
        if (condition == "locked") row.LockoutEnd = DateTimeOffset.UtcNow.AddHours(1);
        if (condition == "unconfirmed") row.EmailConfirmed = false;
        await stores.Employees.SaveChangesAsync();
        var customerBefore = JsonSerializer.Serialize(await stores.Customers.Users.AsNoTracking().SingleAsync());
        var originalStamp = row.SecurityStamp;
        var originalHash = row.PasswordHash;
        await using var factory = new AuthFactory(stores);
        using var client = factory.CreateClient(new() { HandleCookies = false });
        using var response = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest(
            condition == "unknown" ? "missing@example.com" : row.UserName!,
            condition == "wrong-password" ? "wrong-password" : "issuance-password", IdentityKind.Employee));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>();
        if (condition == "correct-password")
            Assert.Equal("requires_two_factor", problem.GetProperty("code").GetString());
        else
            Assert.False(problem.TryGetProperty("code", out _));
        Assert.False(problem.TryGetProperty("accessToken", out _));
        Assert.False(problem.TryGetProperty("refreshToken", out _));
        var after = await stores.Employees.Users.AsNoTracking().SingleAsync();
        Assert.Equal(expectedCount, after.AccessFailedCount);
        Assert.Equal(originalStamp, after.SecurityStamp);
        Assert.Equal(originalHash, after.PasswordHash);
        Assert.Equal(row.LockoutEnd, after.LockoutEnd);
        Assert.Equal(customerBefore, JsonSerializer.Serialize(await stores.Customers.Users.AsNoTracking().SingleAsync()));
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
        Assert.False(response.Headers.Contains("Set-Cookie"));
    }
}
