using System.Security.Claims;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class EmployeePasswordTwoFactorPolicyTests(PostgresFixture postgres)
{
    [Theory]
    [InlineData("none")]
    [InlineData("email")]
    [InlineData("phone")]
    [InlineData("authenticator")]
    public async Task OriginalDefaultProviders_ResolveActualProviderEligibilityWithoutWrites(string provider)
    {
        await using var context = await postgres.CreateEmployeeContextAsync();
        var row = Row();
        if (provider == "email") row.Email = "confirmed@example.com";
        if (provider == "phone") { row.PhoneNumber = "0812345678"; row.PhoneNumberConfirmed = true; }
        context.Users.Add(row);
        await context.SaveChangesAsync();
        if (provider == "authenticator")
        {
            await context.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO "AspNetUserTokens" ("UserId", "LoginProvider", "Name", "Value")
                VALUES ({row.Id}, '[AspNetUserStore]', 'AuthenticatorKey', 'synthetic-enrollment-key')
                """);
            // Reapplying pending migrations cannot erase an existing original enrollment key.
            await context.Database.MigrateAsync();
        }
        var before = System.Text.Json.JsonSerializer.Serialize(row);
        await using var services = Services();
        var decision = await services.GetRequiredService<EmployeePasswordTwoFactorPolicy>().EvaluateAsync(row, context, default);
        var expected = provider switch
        {
            "email" => TokenOptions.DefaultEmailProvider,
            "phone" => TokenOptions.DefaultPhoneProvider,
            "authenticator" => TokenOptions.DefaultAuthenticatorProvider,
            _ => null,
        };
        if (expected is null) Assert.Empty(decision.Providers);
        else Assert.Equal([expected], decision.Providers);
        Assert.Equal(expected is not null, decision.RequiresTwoFactor);
        Assert.False(decision.RememberedClient);
        Assert.Equal(before, System.Text.Json.JsonSerializer.Serialize(await context.Users.AsNoTracking().SingleAsync()));
        if (provider == "authenticator")
            Assert.Equal("synthetic-enrollment-key", await context.Database.SqlQueryRaw<string>(
                "SELECT \"Value\" FROM \"AspNetUserTokens\" WHERE \"Name\" = 'AuthenticatorKey'").SingleAsync());
    }

    [Theory]
    [InlineData("matching", true)]
    [InlineData("wrong-user", false)]
    [InlineData("stale-stamp", false)]
    [InlineData("tampered", false)]
    [InlineData("expired", false)]
    public async Task RememberedClient_RequiresAuthenticatedCookieBoundToCurrentEmployee(string variant, bool allowed)
    {
        await using var context = await postgres.CreateEmployeeContextAsync();
        var row = Row(); row.Email = "confirmed@example.com";
        context.Users.Add(row); await context.SaveChangesAsync();
        await using var services = Services();
        var accessor = services.GetRequiredService<IHttpContextAccessor>();
        await using var issueScope = services.CreateAsyncScope();
        var issue = new DefaultHttpContext { RequestServices = issueScope.ServiceProvider };
        issue.Request.Scheme = "https";
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, variant == "wrong-user" ? "another-employee" : row.Id),
            new Claim(new IdentityOptions().ClaimsIdentity.SecurityStampClaimType,
                variant == "stale-stamp" ? "previous-stamp" : row.SecurityStamp!),
        };
        await issue.SignInAsync(IdentityConstants.TwoFactorRememberMeScheme,
            new ClaimsPrincipal(new ClaimsIdentity(claims, IdentityConstants.TwoFactorRememberMeScheme)),
            variant == "expired" ? new AuthenticationProperties { ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(-1) } : null);
        var cookie = Assert.Single(issue.Response.Headers.SetCookie)!.Split(';')[0];
        await using var requestScope = services.CreateAsyncScope();
        var request = new DefaultHttpContext { RequestServices = requestScope.ServiceProvider };
        request.Request.Scheme = "https";
        request.Request.Headers.Cookie = variant == "tampered" ? cookie[..cookie.IndexOf('=')] + "=invalid" : cookie;
        accessor.HttpContext = request;
        try
        {
            var decision = await requestScope.ServiceProvider.GetRequiredService<EmployeePasswordTwoFactorPolicy>().EvaluateAsync(row, context, default);
            Assert.True(decision.EnabledWithProvider);
            Assert.Equal(allowed, decision.RememberedClient);
            Assert.Equal(!allowed, decision.RequiresTwoFactor);
        }
        finally { accessor.HttpContext = null; }
    }

    private static LegacyIdentityRow Row() => new()
    {
        Id = "provider-employee", UserName = "provider@example.com", NormalizedUserName = "PROVIDER@EXAMPLE.COM",
        EmailConfirmed = true, TwoFactorEnabled = true, SecurityStamp = "provider-stamp",
    };

    private static ServiceProvider Services()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
        services.AddHttpContextAccessor();
        services.AddAuthentication().AddCookie(IdentityConstants.TwoFactorRememberMeScheme);
        services.AddScoped<EmployeePasswordTwoFactorPolicy>();
        return services.BuildServiceProvider();
    }
}
