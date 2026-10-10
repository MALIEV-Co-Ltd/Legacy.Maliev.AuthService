extern alias BffProducer;

using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Legacy.Maliev.AuthService.Tests;
using Legacy.Maliev.Intranet.Auth;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using BffProgram = BffProducer::Program;
using AuthFactory = Legacy.Maliev.AuthService.Tests.EmployeeSessionIssuanceHttpTests.Factory;
using AuthStores = Legacy.Maliev.AuthService.Tests.EmployeeSessionIssuanceHttpTests.Stores;

namespace Legacy.Maliev.EmployeeRememberedCookie.Acceptance;

[CollectionDefinition(Name)]
public sealed class RememberedPostgresCollection : ICollectionFixture<PostgresFixture>
{
    public const string Name = "Protected remembered-cookie paired PostgreSQL";
}

[Collection(RememberedPostgresCollection.Name)]
public sealed class EmployeeRememberedCookieAcceptanceTests(PostgresFixture postgres)
{
    [Theory]
    [InlineData("valid-renewal", true, true)]
    [InlineData("unknown-key", false, false)]
    [InlineData("complete-two-chunks", true, true)]
    [InlineData("complete-five-chunks", true, true)]
    [InlineData("complete-six-chunks", false, false)]
    [InlineData("young", true, false)]
    [InlineData("no-renewal-flag", true, false)]
    [InlineData("wrong-user", false, false)]
    [InlineData("stale-stamp", false, false)]
    [InlineData("tampered", false, false)]
    [InlineData("expired", false, false)]
    [InlineData("wrong-purpose", false, false)]
    [InlineData("wrong-discriminator", false, false)]
    [InlineData("incomplete-chunks", false, false)]
    [InlineData("overlength", false, false)]
    [InlineData("wrong-password", false, false)]
    [InlineData("locked", false, false)]
    [InlineData("unconfirmed", false, false)]
    public async Task ActualBffToAuth_OriginalProtectedCookieControlsIssuanceAndRenewal(string variant, bool allowed, bool renew)
    {
        await using var stores = await AuthStores.CreateAsync(postgres);
        await using var ring = await EmployeeRememberedKeyRingFixture.CreateAsync(postgres);
        // Independent key IDs/certificate; same scheme and discriminator. Synthetic negative only.
        await using var otherRing = variant == "unknown-key" ? await EmployeeRememberedKeyRingFixture.CreateAsync(postgres) : null;
        var row = await stores.Employees.Users.SingleAsync();
        row.UserName = row.Email = "employee@maliev.com";
        row.NormalizedUserName = row.NormalizedEmail = "EMPLOYEE@MALIEV.COM";
        row.TwoFactorEnabled = true;
        row.AccessFailedCount = 2;
        if (variant == "locked") row.LockoutEnd = DateTimeOffset.UtcNow.AddHours(1);
        if (variant == "unconfirmed") row.EmailConfirmed = false;
        await stores.Employees.SaveChangesAsync();
        var customerBefore = JsonSerializer.Serialize(await stores.Customers.Users.AsNoTracking().SingleAsync());
        var employeeBefore = JsonSerializer.Serialize(await stores.Employees.Users.AsNoTracking().SingleAsync());
        var ringBefore = ring.ReadProtectedElements().Select(element => element.ToString()).ToArray();
        Assert.All(ringBefore, xml => Assert.DoesNotContain("<masterKey", xml, StringComparison.Ordinal));
        await using var auth = new AuthFactory(stores, rememberedKeyRing: ring);
        using var authClient = auth.CreateClient(new() { BaseAddress = new Uri("https://auth.test"), HandleCookies = false });
        await using var bff = new PairedBffFactory(auth);
        using var browser = bff.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = true, AllowAutoRedirect = false });
        using var anonymous = await browser.GetAsync("/bff/session");
        var session = await anonymous.Content.ReadFromJsonAsync<JsonElement>();
        var csrf = session.GetProperty("csrfToken").GetString()!;
        var now = DateTimeOffset.UtcNow;
        var ticket = (otherRing ?? ring).Ticket(variant == "wrong-user" ? "other-employee" : row.Id,
            variant == "stale-stamp" ? "previous-stamp" : row.SecurityStamp!, variant, now);
        var cookie = "Identity.TwoFactorRememberMe=" + ticket;
        if (variant is "complete-two-chunks" or "complete-five-chunks" or "complete-six-chunks")
        {
            var count = variant == "complete-two-chunks" ? 2 : variant == "complete-five-chunks" ? 5 : 6;
            Assert.True(ticket.Length > count * count);
            var partLength = (ticket.Length + count - 1) / count;
            cookie = "Identity.TwoFactorRememberMe=chunks-" + count + "; " +
                string.Join("; ", Enumerable.Range(1, count).Select(index =>
                {
                    var offset = (index - 1) * partLength;
                    return "Identity.TwoFactorRememberMeC" + index + "=" +
                        ticket.Substring(offset, Math.Min(partLength, ticket.Length - offset));
                }));
        }
        if (variant == "tampered") cookie = "Identity.TwoFactorRememberMe=invalid_ciphertext";
        if (variant == "incomplete-chunks") cookie = "Identity.TwoFactorRememberMe=chunks-2; Identity.TwoFactorRememberMeC1=partial";
        if (variant == "overlength") cookie = "Identity.TwoFactorRememberMe=" + new string('a', 16_385);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/bff/login")
        {
            Content = JsonContent.Create(new { email = row.Email, password = variant == "wrong-password" ? "wrong-password" : "issuance-password", returnUrl = "/Dashboard" }),
        };
        request.Headers.Add("X-CSRF-TOKEN", csrf);
        request.Headers.Add("Cookie", cookie);
        using var response = await browser.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal(allowed ? HttpStatusCode.OK : HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain("accessToken", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("refreshToken", body, StringComparison.OrdinalIgnoreCase);
        var cookies = response.Headers.TryGetValues("Set-Cookie", out var values) ? SetCookieHeaderValue.ParseList(values.ToList()) : [];
        var renewed = cookies.Where(value => value.Name == IdentityConstants.TwoFactorRememberMeScheme).ToArray();
        Assert.Equal(renew, renewed.Length != 0);
        Assert.Equal(allowed, cookies.Any(value => value.Name == "__Host-Legacy.Maliev.Intranet.Bff"));
        if (renew)
        {
            var header = Assert.Single(renewed);
            Assert.True(header.Secure);
            Assert.True(header.HttpOnly);
            Assert.Equal(Microsoft.Net.Http.Headers.SameSiteMode.Lax, header.SameSite);
            var renewedTicket = Assert.IsType<Microsoft.AspNetCore.Authentication.AuthenticationTicket>(ring.ReadTicket(header.Value.ToString()));
            Assert.Equal(row.Id, renewedTicket.Principal.FindFirstValue(ClaimTypes.Name));
            Assert.Equal(row.SecurityStamp, renewedTicket.Principal.FindFirstValue(new IdentityOptions().ClaimsIdentity.SecurityStampClaimType));
            Assert.True(renewedTicket.Properties.IsPersistent);
            Assert.True(renewedTicket.Properties.IssuedUtc >= now.AddMinutes(-1));
            Assert.True(renewedTicket.Properties.ExpiresUtc > now.AddDays(13));
        }
        var employeeAfter = await stores.Employees.Users.AsNoTracking().SingleAsync();
        Assert.Equal(allowed ? 0 : variant == "wrong-password" ? 3 : 2, employeeAfter.AccessFailedCount);
        Assert.Equal(row.SecurityStamp, employeeAfter.SecurityStamp);
        Assert.Equal(row.PasswordHash, employeeAfter.PasswordHash);
        if (!allowed && variant != "wrong-password") Assert.Equal(employeeBefore, JsonSerializer.Serialize(employeeAfter));
        Assert.Equal(customerBefore, JsonSerializer.Serialize(await stores.Customers.Users.AsNoTracking().SingleAsync()));
        Assert.Equal(allowed ? 1 : 0, await stores.State.RefreshSessions.CountAsync());
        Assert.Empty(await stores.State.IdentityActionTokens.ToListAsync());
        Assert.Equal(ringBefore, ring.ReadProtectedElements().Select(element => element.ToString()).ToArray());
        using var finalSession = await browser.GetAsync("/bff/session");
        var finalPayload = await finalSession.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(allowed, finalPayload.GetProperty("isAuthenticated").GetBoolean());
        if (!allowed)
        {
            var problem = JsonSerializer.Deserialize<JsonElement>(body);
            var requiresTwoFactor = variant is not ("wrong-password" or "locked" or "unconfirmed");
            Assert.Equal(requiresTwoFactor, problem.TryGetProperty("code", out _));
            if (requiresTwoFactor)
                Assert.Equal(Legacy.Maliev.Intranet.Contracts.EmployeeSignInErrorCodes.RequiresTwoFactor,
                    problem.GetProperty("code").GetString());
            Assert.DoesNotContain("Identity.TwoFactorUserId", string.Join("; ", cookies), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task NamedRememberedProvider_DoesNotReplaceGlobalProviderOrCustomerSessionFlow()
    {
        await using var stores = await AuthStores.CreateAsync(postgres);
        await using var ring = await EmployeeRememberedKeyRingFixture.CreateAsync(postgres);
        await using var auth = new AuthFactory(stores, rememberedKeyRing: ring);
        using var client = auth.CreateClient();
        var global = auth.Services.GetRequiredService<IDataProtectionProvider>();
        var named = auth.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(IdentityConstants.TwoFactorRememberMeScheme).DataProtectionProvider;
        Assert.IsType<EphemeralDataProtectionProvider>(global);
        Assert.NotSame(global, named);
        var protector = global.CreateProtector("unrelated-customer-reset-purpose");
        Assert.Equal("unrelated-value", protector.Unprotect(protector.Protect("unrelated-value")));
        using var response = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest((await stores.Customers.Users.SingleAsync()).UserName!, "issuance-password", IdentityKind.Customer));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var session = await stores.State.RefreshSessions.SingleAsync();
        Assert.Equal(IdentityKind.Customer, session.IdentityKind);
    }

    private sealed class PairedBffFactory(AuthFactory auth) : WebApplicationFactory<BffProgram>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            Legacy.Maliev.Intranet.Tests.TestJwtConfiguration.Configure(builder);
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "https://issuance.test", ["Jwt:Audience"] = "issuance-test",
                ["Jwt:PublicKeyPem"] = auth.PublicKey, ["Jwt:KeyId"] = "issuance-test", ["Services:Auth"] = "https://auth.test",
            }));
            builder.ConfigureServices(services => services.AddHttpClient<ILegacyAuthClient, LegacyAuthClient>()
                .ConfigurePrimaryHttpMessageHandler(() => auth.Server.CreateHandler()));
        }
    }
}
