using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using AuthFactory = Legacy.Maliev.AuthService.Tests.EmployeeSessionIssuanceHttpTests.Factory;
using AuthStores = Legacy.Maliev.AuthService.Tests.EmployeeSessionIssuanceHttpTests.Stores;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class EmployeeRememberedCustodyHttpTests(PostgresFixture postgres)
{
    [Theory]
    [InlineData("missing-discriminator")]
    [InlineData("missing-connection")]
    [InlineData("missing-certificate")]
    [InlineData("wrong-certificate-password")]
    [InlineData("wrong-certificate")]
    [InlineData("empty-adopted-ring")]
    public async Task NormalProgram_UnavailableCustodyCannotAuthenticateOriginalProtectedCookie(string condition)
    {
        await using var stores = await AuthStores.CreateAsync(postgres);
        await using var original = await EmployeeRememberedKeyRingFixture.CreateAsync(postgres);
        await using var unrelated = await EmployeeRememberedKeyRingFixture.CreateAsync(postgres, seedKey: false);
        var row = await stores.Employees.Users.SingleAsync();
        row.TwoFactorEnabled = true;
        row.AccessFailedCount = 2;
        await stores.Employees.SaveChangesAsync();
        var employeeBefore = JsonSerializer.Serialize(await stores.Employees.Users.AsNoTracking().SingleAsync());
        var customerBefore = JsonSerializer.Serialize(await stores.Customers.Users.AsNoTracking().SingleAsync());
        var keysBefore = original.ReadProtectedElements().Select(element => element.ToString()).ToArray();
        var changes = new Dictionary<string, string?>();
        switch (condition)
        {
            case "missing-discriminator": changes["EmployeeRememberedClient:OriginalApplicationDiscriminator"] = null; break;
            case "missing-connection": changes["ConnectionStrings:employee-data-protection"] = null; break;
            case "missing-certificate": changes["EmployeeRememberedClient:CertificatePath"] = null; break;
            case "wrong-certificate-password": changes["EmployeeRememberedClient:CertificatePassword"] = "incorrect-fixture-password"; break;
            case "wrong-certificate": changes["EmployeeRememberedClient:CertificatePath"] = unrelated.Settings["EmployeeRememberedClient:CertificatePath"]; break;
            case "empty-adopted-ring": changes["ConnectionStrings:employee-data-protection"] = unrelated.Settings["ConnectionStrings:employee-data-protection"]; break;
            default: throw new ArgumentOutOfRangeException(nameof(condition));
        }
        await using var factory = new AuthFactory(stores, rememberedKeyRing: original);
        await using var configured = factory.WithWebHostBuilder(builder => builder.ConfigureAppConfiguration(
            (_, configuration) => configuration.AddInMemoryCollection(changes)));
        using var client = configured.CreateClient(new() { BaseAddress = new Uri("https://auth.test"), HandleCookies = false });
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/v1/login")
        {
            Content = JsonContent.Create(new LoginRequest(row.UserName!, "issuance-password", IdentityKind.Employee)),
        };
        request.Headers.Add("Cookie", "Identity.TwoFactorRememberMe=" + original.Ticket(row.Id, row.SecurityStamp!, "valid-renewal", DateTimeOffset.UtcNow));
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("requires_two_factor", problem.GetProperty("code").GetString());
        Assert.False(problem.TryGetProperty("accessToken", out _));
        Assert.False(problem.TryGetProperty("refreshToken", out _));
        Assert.False(response.Headers.Contains("Set-Cookie"));
        Assert.Equal(employeeBefore, JsonSerializer.Serialize(await stores.Employees.Users.AsNoTracking().SingleAsync()));
        Assert.Equal(customerBefore, JsonSerializer.Serialize(await stores.Customers.Users.AsNoTracking().SingleAsync()));
        Assert.Empty(await stores.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Empty(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync());
        Assert.Equal(keysBefore, original.ReadProtectedElements().Select(element => element.ToString()).ToArray());
    }
}
