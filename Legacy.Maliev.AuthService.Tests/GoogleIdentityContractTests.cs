using Legacy.Maliev.AuthService.Api.Controllers;
using Legacy.Maliev.AuthService.Application;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Reflection;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>
/// Guards the reflected Google employee-authentication routes and their dedicated least-privilege permission.
/// </summary>
public sealed class GoogleIdentityContractTests
{
    /// <summary>
    /// Checks that the authentication controller exposes the nonce and exchange POST routes with the dedicated Google grant.
    /// </summary>
    [Fact]
    public void AuthenticationBoundary_ExposesEmployeeGoogleNonceAndExchangeEndpoints()
    {
        var methods = typeof(AuthenticationController)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .Where(method => method.DeclaringType == typeof(AuthenticationController))
            .ToArray();

        var nonce = Assert.Single(methods, method => method.Name == "IssueEmployeeGoogleNonce");
        var exchange = Assert.Single(methods, method => method.Name == "ExchangeEmployeeGoogleToken");

        Assert.Equal("exchange/google/nonce", nonce.GetCustomAttribute<HttpPostAttribute>()?.Template);
        Assert.Equal("exchange/google", exchange.GetCustomAttribute<HttpPostAttribute>()?.Template);
        Assert.Equal(
            LegacyAccessTokenPermissions.GoogleIdentityExchange,
            nonce.GetCustomAttribute<RequirePermissionAttribute>()?.Permission);
        Assert.Equal(
            LegacyAccessTokenPermissions.GoogleIdentityExchange,
            exchange.GetCustomAttribute<RequirePermissionAttribute>()?.Permission);
    }

    /// <summary>
    /// Checks that the Google exchange permission retains its exact public least-privilege identifier.
    /// </summary>
    [Fact]
    public void GoogleIdentityExchange_UsesDedicatedLeastPrivilegeServicePermission()
    {
        var permission = typeof(LegacyAccessTokenPermissions)
            .GetField("GoogleIdentityExchange", BindingFlags.Public | BindingFlags.Static);

        Assert.NotNull(permission);
        var value = Assert.IsType<string>(permission!.GetValue(null));
        Assert.Equal("legacy-auth.google-identity.exchange", value);
    }
}
