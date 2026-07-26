using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class GoogleIdentityTokenValidatorTests
{
    [Fact]
    public async Task Validate_RequiresConfiguredAudienceAndHostedDomain()
    {
        var validator = CreateValidator(new GoogleIdentityTokenClaims(
            "subject", "employee@maliev.com", true, "nonce", "maliev.com", "Employee", null), configured: false);

        var result = await validator.ValidateAsync("secret-token", "intranet", "nonce", default);

        Assert.False(result.Succeeded);
        Assert.Equal("service_unavailable", result.ErrorCode);
    }

    [Fact]
    public async Task Validate_AcceptsVerifiedEmployeeWithMatchingAudienceAndNonce()
    {
        var validator = CreateValidator(new GoogleIdentityTokenClaims(
            "subject", "employee@maliev.com", true, "nonce", "maliev.com", "Employee", null));

        var result = await validator.ValidateAsync("secret-token", "intranet", "nonce", default);

        Assert.True(result.Succeeded);
        Assert.Equal("employee@maliev.com", result.Identity?.Email);
        Assert.Equal("subject", result.Identity?.Subject);
    }

    [Theory]
    [InlineData(false, "maliev.com", "invalid_google_credential")]
    [InlineData(true, "other.example", "invalid_domain")]
    [InlineData(true, "maliev.com.evil.example", "invalid_domain")]
    public async Task Validate_RejectsUnverifiedOrNonAllowlistedIdentity(
        bool emailVerified,
        string hostedDomain,
        string errorCode)
    {
        var validator = CreateValidator(new GoogleIdentityTokenClaims(
            "subject", "employee@maliev.com", emailVerified, "nonce", hostedDomain, "Employee", null));

        var result = await validator.ValidateAsync("credential", "intranet", "nonce", default);

        Assert.False(result.Succeeded);
        Assert.Equal(errorCode, result.ErrorCode);
    }

    [Fact]
    public async Task Validate_RejectsNonceMismatchWithoutLeakingClaims()
    {
        var validator = CreateValidator(new GoogleIdentityTokenClaims(
            "subject", "employee@maliev.com", true, "different", "maliev.com", "Employee", null));

        var result = await validator.ValidateAsync("credential", "intranet", "nonce", default);

        Assert.False(result.Succeeded);
        Assert.Equal("invalid_google_credential", result.ErrorCode);
        Assert.Null(result.Identity);
    }

    [Fact]
    public async Task Validate_MapsVerifierFormatFailuresToGenericInvalidCredential()
    {
        var validator = CreateValidator(new FormatException());

        var result = await validator.ValidateAsync("credential", "intranet", "nonce", default);

        Assert.False(result.Succeeded);
        Assert.Equal("invalid_google_credential", result.ErrorCode);
        Assert.DoesNotContain("secret-token", result.ErrorDescription ?? string.Empty, StringComparison.Ordinal);
    }

    private static GoogleIdentityTokenValidator CreateValidator(object verifierResult, bool configured = true)
    {
        var settings = configured
            ? new Dictionary<string, string?>
            {
                ["GoogleIdentity:Employee:Audiences:intranet"] = "employee-client-id",
                ["GoogleIdentity:Employee:HostedDomain"] = "maliev.com",
            }
            : [];
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        return new(configuration, NullLogger<GoogleIdentityTokenValidator>.Instance, new StubVerifier(verifierResult));
    }

    private sealed class StubVerifier(object result) : IGoogleIdentityTokenVerifier
    {
        public Task<GoogleIdentityTokenClaims> VerifyAsync(
            string credential, string audience, CancellationToken cancellationToken)
        {
            if (result is Exception exception)
            {
                return Task.FromException<GoogleIdentityTokenClaims>(exception);
            }

            return Task.FromResult((GoogleIdentityTokenClaims)result);
        }
    }
}
