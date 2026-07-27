using Google.Apis.Auth;
using Legacy.Maliev.AuthService.Application;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Validates Google ID tokens with an explicit audience and employee domain allowlist.</summary>
public sealed class GoogleIdentityTokenValidator(
    IConfiguration configuration,
    ILogger<GoogleIdentityTokenValidator> logger,
    IGoogleIdentityTokenVerifier verifier) : IGoogleIdentityTokenValidator
{
    /// <inheritdoc />
    public async Task<GoogleIdentityValidationResult> ValidateAsync(
        string credential,
        string application,
        string expectedNonce,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(credential) ||
            string.IsNullOrWhiteSpace(application) ||
            string.IsNullOrWhiteSpace(expectedNonce))
        {
            return GoogleIdentityValidationResult.Invalid();
        }

        var audience = ResolveAudience(application);
        var hostedDomain = configuration["GoogleIdentity:Employee:HostedDomain"]?.Trim();
        if (string.IsNullOrWhiteSpace(audience) || string.IsNullOrWhiteSpace(hostedDomain))
        {
            logger.LogError("Google employee identity validation is not configured.");
            return new(false, null, "service_unavailable", "Google sign-in is not configured");
        }

        GoogleIdentityTokenClaims payload;
        try
        {
            payload = await verifier.VerifyAsync(credential, audience, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (HttpRequestException ex)
        {
            logger.LogError(ex, "Google certificate retrieval failed during employee sign-in.");
            return new(false, null, "service_unavailable", "Google sign-in validation is temporarily unavailable");
        }
        catch (Exception ex) when (ex is InvalidJwtException or FormatException or ArgumentException)
        {
            logger.LogWarning("Google employee credential validation failed with {FailureType}.", ex.GetType().Name);
            return GoogleIdentityValidationResult.Invalid();
        }

        if (string.IsNullOrWhiteSpace(payload.Subject) ||
            string.IsNullOrWhiteSpace(payload.Email) ||
            !payload.EmailVerified ||
            !NonceMatches(expectedNonce, payload.Nonce))
        {
            return GoogleIdentityValidationResult.Invalid();
        }

        if (!string.Equals(payload.HostedDomain, hostedDomain, StringComparison.OrdinalIgnoreCase) ||
            !payload.Email.EndsWith($"@{hostedDomain}", StringComparison.OrdinalIgnoreCase))
        {
            return new(false, null, "invalid_domain", $"Only @{hostedDomain} Google Workspace accounts are allowed");
        }

        return new(
            true,
            new VerifiedGoogleIdentity(
                payload.Subject,
                payload.Email.Trim(),
                payload.EmailVerified,
                payload.HostedDomain,
                payload.FullName,
                payload.ProfileImageUrl),
            null,
            null);
    }

    private string? ResolveAudience(string application) =>
        configuration[$"GoogleIdentity:Employee:Audiences:{application.Trim().ToLowerInvariant()}"]?.Trim();

    private static bool NonceMatches(string expected, string? actual)
    {
        if (string.IsNullOrWhiteSpace(actual)) return false;
        var expectedHash = SHA256.HashData(Encoding.UTF8.GetBytes(expected));
        var actualHash = SHA256.HashData(Encoding.UTF8.GetBytes(actual));
        return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash);
    }
}
