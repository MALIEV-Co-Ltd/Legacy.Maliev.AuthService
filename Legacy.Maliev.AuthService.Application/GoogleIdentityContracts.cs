using Legacy.Maliev.AuthService.Domain;
using System.ComponentModel.DataAnnotations;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>Requests a one-time nonce for a trusted Google Identity Services flow.</summary>
public sealed record GoogleIdentityNonceRequest(
    [Required, RegularExpression("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")] string Application);

/// <summary>Exchanges a Google credential for an employee legacy session.</summary>
public sealed record GoogleExchangeRequest(
    [Required, StringLength(8192, MinimumLength = 1)] string Credential,
    [Required, RegularExpression("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")] string Application,
    [Required, StringLength(256, MinimumLength = 32)] string Nonce);

/// <summary>Browser-safe one-time nonce response.</summary>
public sealed record GoogleIdentityNonceResponse(string Nonce, DateTimeOffset ExpiresAtUtc);

/// <summary>Verified claims from a Google ID token.</summary>
public sealed record VerifiedGoogleIdentity(
    string Subject,
    string Email,
    bool EmailVerified,
    string? HostedDomain,
    string? FullName,
    string? ProfileImageUrl);

/// <summary>Stable Google credential validation outcome.</summary>
public sealed record GoogleIdentityValidationResult(
    bool Succeeded,
    VerifiedGoogleIdentity? Identity,
    string? ErrorCode,
    string? ErrorDescription)
{
    /// <summary>Creates an opaque invalid-credential failure.</summary>
    public static GoogleIdentityValidationResult Invalid() => new(
        false,
        null,
        "invalid_google_credential",
        "Google credential is invalid or expired");
}

/// <summary>Signature-verified claims returned by the Google token verifier.</summary>
public sealed record GoogleIdentityTokenClaims(
    string Subject,
    string Email,
    bool EmailVerified,
    string? Nonce,
    string? HostedDomain,
    string? FullName,
    string? ProfileImageUrl);

/// <summary>Issues and atomically consumes Google exchange nonces.</summary>
public interface IGoogleIdentityNonceService
{
    /// <summary>Issues a nonce bound to a trusted service and application.</summary>
    Task<(string Nonce, DateTimeOffset ExpiresAtUtc)> IssueAsync(
        string serviceName,
        string application,
        CancellationToken cancellationToken);

    /// <summary>Consumes a matching, non-expired nonce exactly once.</summary>
    Task<bool> ConsumeAsync(
        string nonce,
        string serviceName,
        string application,
        CancellationToken cancellationToken);
}

/// <summary>Validates raw Google ID tokens at the AuthService trust boundary.</summary>
public interface IGoogleIdentityTokenValidator
{
    /// <summary>Validates signature, audience, issuer, expiry, nonce, and employee domain.</summary>
    Task<GoogleIdentityValidationResult> ValidateAsync(
        string credential,
        string application,
        string expectedNonce,
        CancellationToken cancellationToken);
}

/// <summary>Finds an active employee identity by the verified Google email.</summary>
public interface IGoogleEmployeeIdentityReader
{
    /// <summary>Returns an active employee identity or null without account enumeration detail.</summary>
    Task<LegacyIdentity?> FindActiveEmployeeByEmailAsync(
        string email,
        CancellationToken cancellationToken);
}

/// <summary>Outcome of a Google employee exchange.</summary>
public sealed record GoogleExchangeResult(bool Succeeded, TokenResponse? Tokens, string? ErrorCode)
{
    /// <summary>Creates an opaque exchange failure.</summary>
    public static GoogleExchangeResult Failed(string code) => new(false, null, code);
}
