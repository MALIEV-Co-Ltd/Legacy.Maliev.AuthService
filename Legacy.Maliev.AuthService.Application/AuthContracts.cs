using Legacy.Maliev.AuthService.Domain;
using System.ComponentModel.DataAnnotations;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>Credentials submitted to the modern legacy login boundary.</summary>
public sealed record LoginRequest(
    [Required, EmailAddress, StringLength(320)] string UserName,
    [Required, StringLength(1024, MinimumLength = 1)] string Password,
    [EnumDataType(typeof(IdentityKind))] IdentityKind IdentityKind);

/// <summary>A single-use refresh token request.</summary>
public sealed record RefreshRequest([Required, StringLength(256, MinimumLength = 32)] string RefreshToken);

/// <summary>A refresh-session revocation request.</summary>
public sealed record RevokeRequest([Required, StringLength(256, MinimumLength = 32)] string RefreshToken);

/// <summary>A short-lived access token and rotating refresh token.</summary>
public sealed record TokenResponse(
    string AccessToken,
    string RefreshToken,
    string TokenType,
    int ExpiresIn,
    DateTimeOffset RefreshExpiresAt);

/// <summary>Result returned without revealing which credential component failed.</summary>
public sealed record AuthenticationResult(bool Succeeded, TokenResponse? Tokens)
{
    /// <summary>The BFF-only action required before authentication can succeed, if any.</summary>
    public AuthenticationRequiredAction? RequiredAction { get; init; }

    /// <summary>Creates a generic failure without tokens or an account-specific reason.</summary>
    /// <returns>An unsuccessful result without a required action.</returns>
    public static AuthenticationResult Failed() => new(false, null);

    /// <summary>Creates an unsuccessful result carrying an opaque action for the trusted BFF.</summary>
    /// <param name="action">The action required before a session can be issued.</param>
    /// <param name="token">The opaque, single-use token for that action.</param>
    /// <returns>A result with the required action and no session tokens.</returns>
    public static AuthenticationResult ActionRequired(string action, string token) =>
        new(false, null) { RequiredAction = new(action, token) };

    /// <summary>Creates a successful result.</summary>
    public static AuthenticationResult Success(TokenResponse tokens) => new(true, tokens);
}

/// <summary>An opaque BFF-only action required before a customer session may be created.</summary>
public sealed record AuthenticationRequiredAction(string Action, string Token);
