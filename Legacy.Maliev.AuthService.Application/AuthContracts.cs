using Legacy.Maliev.AuthService.Domain;
using System.ComponentModel.DataAnnotations;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>Credentials submitted to the modern legacy login boundary.</summary>
public sealed record LoginRequest(
    [property: Required, EmailAddress, StringLength(320)] string UserName,
    [property: Required, StringLength(1024, MinimumLength = 1)] string Password,
    IdentityKind IdentityKind);

/// <summary>A single-use refresh token request.</summary>
public sealed record RefreshRequest([property: Required, StringLength(256, MinimumLength = 32)] string RefreshToken);

/// <summary>A refresh-session revocation request.</summary>
public sealed record RevokeRequest([property: Required, StringLength(256, MinimumLength = 32)] string RefreshToken);

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
    /// <summary>Creates a generic authentication failure.</summary>
    public static AuthenticationResult Failed() => new(false, null);

    /// <summary>Creates a successful result.</summary>
    public static AuthenticationResult Success(TokenResponse tokens) => new(true, tokens);
}