using System.ComponentModel.DataAnnotations;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>Credentials presented by an approved legacy service.</summary>
public sealed record ServiceLoginRequest(
    [Required, StringLength(128)] string ClientId,
    [Required, StringLength(1024, MinimumLength = 16)] string ClientSecret);

/// <summary>A short-lived service access token. Machine identities never receive refresh tokens.</summary>
public sealed record ServiceTokenResponse(string AccessToken, string TokenType, int ExpiresIn);

/// <summary>Non-enumerating machine authentication result.</summary>
public sealed record ServiceAuthenticationResult(bool Succeeded, ServiceTokenResponse? Token)
{
    /// <summary>Creates a generic failure.</summary>
    public static ServiceAuthenticationResult Failed() => new(false, null);
    /// <summary>Creates a successful result.</summary>
    public static ServiceAuthenticationResult Success(IssuedAccessToken token) => new(true, new(token.Value, "Bearer", token.ExpiresInSeconds));
}
