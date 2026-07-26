using Google.Apis.Auth;
using Legacy.Maliev.AuthService.Application;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Verifies Google ID-token signatures and audience using Google's certificate set.</summary>
public interface IGoogleIdentityTokenVerifier
{
    /// <summary>Returns claims only after Google signature, issuer, audience and lifetime checks pass.</summary>
    Task<GoogleIdentityTokenClaims> VerifyAsync(
        string credential,
        string audience,
        CancellationToken cancellationToken);
}

/// <summary>Production adapter around the Google.Apis.Auth verifier.</summary>
public sealed class GoogleIdentityTokenVerifier : IGoogleIdentityTokenVerifier
{
    /// <inheritdoc />
    public async Task<GoogleIdentityTokenClaims> VerifyAsync(
        string credential,
        string audience,
        CancellationToken cancellationToken)
    {
        var payload = await GoogleJsonWebSignature.ValidateAsync(
                credential,
                new GoogleJsonWebSignature.ValidationSettings { Audience = [audience] })
            .WaitAsync(cancellationToken);

        return new GoogleIdentityTokenClaims(
            payload.Subject,
            payload.Email,
            payload.EmailVerified,
            payload.Nonce,
            payload.HostedDomain,
            payload.Name,
            payload.Picture);
    }
}
