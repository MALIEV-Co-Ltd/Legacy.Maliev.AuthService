using Legacy.Maliev.AuthService.Domain;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>Coordinates credential validation, short-lived access tokens and rotating refresh sessions.</summary>
public sealed class AuthenticationService(
    ILegacyCredentialValidator credentialValidator,
    ILegacyIdentityReader identityReader,
    IAccessTokenIssuer accessTokenIssuer,
    IRefreshSessionStore refreshSessionStore,
    TimeProvider timeProvider)
{
    private static readonly TimeSpan RefreshLifetime = TimeSpan.FromDays(14);

    /// <summary>Authenticates a legacy account without modifying its identity database.</summary>
    public async Task<AuthenticationResult> LoginAsync(LoginRequest request, CancellationToken cancellationToken)
    {
        var identity = await credentialValidator.ValidateAsync(
            request.UserName.Trim(), request.Password, request.IdentityKind, cancellationToken);

        if (identity is null)
        {
            return AuthenticationResult.Failed();
        }

        var now = timeProvider.GetUtcNow();
        var rawRefreshToken = CreateRefreshToken();
        var session = CreateSession(identity, Hash(rawRefreshToken), Guid.NewGuid(), now);
        await refreshSessionStore.CreateAsync(session, cancellationToken);

        return AuthenticationResult.Success(CreateTokenResponse(identity, rawRefreshToken, session.ExpiresAt, now));
    }

    /// <summary>Rotates a valid refresh token exactly once.</summary>
    public async Task<AuthenticationResult> RefreshAsync(RefreshRequest request, CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var replacementToken = CreateRefreshToken();
        var replacement = new RefreshSession
        {
            Id = Guid.NewGuid(),
            FamilyId = Guid.Empty,
            IdentityId = string.Empty,
            IdentityKind = IdentityKind.Customer,
            TokenHash = Hash(replacementToken),
            CreatedAt = now,
            ExpiresAt = now.Add(RefreshLifetime),
        };

        var rotation = await refreshSessionStore.RotateAsync(Hash(request.RefreshToken), replacement, cancellationToken);
        if (rotation.Status != RefreshRotationStatus.Succeeded ||
            rotation.IdentityId is null ||
            rotation.IdentityKind is null)
        {
            return AuthenticationResult.Failed();
        }

        var identity = await identityReader.FindActiveAsync(
            rotation.IdentityId, rotation.IdentityKind.Value, cancellationToken);
        if (identity is null || !string.Equals(identity.SecurityStamp, rotation.SecurityStamp, StringComparison.Ordinal))
        {
            await refreshSessionStore.RevokeFamilyAsync(replacement.TokenHash, now, cancellationToken);
            return AuthenticationResult.Failed();
        }

        return AuthenticationResult.Success(
            CreateTokenResponse(identity, replacementToken, replacement.ExpiresAt, now));
    }

    /// <summary>Revokes the complete refresh-token family without revealing token validity.</summary>
    public Task RevokeAsync(RevokeRequest request, CancellationToken cancellationToken) =>
        refreshSessionStore.RevokeFamilyAsync(Hash(request.RefreshToken), timeProvider.GetUtcNow(), cancellationToken);

    private TokenResponse CreateTokenResponse(
        LegacyIdentity identity,
        string refreshToken,
        DateTimeOffset refreshExpiresAt,
        DateTimeOffset now)
    {
        var accessToken = accessTokenIssuer.Issue(identity, now);
        return new TokenResponse(accessToken.Value, refreshToken, "Bearer", accessToken.ExpiresInSeconds, refreshExpiresAt);
    }

    private static RefreshSession CreateSession(
        LegacyIdentity identity,
        string tokenHash,
        Guid familyId,
        DateTimeOffset now) => new()
        {
            Id = Guid.NewGuid(),
            FamilyId = familyId,
            IdentityId = identity.Id,
            IdentityKind = identity.Kind,
            SecurityStamp = identity.SecurityStamp,
            TokenHash = tokenHash,
            CreatedAt = now,
            ExpiresAt = now.Add(RefreshLifetime),
        };

    private static string CreateRefreshToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

    internal static string Hash(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}