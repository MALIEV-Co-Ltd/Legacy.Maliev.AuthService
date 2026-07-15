using Legacy.Maliev.AuthService.Domain;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>Validates credentials against read-only projections of the legacy identity tables.</summary>
public interface ILegacyCredentialValidator
{
    /// <summary>Returns a validated identity or null using a constant public failure contract.</summary>
    Task<LegacyIdentity?> ValidateAsync(string userName, string password, IdentityKind kind, CancellationToken cancellationToken);
}

/// <summary>Reads an identity after refresh rotation so current security state is rechecked.</summary>
public interface ILegacyIdentityReader
{
    /// <summary>Finds a non-locked identity by its legacy identifier and database kind.</summary>
    Task<LegacyIdentity?> FindActiveAsync(string identityId, IdentityKind kind, CancellationToken cancellationToken);
}

/// <summary>Issues asymmetric short-lived access tokens.</summary>
public interface IAccessTokenIssuer
{
    /// <summary>Issues an access token for a validated identity.</summary>
    IssuedAccessToken Issue(LegacyIdentity identity, DateTimeOffset now);
}

/// <summary>Issues least-privilege tokens for configured machine identities.</summary>
public interface IServiceAccessTokenIssuer
{
    /// <summary>Issues a short-lived service token containing only the configured permissions.</summary>
    IssuedAccessToken IssueService(string clientId, IReadOnlyList<string> permissions, DateTimeOffset now);
}

/// <summary>An issued access token and its lifetime.</summary>
public sealed record IssuedAccessToken(string Value, int ExpiresInSeconds);

/// <summary>Persists only hashes of rotating refresh tokens.</summary>
public interface IRefreshSessionStore
{
    /// <summary>Creates the first session in a token family.</summary>
    Task CreateAsync(RefreshSession session, CancellationToken cancellationToken);

    /// <summary>Atomically consumes a session and creates its replacement.</summary>
    Task<RefreshRotationResult> RotateAsync(string presentedHash, RefreshSession replacement, CancellationToken cancellationToken);

    /// <summary>Revokes the complete token family containing the supplied token.</summary>
    Task RevokeFamilyAsync(string tokenHash, DateTimeOffset now, CancellationToken cancellationToken);
}

/// <summary>Outcome of atomic refresh-token rotation.</summary>
public enum RefreshRotationStatus
{
    /// <summary>The token was active and its replacement was stored.</summary>
    Succeeded,

    /// <summary>The token was unknown, expired or revoked.</summary>
    Invalid,

    /// <summary>A previously consumed token was replayed and its family was revoked.</summary>
    Reused,
}

/// <summary>Refresh rotation outcome with the authenticated identity when successful.</summary>
public sealed record RefreshRotationResult(
    RefreshRotationStatus Status,
    string? IdentityId,
    IdentityKind? IdentityKind,
    string? SecurityStamp);