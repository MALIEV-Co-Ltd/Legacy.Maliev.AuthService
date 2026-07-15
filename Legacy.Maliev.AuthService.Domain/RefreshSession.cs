namespace Legacy.Maliev.AuthService.Domain;

/// <summary>A hashed, rotating refresh session stored outside the legacy identity databases.</summary>
public sealed class RefreshSession
{
    /// <summary>Gets or sets the session identifier.</summary>
    public Guid Id { get; set; }

    /// <summary>Gets or sets the token-family identifier.</summary>
    public Guid FamilyId { get; set; }

    /// <summary>Gets or sets the legacy identity identifier.</summary>
    public required string IdentityId { get; set; }

    /// <summary>Gets or sets the identity database kind.</summary>
    public IdentityKind IdentityKind { get; set; }

    /// <summary>Gets or sets the identity security stamp captured at session creation.</summary>
    public string? SecurityStamp { get; set; }

    /// <summary>Gets or sets the SHA-256 token hash.</summary>
    public required string TokenHash { get; set; }

    /// <summary>Gets or sets creation time.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Gets or sets expiry time.</summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>Gets or sets rotation time.</summary>
    public DateTimeOffset? RotatedAt { get; set; }

    /// <summary>Gets or sets revocation time.</summary>
    public DateTimeOffset? RevokedAt { get; set; }

    /// <summary>Gets or sets the replacement session identifier.</summary>
    public Guid? ReplacedById { get; set; }
}