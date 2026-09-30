namespace Legacy.Maliev.AuthService.Domain;

/// <summary>Hashed, single-use customer identity action stored outside the legacy identity database.</summary>
public sealed class IdentityActionToken
{
    /// <summary>Token row identifier.</summary>
    public Guid Id { get; set; }
    /// <summary>Legacy identity identifier.</summary>
    public required string IdentityId { get; set; }
    /// <summary>SHA-256 hash of the opaque token.</summary>
    public required string TokenHash { get; set; }
    /// <summary>Bound action purpose.</summary>
    public required string Purpose { get; set; }
    /// <summary>Email address bound to the action when the action targets an email.</summary>
    public string? TargetEmail { get; set; }
    /// <summary>Creation timestamp.</summary>
    public DateTimeOffset CreatedAt { get; set; }
    /// <summary>Expiration timestamp.</summary>
    public DateTimeOffset ExpiresAt { get; set; }
    /// <summary>Consumption timestamp.</summary>
    public DateTimeOffset? ConsumedAt { get; set; }
    public int? RecoveryVersion { get; set; }
    public string? OriginalTokenSha256 { get; set; }
    public string? OwnerSubject { get; set; }
    public string? BoundNormalizedEmail { get; set; }
    public string? BoundSecurityStamp { get; set; }
    public Guid? EffectActionId { get; set; }
    public DateTimeOffset? FinalizedAt { get; set; }
}
