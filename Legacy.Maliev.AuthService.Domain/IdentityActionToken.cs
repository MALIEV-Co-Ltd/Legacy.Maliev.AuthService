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
    /// <summary>The employee recovery binding version, or null for actions outside that recovery protocol.</summary>
    public int? RecoveryVersion { get; set; }
    /// <summary>The SHA-256 hash matched against the committed employee recovery receipt.</summary>
    public string? OriginalTokenSha256 { get; set; }
    /// <summary>The authenticated service subject allowed to complete this employee action.</summary>
    public string? OwnerSubject { get; set; }
    /// <summary>The employee email captured at issuance and checked again before applying recovery.</summary>
    public string? BoundNormalizedEmail { get; set; }
    /// <summary>The employee security stamp captured at issuance to reject stale recovery actions.</summary>
    public string? BoundSecurityStamp { get; set; }
    /// <summary>The committed employee receipt identifier recorded during Auth finalization.</summary>
    public Guid? EffectActionId { get; set; }
    /// <summary>The timestamp when Auth finalized the committed employee recovery effect.</summary>
    public DateTimeOffset? FinalizedAt { get; set; }
}
