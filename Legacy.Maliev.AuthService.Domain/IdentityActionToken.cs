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
    /// <summary>Creation timestamp.</summary>
    public DateTimeOffset CreatedAt { get; set; }
    /// <summary>Expiration timestamp.</summary>
    public DateTimeOffset ExpiresAt { get; set; }
    /// <summary>Consumption timestamp.</summary>
    public DateTimeOffset? ConsumedAt { get; set; }
}