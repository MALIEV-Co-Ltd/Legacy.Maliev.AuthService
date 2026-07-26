namespace Legacy.Maliev.AuthService.Domain;

/// <summary>One-time Google Identity Services nonce bound to the trusted caller and application.</summary>
public sealed class GoogleIdentityNonce
{
    /// <summary>Gets or sets the nonce record identifier.</summary>
    public Guid Id { get; set; }

    /// <summary>Gets or sets the SHA-256 hash of the browser nonce.</summary>
    public required string NonceHash { get; set; }

    /// <summary>Gets or sets the trusted service caller that requested the nonce.</summary>
    public required string ServiceName { get; set; }

    /// <summary>Gets or sets the configured application selector.</summary>
    public required string Application { get; set; }

    /// <summary>Gets or sets the creation timestamp.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Gets or sets the expiry timestamp.</summary>
    public DateTimeOffset ExpiresAt { get; set; }
}
