namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Immutable proof committed atomically with an employee recovery effect; also its delivery outbox.</summary>
public sealed class EmployeeRecoveryEffect
{
    /// <summary>The Auth action identifier used as the immutable receipt's primary key.</summary>
    public Guid ActionId { get; set; }
    /// <summary>The SHA-256 hash of the opaque employee action token.</summary>
    public required string TokenSha256 { get; set; }
    /// <summary>The employee email-confirmation or password-reset purpose applied by this receipt.</summary>
    public required string Purpose { get; set; }
    /// <summary>The authenticated service subject bound to the recovery action.</summary>
    public required string OwnerSubject { get; set; }
    /// <summary>The employee identity whose credential state was changed.</summary>
    public required string IdentityId { get; set; }
    /// <summary>The normalized employee email bound to the applied action.</summary>
    public required string NormalizedEmail { get; set; }
    /// <summary>The employee security stamp required before applying the recovery effect.</summary>
    public required string BeforeSecurityStamp { get; set; }
    /// <summary>The employee security stamp committed with the recovery effect.</summary>
    public required string AfterSecurityStamp { get; set; }
    /// <summary>The identity concurrency stamp committed with the recovery effect.</summary>
    public required string AfterConcurrencyStamp { get; set; }
    /// <summary>The salted Identity password hash for payload verification, never a raw password or unsalted digest.</summary>
    public string? PasswordPayloadHash { get; set; }
    /// <summary>The timestamp when the employee identity effect and receipt were committed.</summary>
    public DateTimeOffset AppliedAt { get; set; }
    /// <summary>The timestamp acknowledging Auth finalization, or null while delivery remains pending.</summary>
    public DateTimeOffset? FinalizedAcknowledgedAt { get; set; }
}

/// <summary>Recovery is disabled until the coordinated writer-drain and additive schema rollout are complete.</summary>
public sealed class EmployeeRecoveryOptions
{
    /// <summary>Whether the coordinated writer-drain and additive-schema rollout has enabled employee recovery.</summary>
    public bool Enabled { get; set; }
}

/// <summary>A generic retryable recovery boundary failure without provider or credential details.</summary>
public sealed class EmployeeRecoveryUnavailableException : Exception
{
    /// <summary>Creates a retryable recovery failure with a generic, non-sensitive message.</summary>
    public EmployeeRecoveryUnavailableException() : base("Employee identity action is temporarily unavailable.") { }
}
