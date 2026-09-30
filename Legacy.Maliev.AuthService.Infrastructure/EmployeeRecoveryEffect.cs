namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Immutable proof committed atomically with an employee recovery effect; also its delivery outbox.</summary>
public sealed class EmployeeRecoveryEffect
{
    public Guid ActionId { get; set; }
    public required string TokenSha256 { get; set; }
    public required string Purpose { get; set; }
    public required string OwnerSubject { get; set; }
    public required string IdentityId { get; set; }
    public required string NormalizedEmail { get; set; }
    public required string BeforeSecurityStamp { get; set; }
    public required string AfterSecurityStamp { get; set; }
    public required string AfterConcurrencyStamp { get; set; }
    /// <summary>The salted Identity password hash for payload verification, never a raw password or unsalted digest.</summary>
    public string? PasswordPayloadHash { get; set; }
    public DateTimeOffset AppliedAt { get; set; }
    public DateTimeOffset? FinalizedAcknowledgedAt { get; set; }
}

/// <summary>Recovery is disabled until the coordinated writer-drain and additive schema rollout are complete.</summary>
public sealed class EmployeeRecoveryOptions
{
    public bool Enabled { get; set; }
}

/// <summary>A generic retryable recovery boundary failure without provider or credential details.</summary>
public sealed class EmployeeRecoveryUnavailableException : Exception
{
    public EmployeeRecoveryUnavailableException() : base("Employee identity action is temporarily unavailable.") { }
}
