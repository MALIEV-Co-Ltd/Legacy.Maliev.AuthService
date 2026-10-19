using Legacy.Maliev.AuthService.Domain;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>The original check-only credential request, without login or email-only validation.</summary>
public sealed class LegacyCredentialValidationRequest
{
    /// <summary>Gets or sets the original username, which need not be an email address.</summary>
    public string? Username { get; set; }

    /// <summary>Gets or sets the password without including it in a generated record representation.</summary>
    public string? Password { get; set; }
}

/// <summary>Distinguishes only the outcomes exposed by the original validation endpoints.</summary>
public enum LegacyCredentialValidationOutcome
{
    /// <summary>No identity exists in the route-selected store.</summary>
    UnknownIdentity,
    /// <summary>The identity exists but the password does not match.</summary>
    InvalidPassword,
    /// <summary>The password matches, independently of sign-in eligibility.</summary>
    Valid,
}

/// <summary>Checks passwords with the original Identity rehash side effects and no session issuance.</summary>
public interface ILegacyCredentialValidationService
{
    /// <summary>Checks one fixed identity domain without applying interactive sign-in policy.</summary>
    Task<LegacyCredentialValidationOutcome> ValidateAsync(
        string username, string password, IdentityKind kind, CancellationToken cancellationToken);
}
