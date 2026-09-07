namespace Legacy.Maliev.AuthService.Application;

/// <summary>Minimal current contact details belonging to the authenticated customer.</summary>
public sealed record CustomerSelfIdentityResponse(int CustomerId, string? Email, string? Mobile);

/// <summary>Outcome of resolving the signed customer's current identity linkage.</summary>
public enum CustomerSelfIdentityStatus
{
    /// <summary>The identity is active and matches its signed customer identifier.</summary>
    Found,
    /// <summary>The signed identity no longer exists.</summary>
    Missing,
    /// <summary>The identity is inactive or its customer linkage no longer matches.</summary>
    Forbidden,
}

/// <summary>Internal result without disclosing inactive or mismatched identity details.</summary>
public sealed record CustomerSelfIdentityResult(CustomerSelfIdentityStatus Status, CustomerSelfIdentityResponse? Identity = null);

/// <summary>Reads only the identity selected by the validated customer principal.</summary>
public interface ICustomerSelfIdentityReader
{
    /// <summary>Resolves current contact fields using the signed subject and customer linkage.</summary>
    Task<CustomerSelfIdentityResult> GetAsync(string identityId, int expectedCustomerId, CancellationToken cancellationToken);
}
