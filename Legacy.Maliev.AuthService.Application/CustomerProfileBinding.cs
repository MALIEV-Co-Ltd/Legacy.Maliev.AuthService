namespace Legacy.Maliev.AuthService.Application;

/// <summary>Authoritative contact fields from the selected persisted customer profile.</summary>
public sealed record CustomerProfileBinding(int Id, string Email, string? Telephone, string? Fax, string? Mobile);

/// <summary>Result of the separately authorized fixed Customer read.</summary>
public enum CustomerProfileBindingStatus { Verified, Missing, Unavailable }

/// <summary>Verified profile or an unavailable authority without private details.</summary>
public sealed record CustomerProfileBindingResult(CustomerProfileBindingStatus Status, CustomerProfileBinding? Profile = null);

/// <summary>Reads a selected profile without substituting incoming caller fields or authority.</summary>
public interface ICustomerProfileBindingClient
{
    /// <summary>Reads the exact selected profile through its existing resource route.</summary>
    Task<CustomerProfileBindingResult> ReadAsync(int databaseId, CancellationToken cancellationToken);
}

/// <summary>Signals a generic profile-admission failure before a new identity effect.</summary>
public sealed class CustomerProfileBindingException(CustomerProfileBindingStatus status) : Exception("Customer profile authority unavailable")
{
    /// <summary>Distinguishes a verified missing profile from unavailable authority.</summary>
    public CustomerProfileBindingStatus Status { get; } = status;
}
