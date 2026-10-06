namespace Legacy.Maliev.AuthService.Application;

/// <summary>Selected persisted employee fields used when creating its identity.</summary>
public sealed record EmployeeProfileBinding(int Id, string Email, string? PhoneNumber);

/// <summary>Outcome of an authoritative employee profile read.</summary>
public enum EmployeeProfileBindingStatus
{
    /// <summary>The selected profile was verified.</summary>
    Verified,
    /// <summary>The selected profile does not exist.</summary>
    Missing,
    /// <summary>The profile authority could not be verified.</summary>
    Unavailable,
}

/// <summary>Profile read outcome without customer data in error responses.</summary>
public sealed record EmployeeProfileBindingResult(EmployeeProfileBindingStatus Status, EmployeeProfileBinding? Profile = null);

/// <summary>Reads the selected owned business profile before identity creation.</summary>
public interface IEmployeeProfileBindingClient
{
    /// <summary>Reads current employee fields using Auth's own service authority.</summary>
    Task<EmployeeProfileBindingResult> ReadAsync(int databaseId, CancellationToken cancellationToken);
}
