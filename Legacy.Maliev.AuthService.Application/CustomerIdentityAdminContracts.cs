using System.ComponentModel.DataAnnotations;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>Creates a customer identity using a password carried only in JSON.</summary>
public sealed record CreateCustomerIdentityRequest(
    [Required, EmailAddress, StringLength(320)] string UserName,
    [Required, EmailAddress, StringLength(320)] string Email,
    [Required, StringLength(1024, MinimumLength = 6)] string Password,
    bool EmailConfirmed,
    [Phone, StringLength(64)] string? PhoneNumber,
    string? FaxNumber,
    string? MobileNumber,
    bool PasswordSetupRequired = false);

/// <summary>Updates non-secret fields of an existing customer identity.</summary>
public sealed record UpdateCustomerIdentityRequest(
    [Required, EmailAddress, StringLength(320)] string UserName,
    [Required, EmailAddress, StringLength(320)] string Email,
    bool EmailConfirmed,
    [Phone, StringLength(64)] string? PhoneNumber,
    bool PhoneNumberConfirmed,
    bool TwoFactorEnabled,
    DateTimeOffset? LockoutEnd,
    bool LockoutEnabled,
    string? FaxNumber,
    string? MobileNumber);

/// <summary>Safe customer identity fields; password and security material are excluded.</summary>
public sealed record CustomerIdentityResponse(
    string Id,
    string? UserName,
    string? Email,
    bool EmailConfirmed,
    string? PhoneNumber,
    bool PhoneNumberConfirmed,
    bool TwoFactorEnabled,
    DateTimeOffset? LockoutEnd,
    bool LockoutEnabled,
    int AccessFailedCount,
    int DatabaseID,
    string? FaxNumber,
    string? MobileNumber);

/// <summary>Non-PII result of an operation-keyed customer identity create.</summary>
public sealed record CustomerIdentityCreateReceipt(int DatabaseId, string Status);

/// <summary>Outcome of an operation-keyed create attempt.</summary>
public enum CustomerIdentityCreateOutcome { Created, Replayed, Conflict }

/// <summary>Result of an operation-keyed create attempt.</summary>
public sealed record CustomerIdentityCreateResult(CustomerIdentityCreateOutcome Outcome, int DatabaseId);

/// <summary>Customer identity administration backed by the unchanged legacy schema.</summary>
public interface ICustomerIdentityAdminService
{
    /// <summary>Atomically creates an identity and durable ownership receipt, or reconciles its retry.</summary>
    Task<CustomerIdentityCreateResult> CreateOrReconcileAsync(
        int databaseId, string serviceSubject, Guid operationKey,
        CreateCustomerIdentityRequest request, CancellationToken cancellationToken);
    /// <summary>Creates a customer identity for a business database identifier.</summary>
    Task<CustomerIdentityResponse?> CreateAsync(int databaseId, CreateCustomerIdentityRequest request, CancellationToken cancellationToken);

    /// <summary>Gets a customer identity by business database identifier.</summary>
    Task<CustomerIdentityResponse?> GetAsync(int databaseId, CancellationToken cancellationToken);

    /// <summary>Updates safe identity fields.</summary>
    Task<bool> UpdateAsync(int databaseId, UpdateCustomerIdentityRequest request, CancellationToken cancellationToken);

    /// <summary>Deletes an identity while leaving the customer profile untouched.</summary>
    Task<bool> DeleteAsync(int databaseId, CancellationToken cancellationToken);
}
