using System.ComponentModel.DataAnnotations;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>Creates an employee identity using a password carried only in JSON.</summary>
public sealed record CreateEmployeeIdentityRequest(
    [Required, EmailAddress, StringLength(320)] string UserName,
    [Required, EmailAddress, StringLength(320)] string Email,
    [Required, StringLength(1024, MinimumLength = 6)] string Password,
    bool EmailConfirmed,
    [Phone, StringLength(64)] string? PhoneNumber);

/// <summary>Updates non-secret employee identity fields.</summary>
public sealed record UpdateEmployeeIdentityRequest(
    [Required, EmailAddress, StringLength(320)] string UserName,
    [Required, EmailAddress, StringLength(320)] string Email,
    bool EmailConfirmed,
    [Phone, StringLength(64)] string? PhoneNumber,
    bool PhoneNumberConfirmed,
    bool TwoFactorEnabled,
    DateTimeOffset? LockoutEnd,
    bool LockoutEnabled);

/// <summary>Safe employee identity fields with password and security material excluded.</summary>
public sealed record EmployeeIdentityResponse(
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
    int DatabaseID);

/// <summary>Employee identity administration backed by the unchanged legacy schema.</summary>
public interface IEmployeeIdentityAdminService
{
    /// <summary>Creates an identity for an employee business identifier.</summary>
    Task<EmployeeIdentityResponse?> CreateAsync(int databaseId, CreateEmployeeIdentityRequest request, CancellationToken cancellationToken);

    /// <summary>Gets an employee identity by its business identifier.</summary>
    Task<EmployeeIdentityResponse?> GetAsync(int databaseId, CancellationToken cancellationToken);

    /// <summary>Updates safe employee identity fields and rotates the security stamp.</summary>
    Task<bool> UpdateAsync(int databaseId, UpdateEmployeeIdentityRequest request, CancellationToken cancellationToken);

    /// <summary>Deletes an identity while leaving the employee profile untouched.</summary>
    Task<bool> DeleteAsync(int databaseId, CancellationToken cancellationToken);
}
