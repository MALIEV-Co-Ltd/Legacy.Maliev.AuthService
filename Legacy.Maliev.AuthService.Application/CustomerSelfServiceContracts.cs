using System.ComponentModel.DataAnnotations;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>Creates a customer identity after its CustomerService profile exists.</summary>
public sealed record RegisterCustomerIdentityRequest(
    [Range(1, int.MaxValue)] int DatabaseId,
    [Required, EmailAddress, StringLength(320)] string Email,
    [Required, StringLength(1024, MinimumLength = 6)] string Password);
/// <summary>Customer identity registration outcome without security material.</summary>
public sealed record CustomerSelfServiceResult(bool Succeeded, string? IdentityId, int? DatabaseId, string? Email);
/// <summary>Requests an email-bound identity action.</summary>
public sealed record CustomerActionRequest([Required, EmailAddress, StringLength(320)] string Email);
/// <summary>Internal BFF challenge result. External responses must never expose whether an account exists.</summary>
public sealed record CustomerActionChallenge(bool Accepted, string? Token);
/// <summary>Completes an email-bound identity action.</summary>
public sealed record CompleteCustomerActionRequest(
    [Required, EmailAddress, StringLength(320)] string Email,
    [Required, StringLength(256, MinimumLength = 32)] string Token);
/// <summary>Completes a password reset.</summary>
public sealed record CompletePasswordResetRequest(
    [Required, EmailAddress, StringLength(320)] string Email,
    [Required, StringLength(256, MinimumLength = 32)] string Token,
    [Required, StringLength(1024, MinimumLength = 6)] string Password);
/// <summary>Changes the authenticated customer's email after verifying the current password.</summary>
public sealed record ChangeCustomerEmailRequest(
    [Required, StringLength(1024)] string CurrentPassword,
    [Required, EmailAddress, StringLength(320)] string NewEmail);
/// <summary>Changes the authenticated customer's password after verifying the current password.</summary>
public sealed record ChangeCustomerPasswordRequest(
    [Required, StringLength(1024)] string CurrentPassword,
    [Required, StringLength(1024, MinimumLength = 6)] string NewPassword);
