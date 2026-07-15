using System.ComponentModel.DataAnnotations;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>Creates a customer identity after its CustomerService profile exists.</summary>
public sealed record RegisterCustomerIdentityRequest(
    [property: Range(1, int.MaxValue)] int DatabaseId,
    [property: Required, EmailAddress, StringLength(320)] string Email,
    [property: Required, StringLength(1024, MinimumLength = 6)] string Password);
/// <summary>Customer identity registration outcome without security material.</summary>
public sealed record CustomerSelfServiceResult(bool Succeeded, string? IdentityId, int? DatabaseId, string? Email);
/// <summary>Requests an email-bound identity action.</summary>
public sealed record CustomerActionRequest([property: Required, EmailAddress, StringLength(320)] string Email);
/// <summary>Internal BFF challenge result. External responses must never expose whether an account exists.</summary>
public sealed record CustomerActionChallenge(bool Accepted, string? Token);
/// <summary>Completes an email-bound identity action.</summary>
public sealed record CompleteCustomerActionRequest(
    [property: Required, EmailAddress, StringLength(320)] string Email,
    [property: Required, StringLength(256, MinimumLength = 32)] string Token);
/// <summary>Completes a password reset.</summary>
public sealed record CompletePasswordResetRequest(
    [property: Required, EmailAddress, StringLength(320)] string Email,
    [property: Required, StringLength(256, MinimumLength = 32)] string Token,
    [property: Required, StringLength(1024, MinimumLength = 6)] string Password);