using System.ComponentModel.DataAnnotations;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>Requests an employee email-bound identity action.</summary>
public sealed record EmployeeActionRequest(
    [Required, EmailAddress, StringLength(320)] string Email);

/// <summary>Trusted-BFF challenge result. Public responses must never reveal account existence.</summary>
public sealed record EmployeeActionChallenge(bool Accepted, string? Token);

/// <summary>Completes an employee email-bound identity action.</summary>
public sealed record CompleteEmployeeActionRequest(
    [Required, EmailAddress, StringLength(320)] string Email,
    [Required, StringLength(256, MinimumLength = 32)] string Token);

/// <summary>Completes an employee password reset.</summary>
public sealed record CompleteEmployeePasswordResetRequest(
    [Required, EmailAddress, StringLength(320)] string Email,
    [Required, StringLength(256, MinimumLength = 32)] string Token,
    [Required, StringLength(1024, MinimumLength = 6)] string Password);
