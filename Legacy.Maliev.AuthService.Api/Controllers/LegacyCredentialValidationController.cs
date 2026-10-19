using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Legacy.Maliev.AuthService.Api.Controllers;

/// <summary>Retains the two original password-only validation routes without issuing authority.</summary>
[ApiController]
[AllowAnonymous]
[EnableRateLimiting("login")]
public sealed class LegacyCredentialValidationController(ILegacyCredentialValidationService validation) : ControllerBase
{
    /// <summary>Checks a customer password in the customer identity store.</summary>
    [HttpPost("/customers/v1/validate")]
    public Task<IActionResult> Customer(
        [FromBody] LegacyCredentialValidationRequest request,
        CancellationToken cancellationToken) => ValidateAsync(request, IdentityKind.Customer, cancellationToken);

    /// <summary>Checks an employee password in the employee identity store.</summary>
    [HttpPost("/Employees/v1/validate")]
    public Task<IActionResult> Employee(
        [FromBody] LegacyCredentialValidationRequest request,
        CancellationToken cancellationToken) => ValidateAsync(request, IdentityKind.Employee, cancellationToken);

    private async Task<IActionResult> ValidateAsync(
        LegacyCredentialValidationRequest? request, IdentityKind kind, CancellationToken cancellationToken)
    {
        if (request is null || string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
            return BadRequest("Username and password are required.");

        var outcome = await validation.ValidateAsync(request.Username, request.Password, kind, cancellationToken);
        return outcome switch
        {
            LegacyCredentialValidationOutcome.UnknownIdentity => NotFound("User not found."),
            LegacyCredentialValidationOutcome.InvalidPassword => Unauthorized(),
            LegacyCredentialValidationOutcome.Valid => Ok(),
            _ => throw new InvalidOperationException("Unknown credential-validation outcome."),
        };
    }
}
