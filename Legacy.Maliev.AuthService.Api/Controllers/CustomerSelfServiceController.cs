using Legacy.Maliev.AuthService.Api.Authorization;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Legacy.Maliev.AuthService.Api.Controllers;

/// <summary>Trusted-BFF customer registration, confirmation, and recovery boundary.</summary>
[ApiController]
[Route("auth/v1/customer-self-service")]
[Authorize]
[Produces("application/json")]
public sealed class CustomerSelfServiceController(CustomerSelfService service) : ControllerBase
{
    /// <summary>Registers an unconfirmed customer identity after CustomerService created its profile.</summary>
    [HttpPost("register")]
    [RequirePermission(CustomerSelfServicePermissions.Use)]
    public async Task<ActionResult<CustomerSelfServiceResult>> Register(RegisterCustomerIdentityRequest request, CancellationToken cancellationToken)
    {
        var result = await service.RegisterAsync(request, cancellationToken);
        return result.Succeeded ? StatusCode(StatusCodes.Status201Created, result) : Conflict(InvalidAction());
    }

    /// <summary>Creates a one-time email confirmation challenge for delivery by the BFF.</summary>
    [HttpPost("email-confirmation/request")]
    [RequirePermission(CustomerSelfServicePermissions.Use)]
    public Task<CustomerActionChallenge> RequestEmailConfirmation(CustomerActionRequest request, CancellationToken cancellationToken) => service.RequestEmailConfirmationAsync(request, cancellationToken);

    /// <summary>Consumes a one-time email confirmation challenge.</summary>
    [HttpPost("email-confirmation/complete")]
    [RequirePermission(CustomerSelfServicePermissions.Use)]
    public async Task<IActionResult> ConfirmEmail(CompleteCustomerActionRequest request, CancellationToken cancellationToken) => await service.ConfirmEmailAsync(request, cancellationToken) ? NoContent() : BadRequest(InvalidAction());

    /// <summary>Creates a one-time password reset challenge for delivery by the BFF.</summary>
    [HttpPost("password-reset/request")]
    [RequirePermission(CustomerSelfServicePermissions.Use)]
    public Task<CustomerActionChallenge> RequestPasswordReset(CustomerActionRequest request, CancellationToken cancellationToken) => service.RequestPasswordResetAsync(request, cancellationToken);

    /// <summary>Consumes a one-time password reset challenge and rotates identity security state.</summary>
    [HttpPost("password-reset/complete")]
    [RequirePermission(CustomerSelfServicePermissions.Use)]
    public async Task<IActionResult> CompletePasswordReset(CompletePasswordResetRequest request, CancellationToken cancellationToken) => await service.CompletePasswordResetAsync(request, cancellationToken) ? NoContent() : BadRequest(InvalidAction());

    /// <summary>Changes the authenticated customer's email and creates a one-time confirmation challenge.</summary>
    [HttpPost("email/change")]
    [Authorize(Policy = "LegacyCustomer")]
    [EnableRateLimiting("credential-change")]
    public async Task<ActionResult<CustomerActionChallenge>> ChangeEmail(
        ChangeCustomerEmailRequest request,
        CancellationToken cancellationToken)
    {
        var identityId = User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (string.IsNullOrWhiteSpace(identityId))
        {
            return Unauthorized();
        }

        var result = await service.ChangeEmailAsync(identityId, request, cancellationToken);
        return result is null ? BadRequest(InvalidCredentialChange()) : Ok(result);
    }

    /// <summary>Changes the authenticated customer's password and revokes all refresh sessions.</summary>
    [HttpPost("password/change")]
    [Authorize(Policy = "LegacyCustomer")]
    [EnableRateLimiting("credential-change")]
    public async Task<IActionResult> ChangePassword(
        ChangeCustomerPasswordRequest request,
        CancellationToken cancellationToken)
    {
        var identityId = User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (string.IsNullOrWhiteSpace(identityId))
        {
            return Unauthorized();
        }

        return await service.ChangePasswordAsync(identityId, request, cancellationToken)
            ? NoContent()
            : BadRequest(InvalidCredentialChange());
    }

    private static ProblemDetails InvalidAction() => new() { Status = StatusCodes.Status400BadRequest, Title = "Identity action failed", Detail = "The identity action is invalid or expired." };
    private static ProblemDetails InvalidCredentialChange() => new() { Status = StatusCodes.Status400BadRequest, Title = "Credential change failed", Detail = "The current password or requested account value is invalid." };
}
