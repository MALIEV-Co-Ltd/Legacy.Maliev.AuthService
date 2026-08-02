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

    /// <summary>Consumes a credential-validated resend grant and creates a fresh confirmation challenge.</summary>
    [HttpPost("email-confirmation/recover")]
    [RequirePermission(CustomerSelfServicePermissions.Use)]
    [EnableRateLimiting("credential-change")]
    public async Task<ActionResult<CustomerActionChallenge>> RecoverEmailConfirmation(
        CompleteCustomerActionRequest request,
        CancellationToken cancellationToken)
    {
        var result = await service.RecoverEmailConfirmationAsync(request, cancellationToken);
        return result.Accepted && result.Token is not null
            ? Ok(result)
            : BadRequest(InvalidAction());
    }

    /// <summary>Consumes a one-time email confirmation challenge.</summary>
    [HttpPost("email-confirmation/complete")]
    [RequirePermission(CustomerSelfServicePermissions.Use)]
    public async Task<IActionResult> ConfirmEmail(CompleteCustomerActionRequest request, CancellationToken cancellationToken) => await service.ConfirmEmailAsync(request, cancellationToken) ? NoContent() : BadRequest(InvalidAction());

    /// <summary>Validates a pending customer email-change challenge without consuming it.</summary>
    [HttpPost("email-change/validate")]
    [RequirePermission(CustomerSelfServicePermissions.Use)]
    public async Task<ActionResult<CustomerEmailChangeValidation>> ValidateEmailChange(
        CompleteCustomerActionRequest request,
        CancellationToken cancellationToken)
    {
        var result = await service.ValidateEmailChangeAsync(request, cancellationToken);
        return result is null ? BadRequest(InvalidAction()) : Ok(result);
    }

    /// <summary>Consumes a pending customer email-change challenge and commits the identity change.</summary>
    [HttpPost("email-change/complete")]
    [RequirePermission(CustomerSelfServicePermissions.Use)]
    public async Task<IActionResult> CompleteEmailChange(
        CompleteCustomerActionRequest request,
        CancellationToken cancellationToken) =>
        await service.CompleteEmailChangeAsync(request, cancellationToken)
            ? NoContent()
            : BadRequest(InvalidAction());

    /// <summary>Creates a one-time password reset challenge for delivery by the BFF.</summary>
    [HttpPost("password-reset/request")]
    [RequirePermission(CustomerSelfServicePermissions.Use)]
    public Task<CustomerActionChallenge> RequestPasswordReset(CustomerActionRequest request, CancellationToken cancellationToken) => service.RequestPasswordResetAsync(request, cancellationToken);

    /// <summary>Consumes a one-time password reset challenge and rotates identity security state.</summary>
    [HttpPost("password-reset/complete")]
    [RequirePermission(CustomerSelfServicePermissions.Use)]
    public async Task<IActionResult> CompletePasswordReset(CompletePasswordResetRequest request, CancellationToken cancellationToken) => await service.CompletePasswordResetAsync(request, cancellationToken) ? NoContent() : BadRequest(InvalidAction());

    /// <summary>Consumes a first-login challenge and replaces the issued temporary password.</summary>
    [HttpPost("initial-password/complete")]
    [RequirePermission(CustomerSelfServicePermissions.Use)]
    [EnableRateLimiting("credential-change")]
    public async Task<IActionResult> CompleteInitialPassword(
        CompleteInitialPasswordRequest request,
        CancellationToken cancellationToken) =>
        await service.CompleteInitialPasswordAsync(request, cancellationToken)
            ? NoContent()
            : BadRequest(InvalidAction());

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

    /// <summary>Adds the first password to an authenticated passwordless customer identity.</summary>
    [HttpPost("password/create")]
    [Authorize(Policy = "LegacyCustomer")]
    [EnableRateLimiting("credential-change")]
    public async Task<IActionResult> CreatePassword(
        CreateCustomerPasswordRequest request,
        CancellationToken cancellationToken)
    {
        var identityId = User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (string.IsNullOrWhiteSpace(identityId))
        {
            return Unauthorized();
        }

        return await service.CreatePasswordAsync(identityId, request, cancellationToken) switch
        {
            CreateCustomerPasswordResult.Created => NoContent(),
            CreateCustomerPasswordResult.AlreadyExists => Conflict(PasswordAlreadyExists()),
            _ => NotFound(IdentityNotFound()),
        };
    }

    private static ProblemDetails InvalidAction() => new() { Status = StatusCodes.Status400BadRequest, Title = "Identity action failed", Detail = "The identity action is invalid or expired." };
    private static ProblemDetails InvalidCredentialChange() => new() { Status = StatusCodes.Status400BadRequest, Title = "Credential change failed", Detail = "The current password or requested account value is invalid." };
    private static ProblemDetails PasswordAlreadyExists() => new() { Status = StatusCodes.Status409Conflict, Title = "Password already exists", Detail = "Use the password change flow for an identity that already has a password." };
    private static ProblemDetails IdentityNotFound() => new() { Status = StatusCodes.Status404NotFound, Title = "Identity not found", Detail = "The authenticated customer identity no longer exists." };
}
