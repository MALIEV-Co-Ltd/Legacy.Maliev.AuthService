using Legacy.Maliev.AuthService.Api.Authorization;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Legacy.Maliev.AuthService.Api.Controllers;

/// <summary>Trusted-BFF employee confirmation and recovery boundary.</summary>
[ApiController]
[Route("auth/v1/employee-self-service")]
[Authorize]
[Produces("application/json")]
public sealed class EmployeeSelfServiceController(EmployeeSelfService service) : ControllerBase
{
    /// <summary>Creates a one-time email confirmation challenge for delivery by the BFF.</summary>
    [HttpPost("email-confirmation/request")]
    [RequirePermission(EmployeeSelfServicePermissions.Use)]
    public Task<EmployeeActionChallenge> RequestEmailConfirmation(
        EmployeeActionRequest request,
        CancellationToken cancellationToken) =>
        service.RequestEmailConfirmationAsync(request, cancellationToken);

    /// <summary>Consumes a one-time employee email confirmation challenge.</summary>
    [HttpPost("email-confirmation/complete")]
    [RequirePermission(EmployeeSelfServicePermissions.Use)]
    public async Task<IActionResult> ConfirmEmail(
        CompleteEmployeeActionRequest request,
        CancellationToken cancellationToken) =>
        await service.ConfirmEmailAsync(request, cancellationToken)
            ? NoContent()
            : BadRequest(InvalidAction());

    /// <summary>Creates a one-time employee password reset challenge for delivery by the BFF.</summary>
    [HttpPost("password-reset/request")]
    [RequirePermission(EmployeeSelfServicePermissions.Use)]
    public Task<EmployeeActionChallenge> RequestPasswordReset(
        EmployeeActionRequest request,
        CancellationToken cancellationToken) =>
        service.RequestPasswordResetAsync(request, cancellationToken);

    /// <summary>Consumes a one-time employee password reset challenge and rotates security state.</summary>
    [HttpPost("password-reset/complete")]
    [RequirePermission(EmployeeSelfServicePermissions.Use)]
    public async Task<IActionResult> CompletePasswordReset(
        CompleteEmployeePasswordResetRequest request,
        CancellationToken cancellationToken) =>
        await service.CompletePasswordResetAsync(request, cancellationToken)
            ? NoContent()
            : BadRequest(InvalidAction());

    private static ProblemDetails InvalidAction() => new()
    {
        Status = StatusCodes.Status400BadRequest,
        Title = "Identity action failed",
        Detail = "The identity action is invalid or expired.",
    };
}
