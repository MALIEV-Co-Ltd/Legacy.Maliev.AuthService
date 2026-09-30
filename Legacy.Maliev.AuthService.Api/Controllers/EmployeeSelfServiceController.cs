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
    public async Task<ActionResult<EmployeeActionChallenge>> RequestEmailConfirmation(
        EmployeeActionRequest request,
        CancellationToken cancellationToken)
    {
        var owner = Owner();
        if (owner is null) return BadRequest(InvalidAction());
        try { return await service.RequestEmailConfirmationAsync(request, owner, cancellationToken); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return Unavailable(); }
    }

    /// <summary>Consumes a one-time employee email confirmation challenge.</summary>
    [HttpPost("email-confirmation/complete")]
    [RequirePermission(EmployeeSelfServicePermissions.Use)]
    public async Task<IActionResult> ConfirmEmail(
        CompleteEmployeeActionRequest request,
        CancellationToken cancellationToken)
    {
        var owner = Owner();
        if (owner is null) return BadRequest(InvalidAction());
        try { return await service.ConfirmEmailAsync(request, owner, cancellationToken) ? NoContent() : BadRequest(InvalidAction()); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return Unavailable(); }
    }

    /// <summary>Creates a one-time employee password reset challenge for delivery by the BFF.</summary>
    [HttpPost("password-reset/request")]
    [RequirePermission(EmployeeSelfServicePermissions.Use)]
    public async Task<ActionResult<EmployeeActionChallenge>> RequestPasswordReset(
        EmployeeActionRequest request,
        CancellationToken cancellationToken)
    {
        var owner = Owner();
        if (owner is null) return BadRequest(InvalidAction());
        try { return await service.RequestPasswordResetAsync(request, owner, cancellationToken); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return Unavailable(); }
    }

    /// <summary>Consumes a one-time employee password reset challenge and rotates security state.</summary>
    [HttpPost("password-reset/complete")]
    [RequirePermission(EmployeeSelfServicePermissions.Use)]
    public async Task<IActionResult> CompletePasswordReset(
        CompleteEmployeePasswordResetRequest request,
        CancellationToken cancellationToken)
    {
        var owner = Owner();
        if (owner is null) return BadRequest(InvalidAction());
        try { return await service.CompletePasswordResetAsync(request, owner, cancellationToken) ? NoContent() : BadRequest(InvalidAction()); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return Unavailable(); }
    }

    private string? Owner()
    {
        var principal = ControllerContext.HttpContext?.User;
        if (principal is null) return null;
        var subjects = principal.FindAll("sub").ToArray();
        return principal.Identity?.IsAuthenticated == true && subjects.Length == 1
            && !string.IsNullOrWhiteSpace(subjects[0].Value) && subjects[0].Value.Length <= 256 ? subjects[0].Value : null;
    }

    private ObjectResult Unavailable() => StatusCode(StatusCodes.Status503ServiceUnavailable, new ProblemDetails
    {
        Status = StatusCodes.Status503ServiceUnavailable,
        Title = "Identity action unavailable",
        Detail = "The identity action is temporarily unavailable. Please retry later.",
    });

    private static ProblemDetails InvalidAction() => new()
    {
        Status = StatusCodes.Status400BadRequest,
        Title = "Identity action failed",
        Detail = "The identity action is invalid or expired.",
    };
}
