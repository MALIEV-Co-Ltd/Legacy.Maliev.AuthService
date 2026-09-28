using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Claims;

namespace Legacy.Maliev.AuthService.Api.Controllers;

/// <summary>Exchanges two validated server-held credentials for one invoice-create delegation.</summary>
[ApiController, Route("auth/v1/exchange/invoice-create"), Authorize(Policy = "LegacyService")]
public sealed class InvoiceDelegationController(InvoiceDelegationService delegation) : ControllerBase
{
    /// <summary>Issues a short-lived Accounting-only employee-bound JWT to the trusted Intranet service.</summary>
    [HttpPost, RequirePermission(LegacyAccessTokenPermissions.InvoiceDelegationIssue)]
    [EnableRateLimiting("service-login")]
    [ProducesResponseType<InvoiceDelegationTokenResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public ActionResult<InvoiceDelegationTokenResponse> Exchange(InvoiceDelegationRequest request)
    {
        if (request.QuotationId <= 0 ||
            !Guid.TryParseExact(request.OperationId, "D", out var operationId) ||
            operationId == Guid.Empty ||
            !string.Equals(request.OperationId, operationId.ToString("D"), StringComparison.Ordinal))
        {
            return BadRequest(new ProblemDetails { Status = StatusCodes.Status400BadRequest, Title = "Invalid invoice operation" });
        }

        var subjects = User.FindAll("sub").ToArray();
        if (subjects.Length != 1 ||
            !string.Equals(subjects[0].Value, InvoiceDelegationContract.IntranetServiceSubject, StringComparison.Ordinal))
        {
            return Forbid();
        }

        var issued = delegation.Issue(subjects[0].Value, request);
        return issued is null
            ? Unauthorized(new ProblemDetails { Status = StatusCodes.Status401Unauthorized, Title = "Authentication failed" })
            : Ok(issued);
    }
}
