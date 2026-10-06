using Asp.Versioning;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Npgsql;

namespace Legacy.Maliev.AuthService.Api.Controllers;

/// <summary>Exchanges current employee authority for one separately scoped Accounting-executed operation.</summary>
[ApiController, ApiVersion("1.0"), Route("auth/v{version:apiVersion}/exchange/quotation-invoice-completion"), Authorize(Policy = "LegacyService")]
public sealed class QuotationInvoiceCapabilityController(QuotationInvoiceCapabilityService service) : ControllerBase
{
    /// <summary>Issues a short-lived quotation capability, never an ordinary employee access token.</summary>
    [HttpPost, RequirePermission(QuotationInvoiceCapabilityContract.IssuePermission), EnableRateLimiting("service-login")]
    [ProducesResponseType<QuotationInvoiceCapabilityResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<QuotationInvoiceCapabilityResponse>> Exchange(QuotationInvoiceCapabilityRequest request)
    {
        if (request.QuotationId <= 0 || request.InvoiceId is <= 0 || !Guid.TryParseExact(request.OperationId, "D", out var operation)
            || operation == Guid.Empty || request.OperationId != operation.ToString("D"))
            return BadRequest(new ProblemDetails { Status = 400, Title = "Invalid quotation operation" });
        try
        {
            var authorization = Request.Headers.Authorization.ToString();
            var callerToken = authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? authorization[7..] : null;
            var result = await service.IssueAsync(User, callerToken, request, HttpContext.RequestAborted);
            return result.Status switch
            {
                QuotationInvoiceCapabilityStatus.Issued => Ok(result.Token),
                QuotationInvoiceCapabilityStatus.InvalidRequest => BadRequest(new ProblemDetails { Status = 400, Title = "Invalid quotation operation" }),
                QuotationInvoiceCapabilityStatus.Forbidden => Forbid(),
                QuotationInvoiceCapabilityStatus.Unavailable => Unavailable(),
                _ => Unauthorized(new ProblemDetails { Status = 401, Title = "Authentication failed" }),
            };
        }
        catch (Exception exception) when (exception is NpgsqlException or RetryLimitExceededException or TimeoutException or OptionsValidationException)
        {
            HttpContext.RequestAborted.ThrowIfCancellationRequested();
            return Unavailable();
        }
    }

    private ObjectResult Unavailable() => StatusCode(503, new ProblemDetails { Status = 503, Title = "Authentication authority unavailable" });
}
