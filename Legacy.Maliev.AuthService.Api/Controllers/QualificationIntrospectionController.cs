using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Api.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Npgsql;

namespace Legacy.Maliev.AuthService.Api.Controllers;

/// <summary>Default-off qualification-only authority; local normal authentication preserves disabled-first ordering.</summary>
[ApiController, AllowAnonymous, Route("auth/v1/introspection/quotation-qualification")]
[ServiceFilter(typeof(QualificationIntrospectionBoundaryFilter), Order = -3000)]
public sealed class QualificationIntrospectionController(IQualificationIntrospectionService authority) : ControllerBase
{
    /// <summary>Returns a bounded point-in-time decision, not a distributed commit authorization.</summary>
    [HttpPost]
    public async Task<ActionResult<QualificationIntrospectionResponse>> Evaluate(QualificationIntrospectionRequest request, CancellationToken cancellationToken)
    {
        try { return Ok(await authority.EvaluateAsync(request, cancellationToken)); }
        catch (Exception exception) when (exception is NpgsqlException or RetryLimitExceededException or TimeoutException or OptionsValidationException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Do not expose or log provider/configuration details or supplied credentials.
            return QualificationIntrospectionBoundaryFilter.Error(503);
        }
    }
}
