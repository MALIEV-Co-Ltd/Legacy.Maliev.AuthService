using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;

namespace Legacy.Maliev.AuthService.Api.Security;

/// <summary>Endpoint-only boundary before binding; deliberately avoids a generic authorization challenge before disabled404.</summary>
public sealed class QualificationIntrospectionBoundaryFilter(
    IOptionsMonitor<QualificationIntrospectionOptions> options,
    IQualificationCallerAuthorizer authorizer,
    QualificationIntrospectionRateLimiter limiter) : IAsyncResourceFilter, IActionFilter
{
    private static readonly object AdmissionProofKey = new();
    /// <inheritdoc />
    public async Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
    {
        var http = context.HttpContext;
        http.Response.Headers.CacheControl = "no-store";
        http.Response.Headers.Pragma = "no-cache";
        try { if (!options.CurrentValue.Enabled) { context.Result = Error(404); return; } }
        catch (OptionsValidationException) { context.Result = Error(503); return; }
        var authentication = await http.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);
        if (!authentication.Succeeded || authentication.Principal is null)
        {
            http.Response.Headers.WWWAuthenticate = "Bearer";
            context.Result = Error(401); return;
        }
        var admission = authorizer.Authorize(authentication.Principal);
        if (admission != QualificationCallerAuthorization.Allowed)
        { context.Result = Error(admission == QualificationCallerAuthorization.Unavailable ? 503 : 403); return; }
        try
        {
            if (!limiter.AttemptAcquire(QualificationIntrospectionContract.Caller)) { context.Result = Error(429); return; }
        }
        catch (OptionsValidationException) { context.Result = Error(503); return; }
        var request = http.Request;
        if (!request.HasJsonContentType()) { context.Result = Error(400); return; }
        if (request.ContentLength > QualificationIntrospectionContract.MaxBodyBytes) { context.Result = Error(400); return; }
        var original = request.Body;
        await using var bounded = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var remaining = QualificationIntrospectionContract.MaxBodyBytes + 1 - (int)bounded.Length;
            var read = await original.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, remaining)), http.RequestAborted);
            if (read == 0) break;
            await bounded.WriteAsync(buffer.AsMemory(0, read), http.RequestAborted);
            if (bounded.Length > QualificationIntrospectionContract.MaxBodyBytes) { context.Result = Error(400); return; }
        }
        bounded.Position = 0;
        request.Body = bounded;
        http.Items[AdmissionProofKey] = true;
        try { await next(); }
        finally { http.Items.Remove(AdmissionProofKey); request.Body = original; }
    }

    /// <inheritdoc />
    public void OnActionExecuting(ActionExecutingContext context)
    {
        if (!context.HttpContext.Items.TryGetValue(AdmissionProofKey, out var proof) || proof is not true)
        { context.Result = Error(401); return; }
        if (!context.ModelState.IsValid ||
            !context.ActionArguments.TryGetValue("request", out var value) || value is not QualificationIntrospectionRequest request ||
            request.Purpose != QualificationIntrospectionContract.Purpose ||
            request.Permission is not (QualificationIntrospectionContract.Read or QualificationIntrospectionContract.Update))
            context.Result = Error(400);
    }

    /// <inheritdoc />
    public void OnActionExecuted(ActionExecutedContext context) { }

    internal static ObjectResult Error(int status) => new(new ProblemDetails { Status = status, Title = "Qualification request failed" }) { StatusCode = status };
}
