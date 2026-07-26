using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Api.Security;
using Legacy.Maliev.AuthService.Infrastructure;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Legacy.Maliev.AuthService.Api.Controllers;

/// <summary>Secure token endpoints for customer and employee legacy identities.</summary>
[ApiController]
[Route("auth/v1")]
[Produces("application/json")]
public sealed class AuthenticationController(
    AuthenticationService authenticationService,
    ServiceAuthenticationService serviceAuthenticationService,
    GoogleAuthenticationService? googleAuthenticationService = null) : ControllerBase
{
    private const string EmployeeApplication = "intranet";

    /// <summary>Authenticates a configured machine identity without creating a refresh session.</summary>
    [HttpPost("service/login")]
    [EnableRateLimiting("service-login")]
    [ProducesResponseType<ServiceTokenResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<ServiceTokenResponse>> ServiceLogin(ServiceLoginRequest request)
    {
        var result = await serviceAuthenticationService.LoginAsync(request);
        return result.Succeeded ? Ok(result.Token) : Unauthorized(AuthenticationProblem());
    }
    /// <summary>Authenticates against one unchanged legacy identity database.</summary>
    [HttpPost("login")]
    [ServiceFilter(typeof(LoginRateLimitFilter))]
    [ProducesResponseType<TokenResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<ActionResult<TokenResponse>> Login(
        LoginRequest request,
        CancellationToken cancellationToken)
    {
        var result = await authenticationService.LoginAsync(request, cancellationToken);
        return result.Succeeded
            ? Ok(result.Tokens)
            : Unauthorized(AuthenticationProblem());
    }

    /// <summary>Atomically exchanges a single-use refresh token.</summary>
    [HttpPost("refresh")]
    [EnableRateLimiting("login")]
    [ProducesResponseType<TokenResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<TokenResponse>> Refresh(
        RefreshRequest request,
        CancellationToken cancellationToken)
    {
        var result = await authenticationService.RefreshAsync(request, cancellationToken);
        return result.Succeeded
            ? Ok(result.Tokens)
            : Unauthorized(AuthenticationProblem());
    }

    /// <summary>Revokes the complete family associated with a refresh token.</summary>
    [HttpPost("revoke")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Revoke(RevokeRequest request, CancellationToken cancellationToken)
    {
        await authenticationService.RevokeAsync(request, cancellationToken);
        return NoContent();
    }

    /// <summary>Issues a one-time nonce for the trusted Intranet Google Identity Services flow.</summary>
    [HttpPost("exchange/google/nonce")]
    [RequirePermission(LegacyAccessTokenPermissions.GoogleIdentityExchange)]
    [ProducesResponseType<GoogleIdentityNonceResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status403Forbidden)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<GoogleIdentityNonceResponse>> IssueEmployeeGoogleNonce(
        GoogleIdentityNonceRequest request,
        CancellationToken cancellationToken)
    {
        if (googleAuthenticationService is null ||
            !string.Equals(request.Application, EmployeeApplication, StringComparison.Ordinal))
        {
            return Forbid();
        }

        var serviceName = User.FindFirst("name")?.Value;
        if (string.IsNullOrWhiteSpace(serviceName))
        {
            return Forbid();
        }

        try
        {
            var issued = await googleAuthenticationService.IssueNonceAsync(
                serviceName,
                request.Application,
                cancellationToken);
            return Ok(new GoogleIdentityNonceResponse(issued.Nonce, issued.ExpiresAtUtc));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new ProblemDetails
            {
                Status = StatusCodes.Status503ServiceUnavailable,
                Title = "Google sign-in is temporarily unavailable.",
            });
        }
    }

    /// <summary>Exchanges a nonce-bound Google credential for an employee token session.</summary>
    [HttpPost("exchange/google")]
    [RequirePermission(LegacyAccessTokenPermissions.GoogleIdentityExchange)]
    [ProducesResponseType<TokenResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status403Forbidden)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<TokenResponse>> ExchangeEmployeeGoogleToken(
        GoogleExchangeRequest request,
        CancellationToken cancellationToken)
    {
        if (googleAuthenticationService is null ||
            !string.Equals(request.Application, EmployeeApplication, StringComparison.Ordinal))
        {
            return Forbid();
        }

        var serviceName = User.FindFirst("name")?.Value;
        if (string.IsNullOrWhiteSpace(serviceName))
        {
            return Forbid();
        }

        GoogleExchangeResult result;
        try
        {
            result = await googleAuthenticationService.ExchangeAsync(
                request,
                serviceName,
                cancellationToken);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new ProblemDetails
            {
                Status = StatusCodes.Status503ServiceUnavailable,
                Title = "Google sign-in is temporarily unavailable.",
            });
        }

        if (result.Succeeded && result.Tokens is not null)
        {
            return Ok(result.Tokens);
        }

        return result.ErrorCode switch
        {
            "employee_not_found" or "invalid_domain" => StatusCode(StatusCodes.Status403Forbidden, new ProblemDetails
            {
                Status = StatusCodes.Status403Forbidden,
                Title = "Google employee access is not permitted.",
            }),
            "service_unavailable" => StatusCode(StatusCodes.Status503ServiceUnavailable, new ProblemDetails
            {
                Status = StatusCodes.Status503ServiceUnavailable,
                Title = "Google sign-in is temporarily unavailable.",
            }),
            _ => Unauthorized(AuthenticationProblem()),
        };
    }

    private static ProblemDetails AuthenticationProblem() => new()
    {
        Status = StatusCodes.Status401Unauthorized,
        Title = "Authentication failed",
        Detail = "The supplied credentials or session are invalid.",
    };
}
