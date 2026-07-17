using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Api.Security;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Legacy.Maliev.AuthService.Api.Controllers;

/// <summary>Secure token endpoints for customer and employee legacy identities.</summary>
[ApiController]
[Route("auth/v1")]
[Produces("application/json")]
public sealed class AuthenticationController(AuthenticationService authenticationService, ServiceAuthenticationService serviceAuthenticationService) : ControllerBase
{
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

    private static ProblemDetails AuthenticationProblem() => new()
    {
        Status = StatusCodes.Status401Unauthorized,
        Title = "Authentication failed",
        Detail = "The supplied credentials or session are invalid.",
    };
}
