using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Maliev.Aspire.ServiceDefaults.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Legacy.Maliev.AuthService.Api.Controllers;

/// <summary>Employee-authorized administration of employee identities.</summary>
[ApiController]
[Route("auth/v1/employee-identities")]
public sealed class EmployeeIdentitiesController(IEmployeeIdentityAdminService service) : ControllerBase
{
    /// <summary>Creates an employee identity with the initial password accepted only in JSON.</summary>
    [HttpPost("{databaseId:int}")]
    [RequirePermission(LegacyAccessTokenPermissions.EmployeeIdentitiesCreate)]
    [ProducesResponseType<EmployeeIdentityResponse>(StatusCodes.Status201Created)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status409Conflict)]
    public async Task<ActionResult<EmployeeIdentityResponse>> Create(
        int databaseId,
        CreateEmployeeIdentityRequest request,
        CancellationToken cancellationToken)
    {
        if (!AdministrativePasswordPolicy.Accepts(request.Password))
            return BadRequest(new ProblemDetails { Status = StatusCodes.Status400BadRequest, Title = "Invalid initial password" });

        var identity = await service.CreateAsync(databaseId, request, cancellationToken);
        return identity is null
            ? Conflict(new ProblemDetails { Status = StatusCodes.Status409Conflict, Title = "Identity already exists" })
            : CreatedAtAction(nameof(Get), new { databaseId }, identity);
    }

    /// <summary>Gets safe employee identity fields by legacy employee identifier.</summary>
    [HttpGet("{databaseId:int}", Name = "GetEmployeeIdentity")]
    [RequirePermission(LegacyAccessTokenPermissions.EmployeeIdentitiesRead)]
    [Authorize(Policy = "LegacyEmployee")]
    public async Task<ActionResult<EmployeeIdentityResponse>> Get(int databaseId, CancellationToken cancellationToken)
    {
        var identity = await service.GetAsync(databaseId, cancellationToken);
        return identity is null ? NotFound() : identity;
    }

    /// <summary>Updates safe identity fields without accepting password or security material.</summary>
    [HttpPut("{databaseId:int}")]
    [RequirePermission(LegacyAccessTokenPermissions.EmployeeIdentitiesUpdate)]
    [Authorize(Policy = "LegacyEmployee")]
    public async Task<IActionResult> Update(
        int databaseId,
        UpdateEmployeeIdentityRequest request,
        CancellationToken cancellationToken)
    {
        try { return await service.UpdateAsync(databaseId, request, cancellationToken) ? NoContent() : NotFound(); }
        catch (EmployeeRecoveryUnavailableException) { return Unavailable(); }
    }

    /// <summary>Deletes an identity without deleting the employee profile.</summary>
    [HttpDelete("{databaseId:int}")]
    [RequirePermission(LegacyAccessTokenPermissions.EmployeeIdentitiesDelete)]
    [Authorize(Policy = "LegacyEmployee")]
    public async Task<IActionResult> Delete(int databaseId, CancellationToken cancellationToken)
    {
        try { return await service.DeleteAsync(databaseId, cancellationToken) ? NoContent() : NotFound(); }
        catch (EmployeeRecoveryUnavailableException) { return Unavailable(); }
    }

    private ObjectResult Unavailable() => StatusCode(StatusCodes.Status503ServiceUnavailable, new ProblemDetails
    {
        Status = StatusCodes.Status503ServiceUnavailable,
        Title = "Identity action unavailable",
        Detail = "The identity action is temporarily unavailable. Please retry later.",
    });
}
