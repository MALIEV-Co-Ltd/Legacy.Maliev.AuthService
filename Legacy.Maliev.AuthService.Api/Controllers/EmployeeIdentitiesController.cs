using Legacy.Maliev.AuthService.Application;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Legacy.Maliev.AuthService.Api.Controllers;

/// <summary>Employee-authorized administration of employee identities.</summary>
[ApiController]
[Authorize(Policy = "LegacyEmployee")]
[Route("auth/v1/employee-identities")]
public sealed class EmployeeIdentitiesController(IEmployeeIdentityAdminService service) : ControllerBase
{
    /// <summary>Creates an employee identity with the initial password accepted only in JSON.</summary>
    [HttpPost("{databaseId:int}")]
    [ProducesResponseType<EmployeeIdentityResponse>(StatusCodes.Status201Created)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status409Conflict)]
    public async Task<ActionResult<EmployeeIdentityResponse>> Create(
        int databaseId,
        CreateEmployeeIdentityRequest request,
        CancellationToken cancellationToken)
    {
        var identity = await service.CreateAsync(databaseId, request, cancellationToken);
        return identity is null
            ? Conflict(new ProblemDetails { Status = StatusCodes.Status409Conflict, Title = "Identity already exists" })
            : CreatedAtAction(nameof(Get), new { databaseId }, identity);
    }

    /// <summary>Gets safe employee identity fields by legacy employee identifier.</summary>
    [HttpGet("{databaseId:int}", Name = "GetEmployeeIdentity")]
    public async Task<ActionResult<EmployeeIdentityResponse>> Get(int databaseId, CancellationToken cancellationToken)
    {
        var identity = await service.GetAsync(databaseId, cancellationToken);
        return identity is null ? NotFound() : identity;
    }

    /// <summary>Updates safe identity fields without accepting password or security material.</summary>
    [HttpPut("{databaseId:int}")]
    public async Task<IActionResult> Update(
        int databaseId,
        UpdateEmployeeIdentityRequest request,
        CancellationToken cancellationToken) =>
        await service.UpdateAsync(databaseId, request, cancellationToken) ? NoContent() : NotFound();

    /// <summary>Deletes an identity without deleting the employee profile.</summary>
    [HttpDelete("{databaseId:int}")]
    public async Task<IActionResult> Delete(int databaseId, CancellationToken cancellationToken) =>
        await service.DeleteAsync(databaseId, cancellationToken) ? NoContent() : NotFound();
}
