using Legacy.Maliev.AuthService.Application;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Legacy.Maliev.AuthService.Api.Controllers;

/// <summary>Employee-authorized administration of customer identities.</summary>
[ApiController]
[Authorize(Policy = "LegacyEmployee")]
[Route("auth/v1/customer-identities")]
public sealed class CustomerIdentitiesController(ICustomerIdentityAdminService service) : ControllerBase
{
    /// <summary>Creates a customer identity; the password is accepted only in the JSON body.</summary>
    [HttpPost("{databaseId:int}")]
    [ProducesResponseType<CustomerIdentityResponse>(StatusCodes.Status201Created)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status409Conflict)]
    public async Task<ActionResult<CustomerIdentityResponse>> Create(
        int databaseId,
        CreateCustomerIdentityRequest request,
        CancellationToken cancellationToken)
    {
        var identity = await service.CreateAsync(databaseId, request, cancellationToken);
        return identity is null
            ? Conflict(new ProblemDetails { Status = StatusCodes.Status409Conflict, Title = "Identity already exists" })
            : CreatedAtAction(nameof(Get), new { databaseId }, identity);
    }

    /// <summary>Gets safe identity fields by legacy customer identifier.</summary>
    [HttpGet("{databaseId:int}", Name = "GetCustomerIdentity")]
    public async Task<ActionResult<CustomerIdentityResponse>> Get(int databaseId, CancellationToken cancellationToken)
    {
        var identity = await service.GetAsync(databaseId, cancellationToken);
        return identity is null ? NotFound() : identity;
    }

    /// <summary>Updates safe identity fields without accepting password or security material.</summary>
    [HttpPut("{databaseId:int}")]
    public async Task<IActionResult> Update(
        int databaseId,
        UpdateCustomerIdentityRequest request,
        CancellationToken cancellationToken) =>
        await service.UpdateAsync(databaseId, request, cancellationToken) ? NoContent() : NotFound();

    /// <summary>Deletes an identity without deleting the customer profile.</summary>
    [HttpDelete("{databaseId:int}")]
    public async Task<IActionResult> Delete(int databaseId, CancellationToken cancellationToken) =>
        await service.DeleteAsync(databaseId, cancellationToken) ? NoContent() : NotFound();
}