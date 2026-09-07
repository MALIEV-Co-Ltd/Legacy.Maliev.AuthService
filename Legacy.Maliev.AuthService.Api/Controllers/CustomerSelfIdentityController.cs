using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using Legacy.Maliev.AuthService.Application;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Legacy.Maliev.AuthService.Api.Controllers;

/// <summary>Customer-only current identity projection, separate from employee identity administration.</summary>
[ApiController]
[Route("auth/v1/customer-self-service/identity")]
[Authorize(Policy = "LegacyCustomer")]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class CustomerSelfIdentityController(ICustomerSelfIdentityReader reader) : ControllerBase
{
    /// <summary>Gets current contact fields exclusively for the validated token's subject.</summary>
    [HttpGet]
    [ProducesResponseType<CustomerSelfIdentityResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<CustomerSelfIdentityResponse>> Get(CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store, private";
        var subjects = User.FindAll(JwtRegisteredClaimNames.Sub).ToArray();
        var customerIds = User.FindAll("legacy_database_id").ToArray();
        if (subjects.Length != 1 || string.IsNullOrWhiteSpace(subjects[0].Value)
            || customerIds.Length != 1
            || !int.TryParse(customerIds[0].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var customerId)
            || customerId <= 0)
        {
            return Unauthorized();
        }

        var result = await reader.GetAsync(subjects[0].Value, customerId, cancellationToken);
        return result.Status switch
        {
            CustomerSelfIdentityStatus.Found => Ok(result.Identity),
            CustomerSelfIdentityStatus.Missing => NotFound(),
            _ => Forbid(),
        };
    }
}
