using Legacy.Maliev.AuthService.Application;
using Microsoft.EntityFrameworkCore;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Reads the signed customer's contact fields without exposing identity security material.</summary>
public sealed class CustomerSelfIdentityReader(CustomerIdentityDbContext customers, TimeProvider timeProvider) : ICustomerSelfIdentityReader
{
    /// <inheritdoc />
    public async Task<CustomerSelfIdentityResult> GetAsync(string identityId, int expectedCustomerId, CancellationToken cancellationToken)
    {
        var row = await customers.Users.AsNoTracking()
            .Where(value => value.Id == identityId)
            .Select(value => new { value.DatabaseID, value.Email, value.MobileNumber, value.EmailConfirmed,
                PasswordSetupRequired = value.PasswordSetupRequired || customers.Set<Microsoft.AspNetCore.Identity.IdentityUserClaim<string>>().Any(claim =>
                    claim.UserId == value.Id && claim.ClaimType == CustomerPasswordSetupState.ClaimType
                    && claim.ClaimValue == CustomerPasswordSetupState.ClaimValue), value.LockoutEnabled, value.LockoutEnd })
            .SingleOrDefaultAsync(cancellationToken);
        if (row is null)
        {
            return new(CustomerSelfIdentityStatus.Missing);
        }

        // Recheck current customer admission rather than relying on a previously issued token.
        if (expectedCustomerId <= 0 || row.DatabaseID != expectedCustomerId || !row.EmailConfirmed || row.PasswordSetupRequired
            || (row.LockoutEnabled && row.LockoutEnd is { } lockout && lockout >= timeProvider.GetUtcNow()))
        {
            return new(CustomerSelfIdentityStatus.Forbidden);
        }

        return new(CustomerSelfIdentityStatus.Found, new(expectedCustomerId, row.Email, row.MobileNumber));
    }
}
