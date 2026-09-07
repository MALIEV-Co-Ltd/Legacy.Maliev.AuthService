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
            .Select(value => new { value.DatabaseID, value.Email, value.MobileNumber, value.EmailConfirmed, value.LockoutEnabled, value.LockoutEnd })
            .SingleOrDefaultAsync(cancellationToken);
        if (row is null)
        {
            return new(CustomerSelfIdentityStatus.Missing);
        }

        // Match LegacyIdentityReader's current customer eligibility rules.
        if (expectedCustomerId <= 0 || row.DatabaseID != expectedCustomerId || !row.EmailConfirmed
            || (row.LockoutEnabled && row.LockoutEnd is { } lockout && lockout > timeProvider.GetUtcNow()))
        {
            return new(CustomerSelfIdentityStatus.Forbidden);
        }

        return new(CustomerSelfIdentityStatus.Found, new(expectedCustomerId, row.Email, row.MobileNumber));
    }
}
