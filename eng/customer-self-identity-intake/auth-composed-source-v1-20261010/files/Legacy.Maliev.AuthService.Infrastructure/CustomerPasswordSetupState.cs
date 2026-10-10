using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Recognizes only the original customer-owned persisted temporary-password marker.</summary>
internal static class CustomerPasswordSetupState
{
    internal const string ClaimType = "maliev:credential_state";
    internal const string ClaimValue = "temporary_password";

    internal static IQueryable<IdentityUserClaim<string>> Markers(CustomerIdentityDbContext context, string identityId) =>
        context.Set<IdentityUserClaim<string>>().Where(claim => claim.UserId == identityId
            && claim.ClaimType == ClaimType && claim.ClaimValue == ClaimValue);

    internal static async Task<bool> IsRequiredAsync(CustomerIdentityDbContext context, LegacyIdentityRow row, CancellationToken token) =>
        row.PasswordSetupRequired || await Markers(context, row.Id).AnyAsync(token);

    // Stage tracked deletions for the same SaveChanges/transaction as the password and stamp update.
    internal static async Task ClearMarkersAsync(CustomerIdentityDbContext context, string identityId, CancellationToken token) =>
        context.RemoveRange(await Markers(context, identityId).ToListAsync(token));
}
