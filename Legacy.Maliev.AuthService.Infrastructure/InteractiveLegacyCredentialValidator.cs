using System.Data;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Accounts for normal password login attempts while retaining the read-only hash reader.</summary>
public sealed class InteractiveLegacyCredentialValidator(
    CustomerIdentityDbContext customers,
    EmployeeIdentityDbContext employees,
    IPasswordHasher<LegacyIdentityRow> passwordHasher,
    TimeProvider clock) : ILegacyCredentialValidator
{
    /// <inheritdoc />
    public async Task<LegacyIdentity?> ValidateAsync(
        string userName, string password, IdentityKind kind, CancellationToken cancellationToken)
    {
        // Accounting cannot be retried blindly after an uncertain commit: that would double-count.
        // Use the same selected store with a fresh non-retrying context for this bounded transaction.
        await using var context = NewAccountingContext(kind);
        var normalized = userName.ToUpperInvariant();
        await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        // Serialize attempts for this selected persisted identity across requests and service instances.
        var user = await context.Users.FromSqlInterpolated(
                $"SELECT * FROM \"AspNetUsers\" WHERE \"NormalizedUserName\" = {normalized} FOR UPDATE")
            .AsNoTracking().SingleOrDefaultAsync(cancellationToken);
        var now = clock.GetUtcNow();
        if (user is null || (user.LockoutEnabled && user.LockoutEnd >= now))
        {
            _ = LegacyIdentityReader.VerifyAndProject(null, password, kind, passwordHasher);
            return null;
        }
        // The original employee SignInManager rejects an unconfirmed account before checking its password.
        if (kind == IdentityKind.Employee && !user.EmailConfirmed) return null;

        // Verify and project this locked row without opening a second pooled database connection.
        var identity = LegacyIdentityReader.VerifyAndProject(user, password, kind, passwordHasher);
        if (identity is null)
        {
            // AccessFailedAsync records attempts even when the persisted LockoutEnabled flag is false.
            var atThreshold = user.AccessFailedCount >= 4;
            await WriteAccountingAsync(context, user.Id, atThreshold ? 0 : user.AccessFailedCount + 1,
                atThreshold ? now.AddMinutes(5) : user.LockoutEnd, cancellationToken);
        }
        else if (user.AccessFailedCount != 0 && (!user.TwoFactorEnabled || !user.EmailConfirmed))
        {
            // The unconfirmed-customer recovery helper resets on a verified password.
            // Confirmed TFA accounts retain counters: provider/remembered-client parity is a separate boundary.
            await WriteAccountingAsync(context, user.Id, 0, user.LockoutEnd, cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return identity;
    }

    private LegacyIdentityDbContext NewAccountingContext(IdentityKind kind) => kind == IdentityKind.Customer
        ? new CustomerIdentityDbContext(new DbContextOptionsBuilder<CustomerIdentityDbContext>()
            .UseNpgsql(customers.Database.GetConnectionString(), options => options.CommandTimeout(120)).Options)
        : new EmployeeIdentityDbContext(new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
            .UseNpgsql(employees.Database.GetConnectionString(), options => options.CommandTimeout(120)).Options);

    private static async Task WriteAccountingAsync(LegacyIdentityDbContext context, string id,
        int count, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
    {
        var stamp = Guid.NewGuid().ToString();
        var written = await context.Users.Where(user => user.Id == id).ExecuteUpdateAsync(update => update
            .SetProperty(user => user.AccessFailedCount, count)
            .SetProperty(user => user.LockoutEnd, lockoutEnd)
            .SetProperty(user => user.ConcurrencyStamp, stamp), cancellationToken);
        if (written != 1) throw new DbUpdateConcurrencyException("Login accounting identity is unavailable.");
    }
}
