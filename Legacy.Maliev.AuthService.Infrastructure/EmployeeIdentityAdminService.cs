using Legacy.Maliev.AuthService.Application;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Administers employee identities without changing the legacy ASP.NET Identity schema.</summary>
public sealed class EmployeeIdentityAdminService(
    EmployeeIdentityDbContext dbContext,
    IPasswordHasher<LegacyIdentityRow> passwordHasher) : IEmployeeIdentityAdminService
{
    /// <inheritdoc />
    public async Task<EmployeeIdentityResponse?> CreateAsync(
        int databaseId,
        CreateEmployeeIdentityRequest request,
        CancellationToken cancellationToken)
    {
        var normalizedUserName = request.UserName.Trim().ToUpperInvariant();
        var normalizedEmail = request.Email.Trim().ToUpperInvariant();
        var exists = await dbContext.Users.AnyAsync(
            user => user.DatabaseID == databaseId ||
                user.NormalizedUserName == normalizedUserName ||
                user.NormalizedEmail == normalizedEmail,
            cancellationToken);
        if (exists)
        {
            return null;
        }

        var user = new LegacyIdentityRow
        {
            Id = Guid.NewGuid().ToString(),
            DatabaseID = databaseId,
            UserName = request.UserName.Trim(),
            NormalizedUserName = normalizedUserName,
            Email = request.Email.Trim(),
            NormalizedEmail = normalizedEmail,
            EmailConfirmed = request.EmailConfirmed,
            PhoneNumber = request.PhoneNumber,
            PhoneNumberConfirmed = false,
            TwoFactorEnabled = false,
            LockoutEnabled = true,
            AccessFailedCount = 0,
            SecurityStamp = Guid.NewGuid().ToString(),
            ConcurrencyStamp = Guid.NewGuid().ToString(),
        };
        user.PasswordHash = passwordHasher.HashPassword(user, request.Password);
        dbContext.Users.Add(user);
        await dbContext.SaveChangesAsync(cancellationToken);
        return Project(user);
    }

    /// <inheritdoc />
    public async Task<EmployeeIdentityResponse?> GetAsync(int databaseId, CancellationToken cancellationToken)
    {
        var user = await dbContext.Users.AsNoTracking()
            .SingleOrDefaultAsync(value => value.DatabaseID == databaseId, cancellationToken);
        return user is null ? null : Project(user);
    }

    /// <inheritdoc />
    public async Task<bool> UpdateAsync(
        int databaseId,
        UpdateEmployeeIdentityRequest request,
        CancellationToken cancellationToken)
    {
        var user = await dbContext.Users.SingleOrDefaultAsync(
            value => value.DatabaseID == databaseId, cancellationToken);
        if (user is null)
        {
            return false;
        }

        user.UserName = request.UserName.Trim();
        user.NormalizedUserName = user.UserName.ToUpperInvariant();
        user.Email = request.Email.Trim();
        user.NormalizedEmail = user.Email.ToUpperInvariant();
        user.EmailConfirmed = request.EmailConfirmed;
        user.PhoneNumber = request.PhoneNumber;
        user.PhoneNumberConfirmed = request.PhoneNumberConfirmed;
        user.TwoFactorEnabled = request.TwoFactorEnabled;
        user.LockoutEnd = request.LockoutEnd;
        user.LockoutEnabled = request.LockoutEnabled;
        user.SecurityStamp = Guid.NewGuid().ToString();
        user.ConcurrencyStamp = Guid.NewGuid().ToString();
        await dbContext.SaveChangesAsync(cancellationToken);
        return true;
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(int databaseId, CancellationToken cancellationToken)
    {
        var user = await dbContext.Users.SingleOrDefaultAsync(
            value => value.DatabaseID == databaseId, cancellationToken);
        if (user is null)
        {
            return false;
        }

        dbContext.Users.Remove(user);
        await dbContext.SaveChangesAsync(cancellationToken);
        return true;
    }

    private static EmployeeIdentityResponse Project(LegacyIdentityRow user) => new(
        user.Id,
        user.UserName,
        user.Email,
        user.EmailConfirmed,
        user.PhoneNumber,
        user.PhoneNumberConfirmed,
        user.TwoFactorEnabled,
        user.LockoutEnd,
        user.LockoutEnabled,
        user.AccessFailedCount,
        user.DatabaseID ?? 0);
}
