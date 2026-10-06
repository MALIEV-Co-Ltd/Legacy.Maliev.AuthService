using Legacy.Maliev.AuthService.Application;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Administers employee identities without changing the legacy ASP.NET Identity schema.</summary>
public sealed class EmployeeIdentityAdminService(
    EmployeeIdentityDbContext dbContext,
    IPasswordHasher<LegacyIdentityRow> passwordHasher,
    EmployeeRecoveryOptions? recoveryOptions = null) : IEmployeeIdentityAdminService
{
    /// <inheritdoc />
    public async Task<EmployeeIdentityResponse?> CreateAsync(
        int databaseId,
        CreateEmployeeIdentityRequest request,
        CancellationToken cancellationToken)
    {
        if (!AdministrativePasswordPolicy.Accepts(request.Password)) return null;

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
        return await MutateAsync(databaseId, (context, user) =>
        {
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
        }, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(int databaseId, CancellationToken cancellationToken)
    {
        return await MutateAsync(databaseId, (context, user) => context.Users.Remove(user), cancellationToken);
    }

    private async Task<bool> MutateAsync(int databaseId, Action<EmployeeIdentityDbContext, LegacyIdentityRow> mutation, CancellationToken cancellationToken)
    {
        if (recoveryOptions?.Enabled != true) throw new EmployeeRecoveryUnavailableException();
        try
        {
            return await dbContext.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
            {
                await using var fresh = new EmployeeIdentityDbContext((DbContextOptions<EmployeeIdentityDbContext>)dbContext.GetService<IDbContextOptions>());
                await EmployeeRecoverySchema.EnsureEmployeeAsync(fresh, cancellationToken);
                await using var transaction = await fresh.Database.BeginTransactionAsync(cancellationToken);
                var user = await fresh.Users.FromSqlInterpolated($"SELECT * FROM \"AspNetUsers\" WHERE \"DatabaseID\" = {databaseId} FOR UPDATE").SingleOrDefaultAsync(cancellationToken);
                if (user is null) return false;
                // Identity lock MUST precede this employee-local intent/receipt read. Never acquire an Auth lock here.
                if (await fresh.RecoveryEffects.AnyAsync(x => x.IdentityId == user.Id && x.FinalizedAcknowledgedAt == null, cancellationToken)) throw new EmployeeRecoveryUnavailableException();
                mutation(fresh, user);
                await fresh.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return true;
            });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (EmployeeRecoveryUnavailableException) { throw; }
        catch { throw new EmployeeRecoveryUnavailableException(); }
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
