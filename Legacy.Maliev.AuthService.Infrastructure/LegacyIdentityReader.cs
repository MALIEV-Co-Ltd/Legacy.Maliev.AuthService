using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Validates ASP.NET Identity password hashes in the unchanged legacy databases.</summary>
public sealed class LegacyIdentityReader(
    CustomerIdentityDbContext customerContext,
    EmployeeIdentityDbContext employeeContext,
    IPasswordHasher<LegacyIdentityRow> passwordHasher,
    TimeProvider timeProvider) : ILegacyCredentialValidator, ILegacyIdentityReader
{
    /// <inheritdoc />
    public async Task<LegacyIdentity?> ValidateAsync(
        string userName,
        string password,
        IdentityKind kind,
        CancellationToken cancellationToken)
    {
        var normalized = userName.ToUpperInvariant();
        var user = await Users(kind)
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.NormalizedUserName == normalized, cancellationToken);

        if (!IsActive(user) || string.IsNullOrEmpty(user!.PasswordHash))
        {
            DummyPasswordVerification(password);
            return null;
        }

        var verification = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password);
        return verification is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded
            ? Project(user, kind)
            : null;
    }

    /// <inheritdoc />
    public async Task<LegacyIdentity?> FindActiveAsync(
        string identityId,
        IdentityKind kind,
        CancellationToken cancellationToken)
    {
        var user = await Users(kind)
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.Id == identityId, cancellationToken);
        return IsActive(user) ? Project(user!, kind) : null;
    }

    private IQueryable<LegacyIdentityRow> Users(IdentityKind kind) =>
        kind == IdentityKind.Customer ? customerContext.Users : employeeContext.Users;

    private bool IsActive(LegacyIdentityRow? user) =>
        user is not null && (!user.LockoutEnabled || user.LockoutEnd is null || user.LockoutEnd <= timeProvider.GetUtcNow());

    private void DummyPasswordVerification(string password)
    {
        var dummy = new LegacyIdentityRow { Id = "dummy" };
        var hash = passwordHasher.HashPassword(dummy, "constant-invalid-password");
        _ = passwordHasher.VerifyHashedPassword(dummy, hash, password);
    }

    private static LegacyIdentity Project(LegacyIdentityRow user, IdentityKind kind) =>
        new(user.Id, user.UserName ?? string.Empty, user.Email, kind, user.DatabaseID, user.SecurityStamp);
}