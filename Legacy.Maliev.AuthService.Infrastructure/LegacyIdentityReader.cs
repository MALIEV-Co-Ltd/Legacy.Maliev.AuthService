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
    TimeProvider timeProvider) : ILegacyCredentialValidator, ILegacyIdentityReader, IGoogleEmployeeIdentityReader
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

        if (!IsUnlocked(user) || string.IsNullOrEmpty(user!.PasswordHash))
        {
            DummyPasswordVerification(password);
            return null;
        }

        var verification = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password);
        return verification is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded
            ? Project(user, kind, password)
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
        return IsActive(user, kind) ? Project(user!, kind) : null;
    }

    /// <inheritdoc />
    public async Task<LegacyIdentity?> FindActiveEmployeeByEmailAsync(
        string email,
        CancellationToken cancellationToken)
    {
        var normalized = email.Trim().ToUpperInvariant();
        if (normalized.Length == 0)
        {
            return null;
        }

        var user = await employeeContext.Users
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.NormalizedEmail == normalized, cancellationToken);
        return IsActive(user, IdentityKind.Employee) ? Project(user!, IdentityKind.Employee) : null;
    }

    private IQueryable<LegacyIdentityRow> Users(IdentityKind kind) =>
        kind == IdentityKind.Customer ? customerContext.Users : employeeContext.Users;

    private bool IsActive(LegacyIdentityRow? user, IdentityKind kind) =>
        IsUnlocked(user)
        && (kind != IdentityKind.Customer || user!.EmailConfirmed);

    private bool IsUnlocked(LegacyIdentityRow? user) =>
        user is not null
        && (!user.LockoutEnabled || user.LockoutEnd is null || user.LockoutEnd <= timeProvider.GetUtcNow());

    private void DummyPasswordVerification(string password)
    {
        var dummy = new LegacyIdentityRow { Id = "dummy" };
        var hash = passwordHasher.HashPassword(dummy, "constant-invalid-password");
        _ = passwordHasher.VerifyHashedPassword(dummy, hash, password);
    }

    private static LegacyIdentity Project(LegacyIdentityRow user, IdentityKind kind, string? validatedPassword = null) =>
        new(
            user.Id,
            user.UserName ?? string.Empty,
            user.Email,
            kind,
            user.DatabaseID,
            user.SecurityStamp,
            kind != IdentityKind.Customer || user.EmailConfirmed,
            kind == IdentityKind.Customer && MatchesLegacyIssuedPassword(validatedPassword),
            !string.IsNullOrEmpty(user.PasswordHash));

    private static bool MatchesLegacyIssuedPassword(string? password)
    {
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@$%";
        return password?.Length == 20
            && password.All(alphabet.Contains)
            && password.Any(char.IsUpper)
            && password.Any(char.IsLower)
            && password.Any(char.IsDigit)
            && password.Any(character => !char.IsLetterOrDigit(character))
            && password.Distinct().Count() >= 6;
    }
}
