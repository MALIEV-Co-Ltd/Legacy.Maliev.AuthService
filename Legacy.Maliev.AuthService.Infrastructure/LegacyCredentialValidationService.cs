using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Uses stock Identity password checks without changing the modern login validator.</summary>
public sealed class LegacyCredentialValidationService(
    CustomerIdentityDbContext customers,
    EmployeeIdentityDbContext employees,
    IPasswordHasher<LegacyIdentityRow> passwordHasher,
    IServiceProvider services) : ILegacyCredentialValidationService
{
    /// <inheritdoc />
    public async Task<LegacyCredentialValidationOutcome> ValidateAsync(
        string username, string password, IdentityKind kind, CancellationToken cancellationToken)
    {
        await using var context = OpenContext(kind);
        using var store = new ValidationStore(context, cancellationToken);
        var options = new IdentityOptions();
        options.User.RequireUniqueEmail = true;
        using var manager = new UserManager<LegacyIdentityRow>(
            store, Options.Create(options), passwordHasher, [new UserValidator<LegacyIdentityRow>()],
            [], new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), services,
            NullLogger<UserManager<LegacyIdentityRow>>.Instance);
        var user = await manager.FindByNameAsync(username);
        if (user is null) return LegacyCredentialValidationOutcome.UnknownIdentity;
        return await manager.CheckPasswordAsync(user, password)
            ? LegacyCredentialValidationOutcome.Valid
            : LegacyCredentialValidationOutcome.InvalidPassword;
    }

    private LegacyIdentityDbContext OpenContext(IdentityKind kind) => kind switch
    {
        IdentityKind.Customer => new CustomerIdentityDbContext(
            new DbContextOptionsBuilder<CustomerIdentityDbContext>()
                .UseNpgsql(customers.Database.GetConnectionString(), options => options.CommandTimeout(120)).Options),
        IdentityKind.Employee => new EmployeeIdentityDbContext(
            new DbContextOptionsBuilder<EmployeeIdentityDbContext>()
                .UseNpgsql(employees.Database.GetConnectionString(), options => options.CommandTimeout(120)).Options),
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    // This private store exists only for the two source password-check actions; it never owns DI contexts.
    private sealed class ValidationStore(LegacyIdentityDbContext context, CancellationToken requestCancellation)
        : IUserPasswordStore<LegacyIdentityRow>, IUserEmailStore<LegacyIdentityRow>, IUserSecurityStampStore<LegacyIdentityRow>
    {
        public void Dispose() { }
        private CancellationToken Cancellation(CancellationToken cancellation)
        {
            cancellation.ThrowIfCancellationRequested();
            requestCancellation.ThrowIfCancellationRequested();
            return requestCancellation;
        }

        public Task<LegacyIdentityRow?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken) =>
            context.Users.AsNoTracking().FirstOrDefaultAsync(user => user.NormalizedUserName == normalizedUserName, Cancellation(cancellationToken));
        public Task<LegacyIdentityRow?> FindByIdAsync(string userId, CancellationToken cancellationToken) =>
            context.Users.AsNoTracking().FirstOrDefaultAsync(user => user.Id == userId, Cancellation(cancellationToken));
        public Task<LegacyIdentityRow?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken) =>
            context.Users.AsNoTracking().SingleOrDefaultAsync(user => user.NormalizedEmail == normalizedEmail, Cancellation(cancellationToken));

        public async Task<IdentityResult> UpdateAsync(LegacyIdentityRow user, CancellationToken cancellationToken)
        {
            var cancellation = Cancellation(cancellationToken);
            var expectedVersion = user.ConcurrencyStamp;
            var nextVersion = Guid.NewGuid().ToString();
            // A failed optimistic update remains an IdentityResult, which stock CheckPasswordAsync intentionally ignores.
            var written = await context.Users.Where(value => value.Id == user.Id && value.ConcurrencyStamp == expectedVersion)
                .ExecuteUpdateAsync(update => update
                    .SetProperty(value => value.PasswordHash, user.PasswordHash)
                    .SetProperty(value => value.SecurityStamp, user.SecurityStamp)
                    .SetProperty(value => value.NormalizedUserName, user.NormalizedUserName)
                    .SetProperty(value => value.NormalizedEmail, user.NormalizedEmail)
                    .SetProperty(value => value.ConcurrencyStamp, nextVersion), cancellation);
            user.ConcurrencyStamp = nextVersion;
            return written == 1 ? IdentityResult.Success
                : IdentityResult.Failed(new IdentityErrorDescriber().ConcurrencyFailure());
        }

        public Task<IdentityResult> CreateAsync(LegacyIdentityRow user, CancellationToken cancellationToken) =>
            throw new NotSupportedException("The validation store cannot create identities.");
        public Task<IdentityResult> DeleteAsync(LegacyIdentityRow user, CancellationToken cancellationToken) =>
            throw new NotSupportedException("The validation store cannot delete identities.");

        public Task<string> GetUserIdAsync(LegacyIdentityRow user, CancellationToken cancellationToken)
        { Cancellation(cancellationToken); return Task.FromResult(user.Id); }
        public Task<string?> GetUserNameAsync(LegacyIdentityRow user, CancellationToken cancellationToken)
        { Cancellation(cancellationToken); return Task.FromResult(user.UserName); }
        public Task SetUserNameAsync(LegacyIdentityRow user, string? userName, CancellationToken cancellationToken)
        { Cancellation(cancellationToken); user.UserName = userName; return Task.CompletedTask; }
        public Task<string?> GetNormalizedUserNameAsync(LegacyIdentityRow user, CancellationToken cancellationToken)
        { Cancellation(cancellationToken); return Task.FromResult(user.NormalizedUserName); }
        public Task SetNormalizedUserNameAsync(LegacyIdentityRow user, string? normalizedName, CancellationToken cancellationToken)
        { Cancellation(cancellationToken); user.NormalizedUserName = normalizedName; return Task.CompletedTask; }
        public Task SetPasswordHashAsync(LegacyIdentityRow user, string? passwordHash, CancellationToken cancellationToken)
        { Cancellation(cancellationToken); user.PasswordHash = passwordHash; return Task.CompletedTask; }
        public Task<string?> GetPasswordHashAsync(LegacyIdentityRow user, CancellationToken cancellationToken)
        { Cancellation(cancellationToken); return Task.FromResult(user.PasswordHash); }
        public Task<bool> HasPasswordAsync(LegacyIdentityRow user, CancellationToken cancellationToken)
        { Cancellation(cancellationToken); return Task.FromResult(user.PasswordHash is not null); }
        public Task SetEmailAsync(LegacyIdentityRow user, string? email, CancellationToken cancellationToken)
        { Cancellation(cancellationToken); user.Email = email; return Task.CompletedTask; }
        public Task<string?> GetEmailAsync(LegacyIdentityRow user, CancellationToken cancellationToken)
        { Cancellation(cancellationToken); return Task.FromResult(user.Email); }
        public Task<bool> GetEmailConfirmedAsync(LegacyIdentityRow user, CancellationToken cancellationToken)
        { Cancellation(cancellationToken); return Task.FromResult(user.EmailConfirmed); }
        public Task SetEmailConfirmedAsync(LegacyIdentityRow user, bool confirmed, CancellationToken cancellationToken)
        { Cancellation(cancellationToken); user.EmailConfirmed = confirmed; return Task.CompletedTask; }
        public Task<string?> GetNormalizedEmailAsync(LegacyIdentityRow user, CancellationToken cancellationToken)
        { Cancellation(cancellationToken); return Task.FromResult(user.NormalizedEmail); }
        public Task SetNormalizedEmailAsync(LegacyIdentityRow user, string? normalizedEmail, CancellationToken cancellationToken)
        { Cancellation(cancellationToken); user.NormalizedEmail = normalizedEmail; return Task.CompletedTask; }
        public Task SetSecurityStampAsync(LegacyIdentityRow user, string stamp, CancellationToken cancellationToken)
        { Cancellation(cancellationToken); user.SecurityStamp = stamp; return Task.CompletedTask; }
        public Task<string?> GetSecurityStampAsync(LegacyIdentityRow user, CancellationToken cancellationToken)
        { Cancellation(cancellationToken); return Task.FromResult(user.SecurityStamp); }
    }
}
