using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Owns customer registration, confirmation, and recovery without changing the legacy schema.</summary>
public sealed class CustomerSelfService(CustomerIdentityDbContext customers, RefreshSessionDbContext state, IPasswordHasher<LegacyIdentityRow> passwordHasher, TimeProvider timeProvider) : ICustomerLoginActionLifecycle
{
    private const string EmailConfirmation = "email-confirmation";
    private const string EmailChange = "email-change";
    private const string PasswordReset = "password-reset";
    private const string InitialPassword = "initial-password";
    private const string EmailConfirmationRecovery = "email-confirmation-recovery";
    private static readonly TimeSpan ActionLifetime = TimeSpan.FromHours(24);
    private static readonly TimeSpan LoginActionLifetime = TimeSpan.FromMinutes(15);

    /// <summary>Creates an unconfirmed customer identity.</summary>
    public async Task<CustomerSelfServiceResult> RegisterAsync(RegisterCustomerIdentityRequest request, CancellationToken cancellationToken)
    {
        var email = request.Email.Trim();
        var normalized = email.ToUpperInvariant();
        var exists = await customers.Users.AnyAsync(
            value => value.DatabaseID == request.DatabaseId
                || value.NormalizedEmail == normalized
                || value.NormalizedUserName == normalized,
            cancellationToken);
        if (exists)
        {
            return new(false, null, null, null);
        }

        var row = new LegacyIdentityRow
        {
            Id = Guid.NewGuid().ToString(),
            DatabaseID = request.DatabaseId,
            UserName = email,
            NormalizedUserName = normalized,
            Email = email,
            NormalizedEmail = normalized,
            EmailConfirmed = false,
            PhoneNumberConfirmed = false,
            TwoFactorEnabled = false,
            LockoutEnabled = true,
            AccessFailedCount = 0,
            SecurityStamp = Guid.NewGuid().ToString(),
            ConcurrencyStamp = Guid.NewGuid().ToString(),
        };
        row.PasswordHash = passwordHasher.HashPassword(row, request.Password);
        customers.Users.Add(row);
        await customers.SaveChangesAsync(cancellationToken);
        return new(true, row.Id, row.DatabaseID, row.Email);
    }

    /// <summary>Creates a confirmation challenge for a known unconfirmed identity.</summary>
    public Task<CustomerActionChallenge> RequestEmailConfirmationAsync(CustomerActionRequest request, CancellationToken cancellationToken) => CreateChallengeAsync(request.Email, EmailConfirmation, requireUnconfirmed: true, cancellationToken);
    /// <summary>Creates a reset challenge without revealing missing identities to the public caller.</summary>
    public Task<CustomerActionChallenge> RequestPasswordResetAsync(CustomerActionRequest request, CancellationToken cancellationToken) => CreateChallengeAsync(request.Email, PasswordReset, requireUnconfirmed: false, cancellationToken);

    /// <inheritdoc />
    public async Task<string?> IssueInitialPasswordChallengeAsync(
        string identityId,
        string email,
        string securityStamp,
        CancellationToken cancellationToken) =>
        (await CreateSecurityStampBoundChallengeAsync(
            identityId,
            InitialPassword,
            email,
            securityStamp,
            cancellationToken,
            LoginActionLifetime)).Token;

    /// <inheritdoc />
    public async Task<string?> IssueEmailConfirmationRecoveryAsync(
        string identityId,
        string email,
        string securityStamp,
        CancellationToken cancellationToken) =>
        (await CreateSecurityStampBoundChallengeAsync(
            identityId,
            EmailConfirmationRecovery,
            email,
            securityStamp,
            cancellationToken,
            LoginActionLifetime)).Token;

    /// <summary>Consumes a credential-validated resend grant and returns a fresh confirmation challenge.</summary>
    public async Task<CustomerActionChallenge> RecoverEmailConfirmationAsync(
        CompleteCustomerActionRequest request,
        CancellationToken cancellationToken)
    {
        var recovery = await FindSecurityStampBoundActionAsync(
            EmailConfirmationRecovery,
            request.Email,
            request.Token,
            cancellationToken);
        if (recovery is null || !await TryConsumeAsync(recovery, cancellationToken))
        {
            return new(false, null);
        }

        var row = await customers.Users.AsNoTracking().SingleOrDefaultAsync(
            value => value.Id == recovery.IdentityId,
            cancellationToken);
        if (row is null || row.EmailConfirmed || string.IsNullOrWhiteSpace(row.Email))
        {
            return new(false, null);
        }

        return await CreateChallengeForIdentityAsync(
            row.Id,
            EmailConfirmation,
            row.Email,
            cancellationToken);
    }

    /// <summary>Replaces an issued temporary password through a single-use login challenge.</summary>
    public async Task<bool> CompleteInitialPasswordAsync(
        CompleteInitialPasswordRequest request,
        CancellationToken cancellationToken)
    {
        var action = await FindSecurityStampBoundActionAsync(
            InitialPassword,
            request.Email,
            request.Token,
            cancellationToken);
        if (action is null)
        {
            return false;
        }

        var row = await customers.Users.SingleOrDefaultAsync(
            value => value.Id == action.IdentityId,
            cancellationToken);
        if (row is null || !row.EmailConfirmed || !EmailMatches(row.Email, request.Email))
        {
            return false;
        }

        if (!await TryConsumeAsync(action, cancellationToken))
        {
            return false;
        }

        row.PasswordHash = passwordHasher.HashPassword(row, request.Password);
        row.AccessFailedCount = 0;
        row.LockoutEnd = null;
        RotateSecurityStamp(row);
        await customers.SaveChangesAsync(cancellationToken);
        await RevokeRefreshSessionsAsync(row.Id, cancellationToken);
        await SupersedeActiveChallengesAsync(row.Id, InitialPassword, timeProvider.GetUtcNow(), cancellationToken);
        return true;
    }
    /// <summary>Confirms an email using a single-use challenge.</summary>
    public async Task<bool> ConfirmEmailAsync(CompleteCustomerActionRequest request, CancellationToken cancellationToken)
    {
        var action = await FindActionAsync(EmailConfirmation, request.Email, request.Token, cancellationToken);
        if (action is null)
        {
            return false;
        }

        var row = await customers.Users.SingleOrDefaultAsync(
            value => value.Id == action.IdentityId,
            cancellationToken);
        if (row is null || !EmailMatches(row.Email, request.Email))
        {
            return false;
        }

        if (!await TryConsumeAsync(action, cancellationToken))
        {
            return false;
        }

        row.EmailConfirmed = true;
        RotateSecurityStamp(row);
        await customers.SaveChangesAsync(cancellationToken);
        return true;
    }
    /// <summary>Replaces a password using a single-use challenge.</summary>
    public async Task<bool> CompletePasswordResetAsync(CompletePasswordResetRequest request, CancellationToken cancellationToken)
    {
        var action = await FindActionAsync(PasswordReset, request.Email, request.Token, cancellationToken);
        if (action is null)
        {
            return false;
        }

        var row = await customers.Users.SingleOrDefaultAsync(
            value => value.Id == action.IdentityId,
            cancellationToken);
        if (row is null)
        {
            return false;
        }

        if (!await TryConsumeAsync(action, cancellationToken))
        {
            return false;
        }

        row.PasswordHash = passwordHasher.HashPassword(row, request.Password);
        row.AccessFailedCount = 0;
        row.LockoutEnd = null;
        RotateSecurityStamp(row);
        await customers.SaveChangesAsync(cancellationToken);
        await SupersedeActiveChallengesAsync(row.Id, InitialPassword, timeProvider.GetUtcNow(), cancellationToken);
        return true;
    }

    /// <summary>Changes an authenticated customer's email after current-password verification.</summary>
    public async Task<CustomerActionChallenge?> ChangeEmailAsync(
        string identityId,
        ChangeCustomerEmailRequest request,
        CancellationToken cancellationToken)
    {
        var row = await customers.Users.SingleOrDefaultAsync(
            value => value.Id == identityId,
            cancellationToken);
        if (row?.PasswordHash is null)
        {
            return null;
        }

        var verification = passwordHasher.VerifyHashedPassword(row, row.PasswordHash, request.CurrentPassword);
        if (verification == PasswordVerificationResult.Failed)
        {
            return null;
        }

        var email = request.NewEmail.Trim();
        var normalized = email.ToUpperInvariant();
        if (string.Equals(row.NormalizedEmail, normalized, StringComparison.Ordinal))
        {
            return null;
        }
        if (await customers.Users.AnyAsync(
            value => value.Id != identityId
                && (value.NormalizedEmail == normalized || value.NormalizedUserName == normalized),
            cancellationToken))
        {
            return null;
        }

        var challenge = await CreateChallengeForIdentityAsync(
            row.Id,
            EmailChange,
            email,
            cancellationToken);
        if (verification == PasswordVerificationResult.SuccessRehashNeeded)
        {
            row.PasswordHash = passwordHasher.HashPassword(row, request.CurrentPassword);
        }

        await customers.SaveChangesAsync(cancellationToken);
        return challenge;
    }

    /// <summary>Validates a pending email change without consuming its single-use challenge.</summary>
    public async Task<CustomerEmailChangeValidation?> ValidateEmailChangeAsync(
        CompleteCustomerActionRequest request,
        CancellationToken cancellationToken)
    {
        var action = await FindEmailChangeActionAsync(request, cancellationToken);
        if (action is null || string.IsNullOrWhiteSpace(action.TargetEmail))
        {
            return null;
        }

        var row = await customers.Users.AsNoTracking().SingleOrDefaultAsync(
            value => value.Id == action.IdentityId,
            cancellationToken);
        return row is null
            || row.DatabaseID is not > 0
            || string.IsNullOrWhiteSpace(row.Email)
            ? null
            : new CustomerEmailChangeValidation(
                row.DatabaseID.Value,
                row.Email,
                action.TargetEmail,
                action.ConsumedAt is not null);
    }

    /// <summary>Consumes a pending email change and rotates the identity security state.</summary>
    public async Task<bool> CompleteEmailChangeAsync(
        CompleteCustomerActionRequest request,
        CancellationToken cancellationToken)
    {
        var action = await FindActionAsync(EmailChange, request.Email, request.Token, cancellationToken);
        if (action is null || string.IsNullOrWhiteSpace(action.TargetEmail))
        {
            return false;
        }

        var row = await customers.Users.SingleOrDefaultAsync(
            value => value.Id == action.IdentityId,
            cancellationToken);
        if (row is null)
        {
            return false;
        }

        var normalized = action.TargetEmail.ToUpperInvariant();
        if (await customers.Users.AnyAsync(
            value => value.Id != row.Id
                && (value.NormalizedEmail == normalized || value.NormalizedUserName == normalized),
                cancellationToken))
        {
            return false;
        }

        if (!await TryConsumeAsync(action, cancellationToken))
        {
            return false;
        }

        row.Email = action.TargetEmail;
        row.NormalizedEmail = normalized;
        row.UserName = action.TargetEmail;
        row.NormalizedUserName = normalized;
        row.EmailConfirmed = true;
        RotateSecurityStamp(row);
        await customers.SaveChangesAsync(cancellationToken);
        await RevokeRefreshSessionsAsync(row.Id, cancellationToken);
        await SupersedeActiveChallengesAsync(row.Id, InitialPassword, timeProvider.GetUtcNow(), cancellationToken);
        return true;
    }

    /// <summary>Changes an authenticated customer's password and revokes all refresh sessions.</summary>
    public async Task<bool> ChangePasswordAsync(
        string identityId,
        ChangeCustomerPasswordRequest request,
        CancellationToken cancellationToken)
    {
        var row = await customers.Users.SingleOrDefaultAsync(
            value => value.Id == identityId,
            cancellationToken);
        if (row?.PasswordHash is null
            || passwordHasher.VerifyHashedPassword(row, row.PasswordHash, request.CurrentPassword)
                == PasswordVerificationResult.Failed)
        {
            return false;
        }

        row.PasswordHash = passwordHasher.HashPassword(row, request.NewPassword);
        row.AccessFailedCount = 0;
        row.LockoutEnd = null;
        RotateSecurityStamp(row);
        await customers.SaveChangesAsync(cancellationToken);
        await RevokeRefreshSessionsAsync(row.Id, cancellationToken);
        await SupersedeActiveChallengesAsync(row.Id, InitialPassword, timeProvider.GetUtcNow(), cancellationToken);
        return true;
    }

    private async Task<CustomerActionChallenge> CreateChallengeAsync(string email, string purpose, bool requireUnconfirmed, CancellationToken cancellationToken)
    {
        var row = await FindAsync(email, cancellationToken);
        if (row is null || (requireUnconfirmed && row.EmailConfirmed))
        {
            return new(true, null);
        }

        return string.IsNullOrWhiteSpace(row.Email)
            ? new CustomerActionChallenge(true, null)
            : await CreateChallengeForIdentityAsync(row.Id, purpose, row.Email, cancellationToken);
    }

    private async Task<CustomerActionChallenge> CreateChallengeForIdentityAsync(
        string identityId,
        string purpose,
        string targetEmail,
        CancellationToken cancellationToken,
        TimeSpan? lifetime = null)
    {
        var token = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var now = timeProvider.GetUtcNow();
        await SupersedeActiveChallengesAsync(identityId, purpose, now, cancellationToken);
        state.IdentityActionTokens.Add(new()
        {
            Id = Guid.NewGuid(),
            IdentityId = identityId,
            Purpose = purpose,
            TargetEmail = targetEmail.Trim(),
            TokenHash = Hash(token),
            CreatedAt = now,
            ExpiresAt = now.Add(lifetime ?? ActionLifetime),
        });
        await state.SaveChangesAsync(cancellationToken);
        return new(true, token);
    }

    private async Task<CustomerActionChallenge> CreateSecurityStampBoundChallengeAsync(
        string identityId,
        string purpose,
        string targetEmail,
        string securityStamp,
        CancellationToken cancellationToken,
        TimeSpan lifetime)
    {
        var token = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var now = timeProvider.GetUtcNow();
        await SupersedeActiveChallengesAsync(identityId, purpose, now, cancellationToken);
        state.IdentityActionTokens.Add(new()
        {
            Id = Guid.NewGuid(),
            IdentityId = identityId,
            Purpose = purpose,
            TargetEmail = targetEmail.Trim(),
            TokenHash = HashBoundToken(token, securityStamp),
            CreatedAt = now,
            ExpiresAt = now.Add(lifetime),
        });
        await state.SaveChangesAsync(cancellationToken);
        return new(true, token);
    }

    private async Task RevokeRefreshSessionsAsync(string identityId, CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var active = state.RefreshSessions.Where(value =>
            value.IdentityId == identityId
            && value.RevokedAt == null);
        if (state.Database.IsRelational())
        {
            await active.ExecuteUpdateAsync(
                setters => setters.SetProperty(value => value.RevokedAt, now),
                cancellationToken);
            return;
        }

        foreach (var session in await active.ToListAsync(cancellationToken))
        {
            session.RevokedAt = now;
        }

        await state.SaveChangesAsync(cancellationToken);
    }

    private async Task SupersedeActiveChallengesAsync(
        string identityId,
        string purpose,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var active = state.IdentityActionTokens.Where(value =>
            value.IdentityId == identityId
            && value.Purpose == purpose
            && value.ConsumedAt == null);
        if (state.Database.IsRelational())
        {
            await active.ExecuteUpdateAsync(
                setters => setters.SetProperty(value => value.ConsumedAt, now),
                cancellationToken);
            return;
        }

        foreach (var challenge in await active.ToListAsync(cancellationToken))
        {
            challenge.ConsumedAt = now;
        }
    }

    private Task<LegacyIdentityRow?> FindAsync(string email, CancellationToken cancellationToken)
    {
        var normalized = email.Trim().ToUpperInvariant();
        return customers.Users.SingleOrDefaultAsync(
            value => value.NormalizedEmail == normalized,
            cancellationToken);
    }
    private async Task<IdentityActionToken?> FindActionAsync(
        string purpose,
        string email,
        string token,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var hash = Hash(token);
        var action = await state.IdentityActionTokens.AsNoTracking().SingleOrDefaultAsync(value =>
            value.Purpose == purpose
            && value.TokenHash == hash
            && value.ConsumedAt == null
            && value.ExpiresAt > now,
            cancellationToken);
        if (action is null || EmailMatches(action.TargetEmail, email))
        {
            return action;
        }

        if (!string.IsNullOrWhiteSpace(action.TargetEmail))
        {
            return null;
        }

        var identity = await customers.Users.AsNoTracking().SingleOrDefaultAsync(
            value => value.Id == action.IdentityId,
            cancellationToken);
        return identity is not null && EmailMatches(identity.Email, email)
            ? action
            : null;
    }

    private async Task<IdentityActionToken?> FindEmailChangeActionAsync(
        CompleteCustomerActionRequest request,
        CancellationToken cancellationToken)
    {
        var action = await state.IdentityActionTokens.AsNoTracking().SingleOrDefaultAsync(value =>
            value.Purpose == EmailChange
            && value.TokenHash == Hash(request.Token),
            cancellationToken);
        if (action is null || !EmailMatches(action.TargetEmail, request.Email))
        {
            return null;
        }

        if (action.ConsumedAt is not null)
        {
            var completedIdentity = await customers.Users.AsNoTracking().SingleOrDefaultAsync(
                value => value.Id == action.IdentityId,
                cancellationToken);
            return completedIdentity is not null
                && action.TargetEmail is not null
                && EmailMatches(completedIdentity.Email, action.TargetEmail)
                ? action
                : null;
        }

        return action.ExpiresAt > timeProvider.GetUtcNow() ? action : null;
    }

    private async Task<IdentityActionToken?> FindSecurityStampBoundActionAsync(
        string purpose,
        string email,
        string token,
        CancellationToken cancellationToken)
    {
        var identity = await FindAsync(email, cancellationToken);
        if (identity is null || string.IsNullOrWhiteSpace(identity.SecurityStamp))
        {
            return null;
        }

        var now = timeProvider.GetUtcNow();
        return await state.IdentityActionTokens.AsNoTracking().SingleOrDefaultAsync(value =>
            value.IdentityId == identity.Id
            && value.Purpose == purpose
            && value.TokenHash == HashBoundToken(token, identity.SecurityStamp)
            && value.ConsumedAt == null
            && value.ExpiresAt > now,
            cancellationToken);
    }

    private async Task<bool> TryConsumeAsync(
        IdentityActionToken action,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var query = state.IdentityActionTokens.Where(value =>
            value.Id == action.Id
            && value.ConsumedAt == null
            && value.ExpiresAt > now);
        if (state.Database.IsRelational())
        {
            return await query.ExecuteUpdateAsync(
                setters => setters.SetProperty(value => value.ConsumedAt, now),
                cancellationToken) == 1;
        }

        var stored = await query.SingleOrDefaultAsync(cancellationToken);
        if (stored is null)
        {
            return false;
        }

        stored.ConsumedAt = now;
        await state.SaveChangesAsync(cancellationToken);
        return true;
    }
    private static bool EmailMatches(string? actual, string expected) =>
        !string.IsNullOrWhiteSpace(actual)
        && string.Equals(actual.Trim(), expected.Trim(), StringComparison.OrdinalIgnoreCase);
    private static string Hash(string token) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    private static string HashBoundToken(string token, string securityStamp) => Hash($"{token}:{securityStamp}");
    private static void RotateSecurityStamp(LegacyIdentityRow row)
    {
        row.SecurityStamp = Guid.NewGuid().ToString();
        row.ConcurrencyStamp = Guid.NewGuid().ToString();
    }
}
