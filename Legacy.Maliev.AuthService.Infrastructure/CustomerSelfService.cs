using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Owns customer registration, confirmation, and recovery without changing the legacy schema.</summary>
public sealed class CustomerSelfService(CustomerIdentityDbContext customers, RefreshSessionDbContext state, IPasswordHasher<LegacyIdentityRow> passwordHasher, TimeProvider timeProvider)
{
    private const string EmailConfirmation = "email-confirmation";
    private const string PasswordReset = "password-reset";
    private static readonly TimeSpan ActionLifetime = TimeSpan.FromHours(24);

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
    /// <summary>Confirms an email using a single-use challenge.</summary>
    public async Task<bool> ConfirmEmailAsync(CompleteCustomerActionRequest request, CancellationToken cancellationToken)
    {
        var row = await FindAsync(request.Email, cancellationToken);
        if (row is null || !await ConsumeAsync(row.Id, EmailConfirmation, request.Token, cancellationToken))
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
        var row = await FindAsync(request.Email, cancellationToken);
        if (row is null || !await ConsumeAsync(row.Id, PasswordReset, request.Token, cancellationToken))
        {
            return false;
        }

        row.PasswordHash = passwordHasher.HashPassword(row, request.Password);
        row.AccessFailedCount = 0;
        row.LockoutEnd = null;
        RotateSecurityStamp(row);
        await customers.SaveChangesAsync(cancellationToken);
        return true;
    }

    private async Task<CustomerActionChallenge> CreateChallengeAsync(string email, string purpose, bool requireUnconfirmed, CancellationToken cancellationToken)
    {
        var row = await FindAsync(email, cancellationToken);
        if (row is null || (requireUnconfirmed && row.EmailConfirmed))
        {
            return new(true, null);
        }

        var token = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var now = timeProvider.GetUtcNow();
        await SupersedeActiveChallengesAsync(row.Id, purpose, now, cancellationToken);
        state.IdentityActionTokens.Add(new()
        {
            Id = Guid.NewGuid(),
            IdentityId = row.Id,
            Purpose = purpose,
            TokenHash = Hash(token),
            CreatedAt = now,
            ExpiresAt = now.Add(ActionLifetime),
        });
        await state.SaveChangesAsync(cancellationToken);
        return new(true, token);
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
    private async Task<bool> ConsumeAsync(string identityId, string purpose, string token, CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var hash = Hash(token);
        var query = state.IdentityActionTokens.Where(value =>
            value.IdentityId == identityId
            && value.Purpose == purpose
            && value.TokenHash == hash
            && value.ConsumedAt == null
            && value.ExpiresAt > now);
        if (state.Database.IsRelational())
        {
            return await query.ExecuteUpdateAsync(
                setters => setters.SetProperty(value => value.ConsumedAt, now),
                cancellationToken) == 1;
        }

        var action = await query.SingleOrDefaultAsync(cancellationToken);
        if (action is null)
        {
            return false;
        }

        action.ConsumedAt = now;
        await state.SaveChangesAsync(cancellationToken);
        return true;
    }
    private static string Hash(string token) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    private static void RotateSecurityStamp(LegacyIdentityRow row)
    {
        row.SecurityStamp = Guid.NewGuid().ToString();
        row.ConcurrencyStamp = Guid.NewGuid().ToString();
    }
}