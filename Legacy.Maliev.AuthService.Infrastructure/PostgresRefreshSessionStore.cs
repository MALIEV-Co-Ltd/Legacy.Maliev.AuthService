using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.EntityFrameworkCore;
using System.Data;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>PostgreSQL implementation of atomic refresh-token rotation and family revocation.</summary>
public sealed class PostgresRefreshSessionStore(
    RefreshSessionDbContext dbContext,
    ILegacyIdentityReader identityReader,
    TimeProvider timeProvider) : IRefreshSessionStore
{
    /// <inheritdoc />
    public async Task CreateAsync(RefreshSession session, CancellationToken cancellationToken)
    {
        dbContext.RefreshSessions.Add(session);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<RefreshRotationResult> RotateAsync(
        string presentedHash,
        RefreshSession replacement,
        CancellationToken cancellationToken)
    {
        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        var now = timeProvider.GetUtcNow();
        var current = await dbContext.RefreshSessions
            .SingleOrDefaultAsync(x => x.TokenHash == presentedHash, cancellationToken);

        if (current is null || current.RevokedAt is not null || current.ExpiresAt <= now)
        {
            return new(RefreshRotationStatus.Invalid, null, null, null);
        }

        if (current.RotatedAt is not null)
        {
            await RevokeFamilyInternalAsync(current.FamilyId, now, cancellationToken);
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new(RefreshRotationStatus.Reused, null, null, null);
        }

        var identity = await identityReader.FindActiveAsync(
            current.IdentityId, current.IdentityKind, cancellationToken);
        if (identity is null || !string.Equals(identity.SecurityStamp, current.SecurityStamp, StringComparison.Ordinal))
        {
            await RevokeFamilyInternalAsync(current.FamilyId, now, cancellationToken);
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new(RefreshRotationStatus.Invalid, null, null, null);
        }

        replacement.FamilyId = current.FamilyId;
        replacement.IdentityId = current.IdentityId;
        replacement.IdentityKind = current.IdentityKind;
        replacement.SecurityStamp = current.SecurityStamp;
        current.RotatedAt = now;
        current.ReplacedById = replacement.Id;
        dbContext.RefreshSessions.Add(replacement);
        await dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new(RefreshRotationStatus.Succeeded, current.IdentityId, current.IdentityKind, current.SecurityStamp);
    }

    /// <inheritdoc />
    public async Task RevokeFamilyAsync(string tokenHash, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var session = await dbContext.RefreshSessions
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.TokenHash == tokenHash, cancellationToken);
        if (session is null)
        {
            return;
        }

        await RevokeFamilyInternalAsync(session.FamilyId, now, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    private Task<int> RevokeFamilyInternalAsync(Guid familyId, DateTimeOffset now, CancellationToken cancellationToken) =>
        dbContext.RefreshSessions
            .Where(x => x.FamilyId == familyId && x.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(x => x.RevokedAt, now), cancellationToken);
}