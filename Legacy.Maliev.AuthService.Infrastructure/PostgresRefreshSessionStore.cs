using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
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
        var intent = new RefreshSession
        {
            Id = replacement.Id,
            TokenHash = replacement.TokenHash,
            CreatedAt = NormalizeTimestamp(replacement.CreatedAt),
            ExpiresAt = NormalizeTimestamp(replacement.ExpiresAt),
            IdentityId = string.Empty,
        };
        var options = (DbContextOptions<RefreshSessionDbContext>)dbContext.GetService<IDbContextOptions>();
        var outcome = await dbContext.Database.CreateExecutionStrategy().ExecuteAsync(async token =>
        {
            await using var attempt = new RefreshSessionDbContext(options);
            return await RotateAttemptAsync(attempt, presentedHash, intent, token);
        }, cancellationToken);
        if (outcome.Replacement is { } persisted)
        {
            replacement.FamilyId = persisted.FamilyId;
            replacement.IdentityId = persisted.IdentityId;
            replacement.IdentityKind = persisted.IdentityKind;
            replacement.SecurityStamp = persisted.SecurityStamp;
        }
        return outcome.Result;
    }

    private async Task<RotationOutcome> RotateAttemptAsync(
        RefreshSessionDbContext attempt, string presentedHash, RefreshSession intent, CancellationToken cancellationToken)
    {
        var familyId = await FindFamilyAsync(attempt, presentedHash, cancellationToken);
        if (familyId is null) return Denied(RefreshRotationStatus.Invalid);
        await using var transaction = await attempt.Database.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await FenceFamilyAsync(attempt, familyId.Value, cancellationToken);
        var now = timeProvider.GetUtcNow();
        // A Serializable snapshot may predate waiting for the advisory fence. Locking
        // the original forces a serialization retry if logout changed it meanwhile,
        // including the otherwise read-only unknown-commit receipt branch.
        var current = await attempt.RefreshSessions.FromSqlInterpolated(
                $"SELECT * FROM refresh_sessions WHERE \"TokenHash\" = {presentedHash} FOR UPDATE")
            .SingleOrDefaultAsync(x => x.TokenHash == presentedHash, cancellationToken);

        if (current is null || current.FamilyId != familyId.Value || current.RevokedAt is not null || current.ExpiresAt <= now)
        {
            return Denied(RefreshRotationStatus.Invalid);
        }

        if (current.RotatedAt is not null)
        {
            var receipt = current.ReplacedById == intent.Id
                ? await attempt.RefreshSessions.AsNoTracking().SingleOrDefaultAsync(x => x.Id == intent.Id, cancellationToken)
                : null;
            if (receipt is not null && MatchesReceipt(current, receipt, intent) &&
                receipt.RevokedAt is null && receipt.ExpiresAt > now)
            {
                var active = await identityReader.FindActiveAsync(current.IdentityId, current.IdentityKind, cancellationToken);
                if (active is not null && string.Equals(active.SecurityStamp, current.SecurityStamp, StringComparison.Ordinal))
                {
                    await transaction.CommitAsync(cancellationToken);
                    return new(new(RefreshRotationStatus.Succeeded, current.IdentityId, current.IdentityKind, current.SecurityStamp), receipt);
                }
                await RevokeFamilyInternalAsync(attempt, current.FamilyId, now, cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return Denied(RefreshRotationStatus.Invalid);
            }
            await RevokeFamilyInternalAsync(attempt, current.FamilyId, now, cancellationToken);
            await attempt.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Denied(RefreshRotationStatus.Reused);
        }

        var identity = await identityReader.FindActiveAsync(
            current.IdentityId, current.IdentityKind, cancellationToken);
        if (identity is null || !string.Equals(identity.SecurityStamp, current.SecurityStamp, StringComparison.Ordinal))
        {
            await RevokeFamilyInternalAsync(attempt, current.FamilyId, now, cancellationToken);
            await attempt.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Denied(RefreshRotationStatus.Invalid);
        }

        var replacement = new RefreshSession
        {
            Id = intent.Id,
            TokenHash = intent.TokenHash,
            CreatedAt = intent.CreatedAt,
            ExpiresAt = intent.ExpiresAt,
            IdentityId = current.IdentityId,
        };
        replacement.FamilyId = current.FamilyId;
        replacement.IdentityId = current.IdentityId;
        replacement.IdentityKind = current.IdentityKind;
        replacement.SecurityStamp = current.SecurityStamp;
        current.RotatedAt = now;
        current.ReplacedById = replacement.Id;
        attempt.RefreshSessions.Add(replacement);
        await attempt.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new(new(RefreshRotationStatus.Succeeded, current.IdentityId, current.IdentityKind, current.SecurityStamp), replacement);
    }

    /// <inheritdoc />
    public async Task RevokeFamilyAsync(string tokenHash, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var options = (DbContextOptions<RefreshSessionDbContext>)dbContext.GetService<IDbContextOptions>();
        await dbContext.Database.CreateExecutionStrategy().ExecuteAsync(async token =>
        {
            await using var attempt = new RefreshSessionDbContext(options);
            var familyId = await FindFamilyAsync(attempt, tokenHash, token);
            if (familyId is null) return;
            await using var transaction = await attempt.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, token);
            await FenceFamilyAsync(attempt, familyId.Value, token);
            var authoritativeFamily = await FindFamilyAsync(attempt, tokenHash, token);
            if (authoritativeFamily == familyId)
                await RevokeFamilyInternalAsync(attempt, familyId.Value, now, token);
            await transaction.CommitAsync(token);
        }, cancellationToken);
    }

    private static Task<Guid?> FindFamilyAsync(RefreshSessionDbContext context, string tokenHash, CancellationToken cancellationToken) =>
        context.RefreshSessions.AsNoTracking().Where(x => x.TokenHash == tokenHash)
            .Select(x => (Guid?)x.FamilyId).SingleOrDefaultAsync(cancellationToken);

    private static Task<int> FenceFamilyAsync(RefreshSessionDbContext context, Guid familyId, CancellationToken cancellationToken) =>
        context.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock(hashtextextended({familyId.ToString("D")}, 0))", cancellationToken);

    private static Task<int> RevokeFamilyInternalAsync(RefreshSessionDbContext context, Guid familyId, DateTimeOffset now, CancellationToken cancellationToken) =>
        context.RefreshSessions
            .Where(x => x.FamilyId == familyId && x.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(x => x.RevokedAt, now), cancellationToken);

    private static bool MatchesReceipt(RefreshSession original, RefreshSession receipt, RefreshSession intent) =>
        receipt.Id == intent.Id &&
        string.Equals(receipt.TokenHash, intent.TokenHash, StringComparison.Ordinal) &&
        receipt.FamilyId == original.FamilyId &&
        string.Equals(receipt.IdentityId, original.IdentityId, StringComparison.Ordinal) &&
        receipt.IdentityKind == original.IdentityKind &&
        string.Equals(receipt.SecurityStamp, original.SecurityStamp, StringComparison.Ordinal) &&
        receipt.CreatedAt == intent.CreatedAt && receipt.ExpiresAt == intent.ExpiresAt;

    private static DateTimeOffset NormalizeTimestamp(DateTimeOffset value) =>
        new(value.UtcTicks - value.UtcTicks % 10, TimeSpan.Zero);

    private static RotationOutcome Denied(RefreshRotationStatus status) => new(new(status, null, null, null), null);

    private sealed record RotationOutcome(RefreshRotationResult Result, RefreshSession? Replacement);
}
