using Microsoft.EntityFrameworkCore;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Checks canonical identity-key ownership without rewriting historical keys or recovery bindings.</summary>
public static class LegacyIdentityKeyOwnership
{
    /// <summary>Returns the default Identity canonical key for a trimmed identity value.</summary>
    public static string CanonicalKey(string email) => email.Trim().Normalize().ToUpperInvariant();

    /// <summary>Serializes participating writers for every canonically equivalent email.</summary>
    public static Task<int> LockAsync(LegacyIdentityDbContext context, string email, CancellationToken cancellationToken)
    {
        if (context.Database.CurrentTransaction is null)
            throw new InvalidOperationException("Email ownership locks require an active transaction.");
        var canonical = CanonicalKey(email);
        return context.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({canonical}, 0))", cancellationToken);
    }

    /// <summary>Serializes new username ownership independently of the email partition.</summary>
    public static Task<int> LockUserNameAsync(LegacyIdentityDbContext context, string userName, CancellationToken cancellationToken)
    {
        if (context.Database.CurrentTransaction is null)
            throw new InvalidOperationException("Username ownership locks require an active transaction.");
        var canonical = "identity-username:" + CanonicalKey(userName);
        return context.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({canonical}, 3))", cancellationToken);
    }

    /// <summary>Denies retained noncanonical username collisions without changing historical rows.</summary>
    public static async Task<bool> HasOtherUserNameOwnerAsync(LegacyIdentityDbContext context, string userName,
        string? excludedIdentityId, CancellationToken cancellationToken)
    {
        var canonical = CanonicalKey(userName);
        var retained = userName.Trim().ToUpperInvariant();
        if (await context.Users.AsNoTracking().AnyAsync(row => row.Id != excludedIdentityId &&
            (row.NormalizedUserName == canonical || row.NormalizedUserName == retained), cancellationToken)) return true;
        var candidates = context.Database.SqlQuery<HistoricalKeyProjection>($"""
            SELECT "Id", "UserName" AS "RawValue", "NormalizedUserName" AS "NormalizedValue" FROM "AspNetUsers"
            WHERE "UserName" IS NOT NFC NORMALIZED OR "NormalizedUserName" IS NOT NFC NORMALIZED
                OR ("NormalizedUserName" IS NULL AND "UserName" IS NOT NULL)
            """);
        return await MatchesHistoricalOwnerAsync(candidates, canonical, excludedIdentityId, cancellationToken);
    }

    /// <summary>Finds another owner across current keys and retained noncanonical historical representations.</summary>
    public static async Task<bool> HasOtherOwnerAsync(LegacyIdentityDbContext context, string email,
        string? excludedIdentityId, CancellationToken cancellationToken)
    {
        var canonical = CanonicalKey(email);
        var retained = email.Trim().ToUpperInvariant();
        if (await context.Users.AsNoTracking().AnyAsync(row => row.Id != excludedIdentityId &&
            (row.NormalizedEmail == canonical || row.NormalizedEmail == retained), cancellationToken)) return true;

        // SQL selects noncanonical or missing-key candidates. Casing stays in .NET, never database-locale UPPER.
        // Project no credentials, stamps, or whole identity rows. Stream without retaining a historical email list.
        var candidates = context.Database.SqlQuery<HistoricalKeyProjection>($"""
            SELECT "Id", "Email" AS "RawValue", "NormalizedEmail" AS "NormalizedValue" FROM "AspNetUsers"
            WHERE "Email" IS NOT NFC NORMALIZED OR "NormalizedEmail" IS NOT NFC NORMALIZED
                OR ("NormalizedEmail" IS NULL AND "Email" IS NOT NULL)
            """);
        return await MatchesHistoricalOwnerAsync(candidates, canonical, excludedIdentityId, cancellationToken);
    }

    private static async Task<bool> MatchesHistoricalOwnerAsync(IQueryable<HistoricalKeyProjection> candidates,
        string canonical, string? excludedIdentityId, CancellationToken cancellationToken)
    {
        await foreach (var row in candidates.AsAsyncEnumerable().WithCancellation(cancellationToken))
        {
            if (row.Id == excludedIdentityId) continue;
            if (row.RawValue is not null && string.Equals(CanonicalKey(row.RawValue), canonical, StringComparison.Ordinal))
                return true;
            // A retained noncanonical key still denies a collision when the historical raw email is absent.
            if (row.NormalizedValue is not null && string.Equals(CanonicalKey(row.NormalizedValue), canonical, StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    private sealed class HistoricalKeyProjection
    {
        public string Id { get; set; } = null!;
        public string? RawValue { get; set; }
        public string? NormalizedValue { get; set; }
    }
}
