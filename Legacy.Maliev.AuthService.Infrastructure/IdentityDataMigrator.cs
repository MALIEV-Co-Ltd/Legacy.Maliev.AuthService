using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Result of a complete source-to-destination identity comparison.</summary>
/// <param name="SourceCount">Number of source rows.</param>
/// <param name="DestinationCount">Number of destination rows.</param>
/// <param name="Fingerprint">Deterministic SHA-256 fingerprint shared by both stores.</param>
public sealed record IdentityMigrationReport(long SourceCount, long DestinationCount, string Fingerprint);

/// <summary>Copies unchanged identity rows into PostgreSQL and proves semantic equivalence.</summary>
public static class IdentityDataMigrator
{
    private const int BatchSize = 500;

    /// <summary>Rejects a SQL Server source unless its connection explicitly requests a read-only replica.</summary>
    public static void EnsureReadOnlySqlServerSource(string connectionString)
    {
        var builder = new SqlConnectionStringBuilder(connectionString);
        if (builder.ApplicationIntent != ApplicationIntent.ReadOnly)
        {
            throw new InvalidOperationException(
                "The legacy SQL Server source must specify ApplicationIntent=ReadOnly. Source writes are forbidden.");
        }
    }

    /// <summary>Copies all rows transactionally, then commits only when count and fingerprint match.</summary>
    public static async Task<IdentityMigrationReport> CopyAndValidateAsync(
        IAsyncEnumerable<LegacyIdentityRow> source,
        LegacyIdentityDbContext destination,
        bool includeCustomerFields,
        CancellationToken cancellationToken = default)
    {
        await using var transaction = await destination.Database.BeginTransactionAsync(cancellationToken);
        destination.ChangeTracker.Clear();
        var sourceFingerprint = new IdentityFingerprint(includeCustomerFields);
        var batch = new List<LegacyIdentityRow>(BatchSize);

        await foreach (var row in source.WithCancellation(cancellationToken))
        {
            sourceFingerprint.Append(row);
            batch.Add(row);
            if (batch.Count == BatchSize)
            {
                await UpsertBatchAsync(destination, batch, cancellationToken);
                batch.Clear();
            }
        }

        if (batch.Count > 0)
        {
            await UpsertBatchAsync(destination, batch, cancellationToken);
        }

        var sourceResult = sourceFingerprint.Complete();
        var destinationResult = await FingerprintDestinationAsync(
            destination,
            includeCustomerFields,
            cancellationToken);
        EnsureEquivalent(sourceResult, destinationResult);
        await transaction.CommitAsync(cancellationToken);
        return new(sourceResult.Count, destinationResult.Count, sourceResult.Hash);
    }

    /// <summary>Compares a read-only source with PostgreSQL without changing either store.</summary>
    public static async Task<IdentityMigrationReport> ValidateAsync(
        IAsyncEnumerable<LegacyIdentityRow> source,
        LegacyIdentityDbContext destination,
        bool includeCustomerFields,
        CancellationToken cancellationToken = default)
    {
        var sourceFingerprint = new IdentityFingerprint(includeCustomerFields);
        await foreach (var row in source.WithCancellation(cancellationToken))
        {
            sourceFingerprint.Append(row);
        }

        var sourceResult = sourceFingerprint.Complete();
        var destinationResult = await FingerprintDestinationAsync(
            destination,
            includeCustomerFields,
            cancellationToken);
        EnsureEquivalent(sourceResult, destinationResult);
        return new(sourceResult.Count, destinationResult.Count, sourceResult.Hash);
    }

    private static async Task UpsertBatchAsync(
        LegacyIdentityDbContext destination,
        IReadOnlyCollection<LegacyIdentityRow> rows,
        CancellationToken cancellationToken)
    {
        var ids = rows.Select(row => row.Id).ToArray();
        var existingIds = await destination.Users
            .AsNoTracking()
            .Where(row => ids.Contains(row.Id))
            .Select(row => row.Id)
            .ToHashSetAsync(cancellationToken);

        foreach (var row in rows)
        {
            destination.Entry(row).State = existingIds.Contains(row.Id)
                ? EntityState.Modified
                : EntityState.Added;
        }

        await destination.SaveChangesAsync(cancellationToken);
        destination.ChangeTracker.Clear();
    }

    private static async Task<FingerprintResult> FingerprintDestinationAsync(
        LegacyIdentityDbContext destination,
        bool includeCustomerFields,
        CancellationToken cancellationToken)
    {
        destination.ChangeTracker.Clear();
        var fingerprint = new IdentityFingerprint(includeCustomerFields);
        await foreach (var row in destination.Users
                           .AsNoTracking()
                           .OrderBy(row => row.Id)
                           .AsAsyncEnumerable()
                           .WithCancellation(cancellationToken))
        {
            fingerprint.Append(row);
        }

        return fingerprint.Complete();
    }

    private static void EnsureEquivalent(FingerprintResult source, FingerprintResult destination)
    {
        if (source.Count != destination.Count ||
            !string.Equals(source.Hash, destination.Hash, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Identity validation failed: source rows={source.Count}, destination rows={destination.Count}, " +
                $"source fingerprint={source.Hash}, destination fingerprint={destination.Hash}.");
        }
    }

    private sealed class IdentityFingerprint(bool includeCustomerFields)
    {
        private readonly IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private string? previousId;

        public long Count { get; private set; }

        public void Append(LegacyIdentityRow row)
        {
            if (previousId is not null && string.CompareOrdinal(previousId, row.Id) >= 0)
            {
                throw new InvalidOperationException("Identity rows must be unique and ordered by Id for deterministic validation.");
            }

            previousId = row.Id;
            AppendValue(row.Id);
            AppendValue(row.UserName);
            AppendValue(row.NormalizedUserName);
            AppendValue(row.Email);
            AppendValue(row.NormalizedEmail);
            AppendValue(row.EmailConfirmed);
            AppendValue(row.PasswordHash);
            AppendValue(row.SecurityStamp);
            AppendValue(row.ConcurrencyStamp);
            AppendValue(row.PhoneNumber);
            AppendValue(row.PhoneNumberConfirmed);
            AppendValue(row.TwoFactorEnabled);
            AppendValue(row.DatabaseID);
            if (includeCustomerFields)
            {
                AppendValue(row.FaxNumber);
                AppendValue(row.MobileNumber);
            }

            AppendValue(row.LockoutEnabled);
            AppendValue(NormalizePostgresTimestamp(row.LockoutEnd));
            AppendValue(row.AccessFailedCount);
            Count++;
        }

        public FingerprintResult Complete() => new(Count, Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant());

        private void AppendValue(object? value)
        {
            var text = value switch
            {
                null => null,
                bool boolean => boolean ? "1" : "0",
                IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture),
                _ => value.ToString()
            };
            var framed = text is null ? "-1:" : $"{text.Length}:{text}";
            hash.AppendData(Encoding.UTF8.GetBytes(framed));
        }

        private static string? NormalizePostgresTimestamp(DateTimeOffset? value)
        {
            if (value is null)
            {
                return null;
            }

            var utcTicks = value.Value.UtcTicks;
            var postgresTicks = utcTicks - (utcTicks % TimeSpan.TicksPerMicrosecond);
            return new DateTimeOffset(postgresTicks, TimeSpan.Zero)
                .ToString("O", CultureInfo.InvariantCulture);
        }
    }

    private sealed record FingerprintResult(long Count, string Hash);
}
