using System.Data;
using Npgsql;
using NpgsqlTypes;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>
/// Explicitly opted-in, prospective access to a reconciled additive lockout sidecar.
/// This store is not registered in the running service or mapped by either identity context.
/// </summary>
public sealed class LockoutEndExactDualColumnStore(string connectionString)
{
    /// <summary>Reads a completed exact value only when the runtime instant agrees with it.</summary>
    public async Task<DateTimeOffset?> ReadReconciledAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken);
        return await ReadStateAsync(connection, userId, false, cancellationToken);
    }

    /// <summary>
    /// Atomically changes the existing timestamptz and exact text from an expected exact preimage.
    /// Rows without a completed, reconciled sidecar cannot be written.
    /// </summary>
    public async Task WriteReconciledAsync(
        string userId, DateTimeOffset? expectedExact, DateTimeOffset? replacement,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        var current = await ReadStateAsync(connection, userId, true, cancellationToken);
        if (!string.Equals(LockoutEndExactText.Format(current), LockoutEndExactText.Format(expectedExact),
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The lockout sidecar changed since the expected read.");
        }

        await using var update = new NpgsqlCommand(
            "UPDATE \"AspNetUsers\" SET \"LockoutEnd\" = @runtime, " +
            "\"LockoutEndExact\" = @exact WHERE \"Id\" = @id " +
            "AND \"LockoutEndExactComplete\" = true " +
            "AND \"LockoutEndExact\" IS NOT DISTINCT FROM @expected", connection, transaction);
        update.Parameters.AddWithValue("id", userId);
        update.Parameters.AddWithValue("exact", NpgsqlDbType.Text,
            (object?)LockoutEndExactText.Format(replacement) ?? DBNull.Value);
        update.Parameters.AddWithValue("expected", NpgsqlDbType.Text,
            (object?)LockoutEndExactText.Format(expectedExact) ?? DBNull.Value);
        update.Parameters.AddWithValue("runtime", NpgsqlDbType.TimestampTz,
            (object?)replacement?.UtcDateTime ?? DBNull.Value);
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            throw new InvalidOperationException("The lockout sidecar compare-and-swap failed.");
        }

        await transaction.CommitAsync(cancellationToken);
    }

    private static async Task<DateTimeOffset?> ReadStateAsync(
        NpgsqlConnection connection, string userId, bool forUpdate, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT \"LockoutEndExactComplete\", \"LockoutEndExact\", \"LockoutEnd\" " +
            "FROM \"AspNetUsers\" WHERE \"Id\" = @id" + (forUpdate ? " FOR UPDATE" : ""), connection);
        command.Parameters.AddWithValue("id", userId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            throw new InvalidOperationException("The identity row does not exist.");
        }

        if (!reader.GetBoolean(0))
        {
            throw new InvalidOperationException("The exact lockout sidecar has not been reconciled.");
        }

        var exact = LockoutEndExactText.Parse(reader.IsDBNull(1) ? null : reader.GetString(1));
        DateTimeOffset? runtime = reader.IsDBNull(2)
            ? null
            : new DateTimeOffset(reader.GetDateTime(2), TimeSpan.Zero);
        if (exact.HasValue != runtime.HasValue ||
            (exact.HasValue && exact.Value.ToUniversalTime().Ticks / 10 != runtime!.Value.Ticks / 10))
        {
            throw new InvalidOperationException("The runtime lockout and exact sidecar have different instants.");
        }

        if (await reader.ReadAsync(cancellationToken))
        {
            throw new InvalidOperationException("The identity key is not unique.");
        }

        return exact;
    }
}
