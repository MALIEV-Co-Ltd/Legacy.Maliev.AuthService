using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class LockoutEndExactTransitionTests(PostgresFixture postgres)
{
    [Fact]
    public void Completeness_DistinguishesSourceNullFromNotBackfilledAndRejectsConflicts()
    {
        Assert.True(LockoutEndExactTransition.NeedsBackfill(false, null, null));
        Assert.Throws<InvalidOperationException>(() => LockoutEndExactTransition.ReadCompleted(false, null));
        Assert.False(LockoutEndExactTransition.NeedsBackfill(true, null, null));
        Assert.Null(LockoutEndExactTransition.ReadCompleted(true, null));

        var exact = new DateTimeOffset(2026, 9, 28, 12, 34, 56, TimeSpan.FromHours(14)).AddTicks(7);
        string text = LockoutEndExactText.Format(exact)!;
        Assert.False(LockoutEndExactTransition.NeedsBackfill(true, text, exact));
        Assert.Equal(exact.Offset, LockoutEndExactTransition.ReadCompleted(true, text)?.Offset);
        Assert.Equal(exact.Ticks, LockoutEndExactTransition.ReadCompleted(true, text)?.Ticks);
        Assert.Throws<InvalidOperationException>(() => LockoutEndExactTransition.NeedsBackfill(false, text, exact));
        Assert.Throws<InvalidOperationException>(() => LockoutEndExactTransition.NeedsBackfill(true, text, null));
        Assert.Throws<FormatException>(() => LockoutEndExactTransition.NeedsBackfill(true, "invalid", exact));
        Assert.Throws<FormatException>(() => LockoutEndExactTransition.ReadCompleted(true, "invalid"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DisposableDualColumn_BackfillIsKeyBoundRetrySafeAndLeavesRuntimeUnchanged(bool employee)
    {
        await using LegacyIdentityDbContext runtime = employee
            ? await postgres.CreateEmployeeContextAsync()
            : await postgres.CreateCustomerContextAsync();
        var runtimeLockout = new DateTimeOffset(2026, 9, 28, 0, 0, 0, TimeSpan.Zero).AddTicks(1_234_560);
        runtime.Users.AddRange(
            new LegacyIdentityRow { Id = "source-null", LockoutEnabled = true },
            new LegacyIdentityRow { Id = "source-exact", LockoutEnabled = true, LockoutEnd = runtimeLockout });
        await runtime.SaveChangesAsync();

        await runtime.Database.ExecuteSqlRawAsync(
            "ALTER TABLE \"AspNetUsers\" ADD COLUMN \"LockoutEndExact\" text NULL, " +
            "ADD COLUMN \"LockoutEndExactComplete\" boolean NOT NULL DEFAULT false");

        var exact = new DateTimeOffset(2026, 9, 28, 12, 34, 56, TimeSpan.FromHours(-14)).AddTicks(1_234_567);
        await using var connection = new NpgsqlConnection(runtime.Database.GetConnectionString());
        await connection.OpenAsync();
        await AssertBackfillAsync(connection, "source-null", null);
        await AssertBackfillAsync(connection, "source-exact", exact);
        await AssertBackfillAsync(connection, "source-null", null);
        await AssertBackfillAsync(connection, "source-exact", exact);

        var nullState = await ReadStateAsync(connection, "source-null");
        var exactState = await ReadStateAsync(connection, "source-exact");
        Assert.True(nullState.Complete);
        Assert.Null(LockoutEndExactTransition.ReadCompleted(nullState.Complete, nullState.Text));
        Assert.True(exactState.Complete);
        Assert.Equal(exact, LockoutEndExactTransition.ReadCompleted(exactState.Complete, exactState.Text));
        Assert.Equal(exact.Offset, LockoutEndExactTransition.ReadCompleted(exactState.Complete, exactState.Text)?.Offset);
        Assert.Equal(exact.Ticks, LockoutEndExactTransition.ReadCompleted(exactState.Complete, exactState.Text)?.Ticks);
        var now = new DateTimeOffset(2026, 9, 28, 0, 0, 0, TimeSpan.Zero);
        Assert.True(LockoutEndExactTransition.ReadCompleted(exactState.Complete, exactState.Text) > now);
        Assert.False(LockoutEndExactTransition.ReadCompleted(nullState.Complete, nullState.Text) > now);
        Assert.Throws<InvalidOperationException>(() => LockoutEndExactTransition.NeedsBackfill(
            exactState.Complete, exactState.Text, exact.AddTicks(1)));

        runtime.ChangeTracker.Clear();
        Assert.Null((await runtime.Users.SingleAsync(row => row.Id == "source-null")).LockoutEnd);
        Assert.Equal(runtimeLockout, (await runtime.Users.SingleAsync(row => row.Id == "source-exact")).LockoutEnd);

        await using (var corrupt = new NpgsqlCommand(
            "UPDATE \"AspNetUsers\" SET \"LockoutEndExact\" = 'invalid' WHERE \"Id\" = 'source-exact'", connection))
        {
            Assert.Equal(1, await corrupt.ExecuteNonQueryAsync());
        }
        var corrupted = await ReadStateAsync(connection, "source-exact");
        Assert.Throws<FormatException>(() => LockoutEndExactTransition.ReadCompleted(corrupted.Complete, corrupted.Text));
    }

    private static async Task AssertBackfillAsync(NpgsqlConnection connection, string id, DateTimeOffset? source)
    {
        var current = await ReadStateAsync(connection, id);
        if (!LockoutEndExactTransition.NeedsBackfill(current.Complete, current.Text, source))
        {
            return;
        }

        await using var update = new NpgsqlCommand(
            "UPDATE \"AspNetUsers\" SET \"LockoutEndExact\" = @exact, " +
            "\"LockoutEndExactComplete\" = true WHERE \"Id\" = @id " +
            "AND \"LockoutEndExactComplete\" = false AND \"LockoutEndExact\" IS NULL", connection);
        update.Parameters.AddWithValue("id", id);
        update.Parameters.AddWithValue("exact", (object?)LockoutEndExactText.Format(source) ?? DBNull.Value);
        Assert.Equal(1, await update.ExecuteNonQueryAsync());
    }

    private static async Task<(bool Complete, string? Text)> ReadStateAsync(NpgsqlConnection connection, string id)
    {
        await using var query = new NpgsqlCommand(
            "SELECT \"LockoutEndExactComplete\", \"LockoutEndExact\" FROM \"AspNetUsers\" WHERE \"Id\" = @id", connection);
        query.Parameters.AddWithValue("id", id);
        await using var reader = await query.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        var state = (reader.GetBoolean(0), reader.IsDBNull(1) ? null : reader.GetString(1));
        Assert.False(await reader.ReadAsync());
        return state;
    }
}
