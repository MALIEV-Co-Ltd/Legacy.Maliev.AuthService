using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class LockoutEndExactTextTests(PostgresFixture postgres)
{
    [Fact]
    public void ExactText_RoundTripsNullableExtremeOffsetsAndSeventhFractionalDigit()
    {
        Assert.Null(LockoutEndExactText.Format(null));
        Assert.Null(LockoutEndExactText.Parse(null));

        DateTimeOffset[] values =
        [
            new DateTimeOffset(2026, 9, 28, 12, 34, 56, TimeSpan.FromHours(14)).AddTicks(1_234_567),
            new DateTimeOffset(2026, 9, 28, 12, 34, 56, TimeSpan.FromHours(-14)).AddTicks(7),
            new DateTimeOffset(2026, 9, 28, 12, 34, 56, TimeSpan.Zero).AddTicks(9_999_999),
        ];

        foreach (var value in values)
        {
            var text = LockoutEndExactText.Format(value);
            var roundTrip = LockoutEndExactText.Parse(text);
            Assert.Equal(value, roundTrip);
            Assert.Equal(value.Offset, roundTrip?.Offset);
            Assert.Equal(value.Ticks, roundTrip?.Ticks);
            Assert.Equal(33, text?.Length);
        }
        Assert.Equal("2026-09-28T12:34:56.1234567+14:00", LockoutEndExactText.Format(values[0]));
        Assert.Equal("2026-09-28T12:34:56.0000007-14:00", LockoutEndExactText.Format(values[1]));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-date")]
    [InlineData("2026-09-28T12:34:56.123456+07:00")]
    [InlineData("2026-09-28T12:34:56.1234567Z")]
    [InlineData("2026-09-28T12:34:56.1234567+14:01")]
    [InlineData("2026-09-28T12:34:56.1234567+07:00 ")]
    public void ExactText_RejectsNonCanonicalOrInvalidValues(string text)
    {
        var exception = Assert.Throws<FormatException>(() => LockoutEndExactText.Parse(text));
        if (text.Length > 0)
        {
            Assert.DoesNotContain(text, exception.Message, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DisposableSidecar_PreservesSourceTextWithoutChangingRuntimeColumn(bool employee)
    {
        await using var runtime = employee
            ? (LegacyIdentityDbContext)await postgres.CreateEmployeeContextAsync()
            : await postgres.CreateCustomerContextAsync();
        var original = new DateTimeOffset(2026, 9, 28, 0, 0, 0, TimeSpan.Zero).AddTicks(1_234_560);
        runtime.Users.Add(new LegacyIdentityRow { Id = "existing", LockoutEnabled = true, LockoutEnd = original });
        await runtime.SaveChangesAsync();
        var before = await ReadColumnShapesAsync(runtime);
        Assert.Contains(before, column => column.Name == "LockoutEnd"
            && column.Type == "timestamp with time zone" && column.Nullable);

        // This DDL is confined to this Testcontainers database. Production schema
        // and the mapped LockoutEnd timestamptz column remain unchanged.
        await runtime.Database.ExecuteSqlRawAsync(
            "ALTER TABLE \"AspNetUsers\" ADD COLUMN \"LockoutEndExact\" text NULL");
        var after = await ReadColumnShapesAsync(runtime);
        Assert.Equal(before.Count + 1, after.Count);
        Assert.Equal(before, after.Take(before.Count));
        Assert.Equal(new ColumnShape("LockoutEndExact", "text", true), after[^1]);

        var source = new DateTimeOffset(2026, 9, 28, 12, 34, 56, TimeSpan.FromHours(14)).AddTicks(1_234_567);
        var sourceText = LockoutEndExactText.Format(source)!;
        var options = new DbContextOptionsBuilder<SidecarContext>()
            .UseNpgsql(runtime.Database.GetConnectionString())
            .Options;
        await using (var sidecar = new SidecarContext(options))
        {
            var row = await sidecar.Users.SingleAsync();
            Assert.Null(row.LockoutEndExact);
            row.LockoutEndExact = source;
            await sidecar.SaveChangesAsync();
        }

        await using (var connection = new NpgsqlConnection(runtime.Database.GetConnectionString()))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand(
                "SELECT \"LockoutEndExact\" FROM \"AspNetUsers\" WHERE \"Id\" = 'existing'", connection);
            Assert.Equal(sourceText, await command.ExecuteScalarAsync());
        }

        await using (var sidecar = new SidecarContext(options))
        {
            var roundTrip = (await sidecar.Users.SingleAsync()).LockoutEndExact;
            Assert.Equal(source, roundTrip);
            Assert.Equal(source.Offset, roundTrip?.Offset);
            Assert.Equal(source.Ticks, roundTrip?.Ticks);
            Assert.True(roundTrip > new DateTimeOffset(2026, 9, 27, 0, 0, 0, TimeSpan.Zero));
            Assert.True(roundTrip <= new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero));
        }

        await using (var connection = new NpgsqlConnection(runtime.Database.GetConnectionString()))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand(
                "UPDATE \"AspNetUsers\" SET \"LockoutEndExact\" = 'invalid' WHERE \"Id\" = 'existing'", connection);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }
        await using (var sidecar = new SidecarContext(options))
        {
            await Assert.ThrowsAsync<FormatException>(() => sidecar.Users.SingleAsync());
        }

        runtime.ChangeTracker.Clear();
        Assert.Equal(original, (await runtime.Users.SingleAsync()).LockoutEnd);
        Assert.Equal(0, original.Offset.TotalMinutes);
    }

    private static async Task<IReadOnlyList<ColumnShape>> ReadColumnShapesAsync(LegacyIdentityDbContext runtime)
    {
        await using var connection = new NpgsqlConnection(runtime.Database.GetConnectionString());
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            "SELECT column_name, data_type, is_nullable FROM information_schema.columns " +
            "WHERE table_schema = 'public' AND table_name = 'AspNetUsers' ORDER BY ordinal_position", connection);
        await using var reader = await command.ExecuteReaderAsync();
        var columns = new List<ColumnShape>();
        while (await reader.ReadAsync())
        {
            columns.Add(new ColumnShape(reader.GetString(0), reader.GetString(1), reader.GetString(2) == "YES"));
        }

        return columns;
    }

    private sealed record ColumnShape(string Name, string Type, bool Nullable);

    private sealed class SidecarRow
    {
        public required string Id { get; set; }
        public DateTimeOffset? LockoutEndExact { get; set; }
    }

    private sealed class SidecarContext(DbContextOptions<SidecarContext> options) : DbContext(options)
    {
        public DbSet<SidecarRow> Users => Set<SidecarRow>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            var row = modelBuilder.Entity<SidecarRow>();
            row.ToTable("AspNetUsers");
            row.HasKey(value => value.Id);
            row.Property(value => value.LockoutEndExact)
                .HasConversion(LockoutEndExactText.Converter)
                .HasColumnType("text");
        }
    }
}
