using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class LockoutEndExactDualColumnStoreTests(PostgresFixture postgres)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReconciledWrite_PreservesOffsetAndTickWhileRuntimeUsesUtc(bool employee)
    {
        await using var context = await CreateContextAsync(employee);
        context.Users.Add(new LegacyIdentityRow { Id = "user", LockoutEnabled = true });
        await context.SaveChangesAsync();
        await AddSidecarAsync(context);
        await MarkCompleteAsync(context, "user", null);

        var store = new LockoutEndExactDualColumnStore(context.Database.GetConnectionString()!);
        var exact = new DateTimeOffset(2026, 9, 28, 12, 34, 56, TimeSpan.FromHours(-14)).AddTicks(1_234_567);
        await store.WriteReconciledAsync("user", null, exact);

        var read = await store.ReadReconciledAsync("user");
        Assert.Equal(exact, read);
        Assert.Equal(exact.Offset, read?.Offset);
        Assert.Equal(exact.Ticks, read?.Ticks);
        context.ChangeTracker.Clear();
        Assert.Equal(exact.ToUniversalTime().Ticks / 10,
            (await context.Users.SingleAsync(row => row.Id == "user")).LockoutEnd?.ToUniversalTime().Ticks / 10);

        var later = new DateTimeOffset(2026, 9, 29, 1, 2, 3, TimeSpan.FromHours(14)).AddTicks(7);
        await store.WriteReconciledAsync("user", exact, later);
        Assert.Equal(later.Offset, (await store.ReadReconciledAsync("user"))?.Offset);
        Assert.Equal(later.Ticks, (await store.ReadReconciledAsync("user"))?.Ticks);
        await store.WriteReconciledAsync("user", later, null);
        Assert.Null(await store.ReadReconciledAsync("user"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReconciledWrite_RejectsStaleOrMalformedStateWithoutChangingRuntime(bool employee)
    {
        await using var context = await CreateContextAsync(employee);
        context.Users.Add(new LegacyIdentityRow { Id = "user", LockoutEnabled = true });
        await context.SaveChangesAsync();
        await AddSidecarAsync(context);
        await MarkCompleteAsync(context, "user", null);
        var store = new LockoutEndExactDualColumnStore(context.Database.GetConnectionString()!);
        var exact = new DateTimeOffset(2026, 9, 28, 12, 34, 56, TimeSpan.FromHours(14)).AddTicks(7);
        await store.WriteReconciledAsync("user", null, exact);

        await Assert.ThrowsAsync<InvalidOperationException>(() => store.WriteReconciledAsync("user", null, exact.AddTicks(1)));
        Assert.Equal(exact.Ticks, (await store.ReadReconciledAsync("user"))?.Ticks);

        await context.Database.ExecuteSqlRawAsync(
            "UPDATE \"AspNetUsers\" SET \"LockoutEndExact\" = 'bad' WHERE \"Id\" = 'user'");
        await Assert.ThrowsAsync<FormatException>(() => store.ReadReconciledAsync("user"));
        await Assert.ThrowsAsync<FormatException>(() => store.WriteReconciledAsync("user", exact, null));
        context.ChangeTracker.Clear();
        Assert.Equal(exact.ToUniversalTime().Ticks / 10,
            (await context.Users.SingleAsync(row => row.Id == "user")).LockoutEnd?.ToUniversalTime().Ticks / 10);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OptInStore_RejectsMissingOrIncompleteSidecar(bool employee)
    {
        await using var context = await CreateContextAsync(employee);
        context.Users.Add(new LegacyIdentityRow { Id = "user", LockoutEnabled = true });
        await context.SaveChangesAsync();
        var store = new LockoutEndExactDualColumnStore(context.Database.GetConnectionString()!);
        await Assert.ThrowsAsync<PostgresException>(() => store.ReadReconciledAsync("user"));
        await AddSidecarAsync(context);
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.ReadReconciledAsync("user"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.WriteReconciledAsync("user", null, null));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReconciledWrite_DatabaseFailureRollsBackBothColumns(bool employee)
    {
        await using var context = await CreateContextAsync(employee);
        context.Users.Add(new LegacyIdentityRow { Id = "user", LockoutEnabled = true });
        await context.SaveChangesAsync();
        await AddSidecarAsync(context);
        await MarkCompleteAsync(context, "user", null);
        await context.Database.ExecuteSqlRawAsync(
            "CREATE FUNCTION reject_lockout_update() RETURNS trigger LANGUAGE plpgsql AS $$ " +
            "BEGIN RAISE EXCEPTION 'reject update'; END $$; " +
            "CREATE TRIGGER reject_lockout AFTER UPDATE ON \"AspNetUsers\" " +
            "FOR EACH ROW EXECUTE FUNCTION reject_lockout_update()");

        var store = new LockoutEndExactDualColumnStore(context.Database.GetConnectionString()!);
        var exact = new DateTimeOffset(2026, 9, 28, 12, 34, 56, TimeSpan.FromHours(14)).AddTicks(7);
        await Assert.ThrowsAsync<PostgresException>(() => store.WriteReconciledAsync("user", null, exact));
        Assert.Null(await store.ReadReconciledAsync("user"));
        context.ChangeTracker.Clear();
        Assert.Null((await context.Users.SingleAsync(row => row.Id == "user")).LockoutEnd);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OptInStore_RejectsCompletedSidecarWithDifferentRuntimeInstant(bool employee)
    {
        await using var context = await CreateContextAsync(employee);
        context.Users.Add(new LegacyIdentityRow { Id = "user", LockoutEnabled = true });
        await context.SaveChangesAsync();
        await AddSidecarAsync(context);
        var exact = new DateTimeOffset(2026, 9, 28, 12, 34, 56, TimeSpan.FromHours(14)).AddTicks(7);
        await MarkCompleteAsync(context, "user", LockoutEndExactText.Format(exact));
        var store = new LockoutEndExactDualColumnStore(context.Database.GetConnectionString()!);
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.ReadReconciledAsync("user"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.WriteReconciledAsync("user", exact, null));
    }

    private async Task<LegacyIdentityDbContext> CreateContextAsync(bool employee) => employee
        ? await postgres.CreateEmployeeContextAsync()
        : await postgres.CreateCustomerContextAsync();

    private static Task AddSidecarAsync(LegacyIdentityDbContext context) => context.Database.ExecuteSqlRawAsync(
        "ALTER TABLE \"AspNetUsers\" ADD COLUMN \"LockoutEndExact\" text NULL, " +
        "ADD COLUMN \"LockoutEndExactComplete\" boolean NOT NULL DEFAULT false");

    private static Task MarkCompleteAsync(LegacyIdentityDbContext context, string id, string? exact) =>
        context.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE \"AspNetUsers\" SET \"LockoutEndExact\" = {exact}, \"LockoutEndExactComplete\" = true WHERE \"Id\" = {id}");
}
