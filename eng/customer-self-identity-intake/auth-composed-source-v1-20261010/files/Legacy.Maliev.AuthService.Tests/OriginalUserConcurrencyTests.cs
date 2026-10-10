using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class OriginalUserConcurrencyModelTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BothUserModels_UseOriginalNullableConcurrencyStampWithoutNewColumn(bool employee)
    {
        using LegacyIdentityDbContext context = employee
            ? new EmployeeIdentityDbContext(new DbContextOptionsBuilder<EmployeeIdentityDbContext>().UseNpgsql("Host=localhost;Database=model_only").Options)
            : new CustomerIdentityDbContext(new DbContextOptionsBuilder<CustomerIdentityDbContext>().UseNpgsql("Host=localhost;Database=model_only").Options);
        var property = context.Model.FindEntityType(typeof(LegacyIdentityRow))!.FindProperty("ConcurrencyStamp")!;
        Assert.True(property.IsConcurrencyToken);
        Assert.True(property.IsNullable);
        Assert.Equal("text", property.GetColumnType());
        Assert.DoesNotContain(context.Model.GetEntityTypes().SelectMany(entity => entity.GetProperties()), item => item.Name == "xmin");
    }
}

[Collection(PostgresCollection.Name)]
public sealed class OriginalUserConcurrencyPersistenceTests(PostgresFixture postgres)
{
    [Fact]
    public async Task Confirmation_RechecksGenerationAfterWaitingForCurrentOwner()
    {
        await using var customers = await postgres.CreateCustomerContextAsync();
        await using var state = await postgres.CreateStateContextAsync();
        await using var blocker = new CustomerIdentityDbContext(new DbContextOptionsBuilder<CustomerIdentityDbContext>()
            .UseNpgsql(customers.Database.GetConnectionString()).Options);
        customers.Users.Add(new() { Id = "owner", UserName = "owner@example.com", Email = "owner@example.com",
            NormalizedUserName = "OWNER@EXAMPLE.COM", NormalizedEmail = "OWNER@EXAMPLE.COM",
            SecurityStamp = "old-security", ConcurrencyStamp = "old-concurrency" });
        await customers.SaveChangesAsync();
        var service = new CustomerSelfService(customers, state, new PasswordHasher<LegacyIdentityRow>(), TimeProvider.System);
        var action = await service.RequestEmailConfirmationAsync(new("owner@example.com"), default);
        Assert.False(string.IsNullOrWhiteSpace(action.Token));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<bool>? completion = null;
        System.Runtime.ExceptionServices.ExceptionDispatchInfo? primary = null;
        var cleanupFailures = new List<Exception>();
        var transaction = await blocker.Database.BeginTransactionAsync(timeout.Token);
        try
        {
            await blocker.Database.ExecuteSqlRawAsync("SELECT * FROM \"AspNetUsers\" WHERE \"Id\" = 'owner' FOR UPDATE", timeout.Token);
            completion = service.ConfirmEmailAsync(new("owner@example.com", action.Token!), timeout.Token);
            var blocked = false;
            for (var attempt = 0; attempt < 500 && !blocked; attempt++)
            {
                blocked = await blocker.Database.SqlQueryRaw<int>("""
                    SELECT count(*)::integer AS "Value" FROM pg_stat_activity
                    WHERE datname = current_database() AND pid <> pg_backend_pid()
                      AND wait_event_type = 'Lock' AND query LIKE '%AspNetUsers%' AND query LIKE '%FOR UPDATE%'
                    """).SingleAsync(timeout.Token) > 0;
                if (!blocked) await Task.Delay(10, timeout.Token);
            }
            Assert.True(blocked, "Confirmation must reach its real owner-row fence.");
            await blocker.Users.Where(row => row.Id == "owner").ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.SecurityStamp, "new-security")
                .SetProperty(row => row.ConcurrencyStamp, "new-concurrency"), timeout.Token);
            await transaction.CommitAsync(timeout.Token);
            Assert.False(await completion);
            var current = await customers.Users.AsNoTracking().SingleAsync();
            Assert.False(current.EmailConfirmed);
            Assert.Equal("new-security", current.SecurityStamp);
            Assert.Equal("new-concurrency", current.ConcurrencyStamp);
            Assert.Null((await state.IdentityActionTokens.AsNoTracking().SingleAsync()).ConsumedAt);
        }
        catch (Exception failure) { primary = System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure); }
        finally
        {
            try { await transaction.DisposeAsync(); } catch (Exception failure) { cleanupFailures.Add(failure); }
            if (completion is not null && !completion.IsCompleted && (primary is not null || cleanupFailures.Count > 0))
            {
                try { timeout.Cancel(); } catch (Exception failure) { cleanupFailures.Add(failure); }
            }
            if (completion is not null)
            {
                try { await completion; }
                catch (OperationCanceledException) when (timeout.IsCancellationRequested) { }
                catch (Exception failure) { if (!ReferenceEquals(primary?.SourceException, failure)) cleanupFailures.Add(failure); }
            }
        }
        if (primary is not null)
        {
            if (cleanupFailures.Count > 0)
            {
                try { primary.SourceException.Data["OwnedConfirmationCleanupFailures"] = new AggregateException(cleanupFailures); } catch { }
            }
            primary.Throw();
        }
        if (cleanupFailures.Count > 0) throw new AggregateException("Owned confirmation cleanup failed.", cleanupFailures);
    }

    [Fact]
    public async Task ResetStampInitialization_AdvancesOriginalConcurrencyFence()
    {
        await using var customers = await postgres.CreateCustomerContextAsync();
        await using var state = await postgres.CreateStateContextAsync();
        await using var stale = new CustomerIdentityDbContext(new DbContextOptionsBuilder<CustomerIdentityDbContext>()
            .UseNpgsql(customers.Database.GetConnectionString()).Options);
        customers.Users.Add(new() { Id = "owner", UserName = "owner@example.com", Email = "owner@example.com",
            NormalizedUserName = "OWNER@EXAMPLE.COM", NormalizedEmail = "OWNER@EXAMPLE.COM", ConcurrencyStamp = "before-initialization" });
        await customers.SaveChangesAsync();
        var prior = await stale.Users.SingleAsync();
        var service = new CustomerSelfService(customers, state, new PasswordHasher<LegacyIdentityRow>(), TimeProvider.System);
        var action = await service.RequestPasswordResetAsync(new("owner@example.com"), default);
        Assert.True(action.Accepted);
        Assert.False(string.IsNullOrWhiteSpace(action.Token));
        var current = await customers.Users.AsNoTracking().SingleAsync();
        Assert.False(string.IsNullOrWhiteSpace(current.SecurityStamp));
        Assert.NotEqual("before-initialization", current.ConcurrencyStamp);
        prior.PhoneNumber = "+66812345678";
        prior.ConcurrencyStamp = "stale-writer";
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => stale.SaveChangesAsync());
        Assert.Null((await customers.Users.AsNoTracking().SingleAsync()).PhoneNumber);
    }

    [Theory]
    [InlineData(false, null)]
    [InlineData(false, "original-stamp")]
    [InlineData(true, null)]
    [InlineData(true, "original-stamp")]
    public async Task BothStores_RejectStaleUserWriteAndPreserveCommittedWinner(bool employee, string? stamp)
    {
        await using LegacyIdentityDbContext winner = employee
            ? await postgres.CreateEmployeeContextAsync()
            : await postgres.CreateCustomerContextAsync();
        var connection = winner.Database.GetConnectionString();
        await using LegacyIdentityDbContext stale = employee
            ? new EmployeeIdentityDbContext(new DbContextOptionsBuilder<EmployeeIdentityDbContext>().UseNpgsql(connection).Options)
            : new CustomerIdentityDbContext(new DbContextOptionsBuilder<CustomerIdentityDbContext>().UseNpgsql(connection).Options);
        winner.Users.Add(new() { Id = "owner", Email = "before@example.com", ConcurrencyStamp = stamp });
        winner.Users.Add(new() { Id = "other", Email = "other@example.com", ConcurrencyStamp = "other-stamp" });
        await winner.SaveChangesAsync();
        var old = await stale.Users.SingleAsync(row => row.Id == "owner");
        var committed = await winner.Users.SingleAsync(row => row.Id == "owner");
        committed.Email = "winner@example.com";
        committed.PasswordHash = "synthetic-winner-hash-column";
        committed.ConcurrencyStamp = "winner-stamp";
        await winner.SaveChangesAsync();
        old.Email = "stale@example.com";
        old.PasswordHash = "synthetic-stale-hash-column";
        old.ConcurrencyStamp = "stale-stamp";
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => stale.SaveChangesAsync());
        var current = await winner.Users.AsNoTracking().SingleAsync(row => row.Id == "owner");
        Assert.Equal("winner@example.com", current.Email);
        Assert.Equal("synthetic-winner-hash-column", current.PasswordHash);
        Assert.Equal("winner-stamp", current.ConcurrencyStamp);
        Assert.Equal("other-stamp", (await winner.Users.AsNoTracking().SingleAsync(row => row.Id == "other")).ConcurrencyStamp);
    }

    [Theory]
    [InlineData("create")]
    [InlineData("change")]
    public async Task ConcurrentPasswordWriters_RecheckLockedOwnerAndReturnExistingSafeOutcomes(string operation)
    {
        await using var customers = await postgres.CreateCustomerContextAsync();
        await using var state = await postgres.CreateStateContextAsync();
        var firstName = "auth-concurrency-A-" + Guid.NewGuid().ToString("N");
        var secondName = "auth-concurrency-B-" + Guid.NewGuid().ToString("N");
        var firstConnection = new NpgsqlConnectionStringBuilder(customers.Database.GetConnectionString()) { ApplicationName = firstName, Pooling = false };
        var secondConnection = new NpgsqlConnectionStringBuilder(firstConnection.ConnectionString) { ApplicationName = secondName };
        customers.Database.SetConnectionString(firstConnection.ConnectionString);
        await using var otherCustomers = new CustomerIdentityDbContext(new DbContextOptionsBuilder<CustomerIdentityDbContext>()
            .UseNpgsql(secondConnection.ConnectionString).Options);
        await using var blocker = new CustomerIdentityDbContext(new DbContextOptionsBuilder<CustomerIdentityDbContext>()
            .UseNpgsql(firstConnection.ConnectionString).Options);
        await using var otherState = new RefreshSessionDbContext(new DbContextOptionsBuilder<RefreshSessionDbContext>()
            .UseNpgsql(state.Database.GetConnectionString()).Options);
        var hasher = new PasswordHasher<LegacyIdentityRow>();
        var row = new LegacyIdentityRow { Id = "owner", Email = "owner@example.com", EmailConfirmed = true,
            SecurityStamp = "old-security", ConcurrencyStamp = "old-concurrency" };
        row.PasswordHash = operation == "create" ? null : hasher.HashPassword(row, "original-password");
        customers.Users.Add(row);
        await customers.SaveChangesAsync();
        var first = new CustomerSelfService(customers, state, hasher, TimeProvider.System);
        var second = new CustomerSelfService(otherCustomers, otherState, hasher, TimeProvider.System);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var passwords = new[] { "replacement-password-A", "replacement-password-B" };
        Task? firstPending = null;
        Task? secondPending = null;
        System.Runtime.ExceptionServices.ExceptionDispatchInfo? primary = null;
        var cleanupFailures = new List<Exception>();
        var transaction = await blocker.Database.BeginTransactionAsync(timeout.Token);
        try
        {
            await blocker.Database.ExecuteSqlRawAsync("SELECT * FROM \"AspNetUsers\" WHERE \"Id\" = 'owner' FOR UPDATE", timeout.Token);
            Task<CreateCustomerPasswordResult>? createA = null, createB = null;
            Task<bool>? changeA = null, changeB = null;
            if (operation == "create")
            {
                createA = first.CreatePasswordAsync(row.Id, new(passwords[0]), timeout.Token);
                firstPending = createA;
                createB = second.CreatePasswordAsync(row.Id, new(passwords[1]), timeout.Token);
                secondPending = createB;
            }
            else
            {
                changeA = first.ChangePasswordAsync(row.Id, new("original-password", passwords[0]), timeout.Token);
                firstPending = changeA;
                changeB = second.ChangePasswordAsync(row.Id, new("original-password", passwords[1]), timeout.Token);
                secondPending = changeB;
            }
            var waiters = 0;
            for (var attempt = 0; attempt < 500 && waiters != 2; attempt++)
            {
                waiters = await blocker.Database.SqlQuery<int>($"""
                    SELECT count(*)::integer AS "Value" FROM pg_stat_activity
                    WHERE datname = current_database() AND pid <> pg_backend_pid()
                      AND application_name IN ({firstName}, {secondName})
                      AND wait_event_type = 'Lock' AND query LIKE '%AspNetUsers%' AND query LIKE '%FOR UPDATE%'
                    """).SingleAsync(timeout.Token);
                if (waiters != 2) await Task.Delay(10, timeout.Token);
            }
            Assert.Equal(2, waiters);
            Assert.False(firstPending!.IsCompleted);
            Assert.False(secondPending!.IsCompleted);
            await transaction.CommitAsync(timeout.Token);
            int winner;
            if (operation == "create")
            {
                var results = await Task.WhenAll(createA!, createB!);
                Assert.Single(results, result => result == CreateCustomerPasswordResult.Created);
                Assert.Single(results, result => result == CreateCustomerPasswordResult.AlreadyExists);
                winner = Array.FindIndex(results, result => result == CreateCustomerPasswordResult.Created);
            }
            else
            {
                var results = await Task.WhenAll(changeA!, changeB!);
                Assert.Single(results, result => result);
                Assert.Single(results, result => !result);
                winner = Array.FindIndex(results, result => result);
            }
            var current = await customers.Users.AsNoTracking().SingleAsync();
            Assert.Equal(PasswordVerificationResult.Success, hasher.VerifyHashedPassword(current, current.PasswordHash!, passwords[winner]));
            Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyHashedPassword(current, current.PasswordHash!, passwords[1 - winner]));
            Assert.NotEqual("old-security", current.SecurityStamp);
            Assert.NotEqual("old-concurrency", current.ConcurrencyStamp);
        }
        catch (Exception failure) { primary = System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure); }
        finally
        {
            try { await transaction.DisposeAsync(); } catch (Exception failure) { cleanupFailures.Add(failure); }
            if ((firstPending is { IsCompleted: false } || secondPending is { IsCompleted: false }) && (primary is not null || cleanupFailures.Count > 0))
            {
                try { timeout.Cancel(); } catch (Exception failure) { cleanupFailures.Add(failure); }
            }
            async Task JoinAsync(Task? pending)
            {
                if (pending is null) return;
                try { await pending; }
                catch (OperationCanceledException) when (timeout.IsCancellationRequested) { }
                catch (Exception failure) { if (!ReferenceEquals(primary?.SourceException, failure)) cleanupFailures.Add(failure); }
            }
            await JoinAsync(firstPending);
            await JoinAsync(secondPending);
        }
        if (primary is not null)
        {
            if (cleanupFailures.Count > 0)
            {
                try { primary.SourceException.Data["OwnedPasswordCleanupFailures"] = new AggregateException(cleanupFailures); } catch { }
            }
            primary.Throw();
        }
        if (cleanupFailures.Count > 0) throw new AggregateException("Owned password cleanup failed.", cleanupFailures);
    }
}
