using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.AuthService.Api.Authorization;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class EmployeeRecoveryWorkerFairnessTests(PostgresFixture postgres)
{
    private const string Root = "/auth/v1/employee-self-service/";
    private const string OriginalPassword = "fairness-original-password";
    private const string AppliedPassword = "fairness-applied-password";

    [Theory]
    [InlineData("highwater-query")]
    [InlineData("batch-query")]
    public async Task ScanQueryFailure_PropagatesWithoutEffects_AndIndependentRetryKeepsCursorValid(string position)
    {
        await using var stores = await Stores.CreateAsync(postgres, 2);
        var faults = new Faults();
        await using var factory = new Factory(stores, faults);
        using var owner = await factory.OwnerAsync();
        await PendingAsync(stores, owner, 2);
        var before = await IdentitySnapshotAsync(stores);
        faults.Mode = position;
        await Assert.ThrowsAsync<InvalidOperationException>(() => factory.Worker.ReconcileBatchAsync(default));
        Assert.True(faults.Triggered);
        Assert.All(await stores.Employees.RecoveryEffects.AsNoTracking().ToListAsync(), value => Assert.Null(value.FinalizedAcknowledgedAt));
        Assert.All(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync(), value => Assert.Null(value.ConsumedAt));
        Assert.Equal(before, await IdentitySnapshotAsync(stores));
        faults.Mode = "none";
        Assert.Equal(2, await factory.Worker.ReconcileBatchAsync(default));
    }

    [Fact]
    public async Task PhysicalReadinessFailure_PropagatesBeforeCursorOrDeliveryMutation()
    {
        await using var stores = await Stores.CreateAsync(postgres, 1);
        var faults = new Faults();
        await using var factory = new Factory(stores, faults);
        using var owner = await factory.OwnerAsync();
        var action = Assert.Single(await PendingAsync(stores, owner, 1));
        var before = await IdentitySnapshotAsync(stores);
        faults.Mode = "none";
        await stores.Employees.Database.ExecuteSqlRawAsync("DROP INDEX \"IX_EmployeeRecoveryEffects_TokenSha256_Purpose\"");
        await Assert.ThrowsAsync<EmployeeRecoveryUnavailableException>(() => factory.Worker.ReconcileBatchAsync(default));
        await AssertPoisonPendingAsync(stores, [action.Id]);
        Assert.Equal(before, await IdentitySnapshotAsync(stores));
        await stores.Employees.Database.ExecuteSqlRawAsync("CREATE UNIQUE INDEX \"IX_EmployeeRecoveryEffects_TokenSha256_Purpose\" ON \"EmployeeRecoveryEffects\" (\"TokenSha256\", \"Purpose\")");
        Assert.Equal(1, await factory.Worker.ReconcileBatchAsync(default));
    }

    [Fact]
    public async Task TiedAppliedAt_UsesPostgresUuidOrder_AndRetainsCursorAcrossFreshScopes()
    {
        await using var stores = await Stores.CreateAsync(postgres, 35);
        var faults = new Faults();
        await using var factory = new Factory(stores, faults);
        using var owner = await factory.OwnerAsync();
        await PendingAsync(stores, owner, 35);
        await stores.Employees.RecoveryEffects.ExecuteUpdateAsync(setters => setters.SetProperty(value => value.AppliedAt, DateTimeOffset.Parse("2026-01-01T00:00:00Z")));
        var expected = await stores.Employees.Database.SqlQueryRaw<Guid>("SELECT \"ActionId\" AS \"Value\" FROM \"EmployeeRecoveryEffects\" ORDER BY \"ActionId\" LIMIT 32").ToListAsync();
        var before = await IdentitySnapshotAsync(stores);
        faults.Mode = "none";
        Assert.Equal(32, await factory.Worker.ReconcileBatchAsync(default));
        var completed = await stores.Employees.RecoveryEffects.AsNoTracking().Where(value => value.FinalizedAcknowledgedAt != null).Select(value => value.ActionId).ToListAsync();
        Assert.Equal(expected.Order(), completed.Order());
        Assert.Equal(3, await factory.Worker.ReconcileBatchAsync(default));
        Assert.Equal(0, await factory.Worker.ReconcileBatchAsync(default));
        Assert.Equal(before, await IdentitySnapshotAsync(stores));
        Assert.All(await stores.Employees.RecoveryEffects.AsNoTracking().ToListAsync(), value => Assert.NotNull(value.FinalizedAcknowledgedAt));
    }

    [Fact]
    public async Task NewReceiptAboveTraversalHighwater_WaitsForNextTraversal()
    {
        await using var stores = await Stores.CreateAsync(postgres, 34);
        var faults = new Faults();
        await using var factory = new Factory(stores, faults);
        using var owner = await factory.OwnerAsync();
        await PendingAsync(stores, owner, 33);
        faults.Mode = "none";
        Assert.Equal(32, await factory.Worker.ReconcileBatchAsync(default));
        faults.Mode = "pending";
        var arrived = Assert.Single(await PendingAsync(stores, owner, 1, 33));
        faults.Mode = "none";
        Assert.Equal(1, await factory.Worker.ReconcileBatchAsync(default));
        await AssertPoisonPendingAsync(stores, [arrived.Id]);
        Assert.Equal(1, await factory.Worker.ReconcileBatchAsync(default));
        Assert.NotNull((await stores.Employees.RecoveryEffects.AsNoTracking().SingleAsync(value => value.ActionId == arrived.Id)).FinalizedAcknowledgedAt);
    }

    [Fact]
    public async Task FailedReceipt_RepairedBinding_IsRevisitedAfterWrapWithoutRepeatingIdentityEffect()
    {
        await using var stores = await Stores.CreateAsync(postgres, 2);
        var faults = new Faults();
        await using var factory = new Factory(stores, faults);
        using var owner = await factory.OwnerAsync();
        var actions = await PendingAsync(stores, owner, 2);
        var before = await IdentitySnapshotAsync(stores);
        await stores.State.IdentityActionTokens.Where(value => value.Id == actions[0].Id).ExecuteUpdateAsync(setters => setters.SetProperty(value => value.OwnerSubject, "service:wrong-owner"));
        faults.Mode = "none";
        var error = await Record.ExceptionAsync(() => factory.Worker.ReconcileBatchAsync(default));
        Assert.NotNull((await stores.Employees.RecoveryEffects.AsNoTracking().SingleAsync(value => value.ActionId == actions[1].Id)).FinalizedAcknowledgedAt);
        Assert.Null(error);
        await AssertPoisonPendingAsync(stores, [actions[0].Id]);
        await stores.State.IdentityActionTokens.Where(value => value.Id == actions[0].Id).ExecuteUpdateAsync(setters => setters.SetProperty(value => value.OwnerSubject, "service:legacy-intranet"));
        Assert.Equal(1, await factory.Worker.ReconcileBatchAsync(default));
        Assert.Equal(0, await factory.Worker.ReconcileBatchAsync(default));
        Assert.Equal(before, await IdentitySnapshotAsync(stores));
    }

    [Fact]
    public async Task ParallelEntries_AndCancelledGateWaiter_DoNotDoubleCountOrLoseCursor()
    {
        await using var stores = await Stores.CreateAsync(postgres, 33);
        var faults = new Faults();
        await using var factory = new Factory(stores, faults);
        using var owner = await factory.OwnerAsync();
        await PendingAsync(stores, owner, 33);
        var before = await IdentitySnapshotAsync(stores);
        faults.Mode = "block";
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var first = factory.Worker.ReconcileBatchAsync(deadline.Token);
        await faults.Entered.Task.WaitAsync(deadline.Token);
        using var cancellation = new CancellationTokenSource();
        var cancelled = factory.Worker.ReconcileBatchAsync(cancellation.Token);
        var parallel = factory.Worker.ReconcileBatchAsync(deadline.Token);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        faults.Release.TrySetResult();
        var counts = await Task.WhenAll(first, parallel);
        Assert.Equal(new[] { 1, 32 }, counts.Order());
        Assert.Equal(0, await factory.Worker.ReconcileBatchAsync(deadline.Token));
        Assert.All(await stores.Employees.RecoveryEffects.AsNoTracking().ToListAsync(), value => Assert.NotNull(value.FinalizedAcknowledgedAt));
        Assert.Equal(before, await IdentitySnapshotAsync(stores));
    }

    [Fact]
    public async Task ActualWorkerExecute_DeliversThroughSameEntry_AndStopsWithinDeadline()
    {
        await using var stores = await Stores.CreateAsync(postgres, 1);
        var faults = new Faults();
        await using var factory = new Factory(stores, faults);
        using var owner = await factory.OwnerAsync();
        var action = Assert.Single(await PendingAsync(stores, owner, 1));
        faults.Mode = "none";
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await factory.Worker.StartAsync(deadline.Token);
        try { await faults.Acknowledged.Task.WaitAsync(deadline.Token); }
        finally { await factory.Worker.StopAsync(deadline.Token); }
        Assert.NotNull((await stores.Employees.RecoveryEffects.AsNoTracking().SingleAsync(value => value.ActionId == action.Id)).FinalizedAcknowledgedAt);
        Assert.Equal(0, await factory.Worker.ReconcileBatchAsync(deadline.Token));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(32)]
    public async Task InvalidOlderReceipts_DoNotStarveUnrelatedCommittedEffect(int poisonCount)
    {
        await using var stores = await Stores.CreateAsync(postgres, poisonCount + 1);
        var faults = new Faults();
        await using var factory = new Factory(stores, faults);
        using var owner = await factory.OwnerAsync();
        using var anonymous = factory.Client();
        var oldEmployee = await LoginAsync(anonymous, "employee-" + poisonCount + "@example.com", OriginalPassword, IdentityKind.Employee);
        var customer = await LoginAsync(anonymous, "customer@example.com", OriginalPassword, IdentityKind.Customer);
        var actions = await PendingAsync(stores, owner, poisonCount + 1);
        var poisoned = actions.Take(poisonCount).Select(value => value.Id).ToArray();
        await stores.State.IdentityActionTokens.Where(value => poisoned.Contains(value.Id))
            .ExecuteUpdateAsync(setters => setters.SetProperty(value => value.OwnerSubject, "service:wrong-owner"));
        faults.Mode = "none";
        var applied = await IdentitySnapshotAsync(stores);
        var newer = await LoginAsync(anonymous, "employee-" + poisonCount + "@example.com", AppliedPassword, IdentityKind.Employee);

        // Two bounded passes are enough to move beyond a complete poisoned first page.
        // Retain failures so assertions prove durable starvation, not merely an escaped exception.
        var failures = await RunPassesAsync(factory, 2);
        await AssertPoisonPendingAsync(stores, poisoned);
        Assert.Equal(applied, await IdentitySnapshotAsync(stores));
        await AssertHealthyAsync(stores, anonymous, actions[^1], oldEmployee, newer, customer, applied);
        Assert.All(failures, value => Assert.Null(value));
        using var replay = await owner.PostAsJsonAsync(Root + "password-reset/complete",
            new CompleteEmployeePasswordResetRequest("employee-" + poisonCount + "@example.com", actions[^1].Token, AppliedPassword));
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }

    [Theory]
    [InlineData("finalization")]
    [InlineData("auth-commit")]
    [InlineData("acknowledgment")]
    public async Task ReceiptLocalFailure_DoesNotBlockOtherIdentity_AndNextPassConverges(string position)
    {
        await using var stores = await Stores.CreateAsync(postgres, 2);
        var faults = new Faults();
        await using var factory = new Factory(stores, faults);
        using var owner = await factory.OwnerAsync();
        using var anonymous = factory.Client();
        var employee = await LoginAsync(anonymous, "employee-1@example.com", OriginalPassword, IdentityKind.Employee);
        var customer = await LoginAsync(anonymous, "customer@example.com", OriginalPassword, IdentityKind.Customer);
        var actions = await PendingAsync(stores, owner, 2);
        var applied = await IdentitySnapshotAsync(stores);
        var newer = await LoginAsync(anonymous, "employee-1@example.com", AppliedPassword, IdentityKind.Employee);
        faults.Mode = position;
        faults.TargetId = actions[0].Id;
        var failures = await RunPassesAsync(factory, 1);
        Assert.True(faults.Triggered);
        var first = await stores.State.IdentityActionTokens.AsNoTracking().SingleAsync(value => value.Id == actions[0].Id);
        Assert.Equal(position == "finalization", first.FinalizedAt is null);
        Assert.Null((await stores.Employees.RecoveryEffects.AsNoTracking().SingleAsync(value => value.ActionId == actions[0].Id)).FinalizedAcknowledgedAt);
        Assert.Equal(applied, await IdentitySnapshotAsync(stores));
        await AssertHealthyAsync(stores, anonymous, actions[1], employee, newer, customer, applied);
        Assert.All(failures, value => Assert.Null(value));
        faults.Mode = "none";
        Assert.All(await RunPassesAsync(factory, 2), value => Assert.Null(value));
        Assert.All(await stores.Employees.RecoveryEffects.AsNoTracking().ToListAsync(), value => Assert.NotNull(value.FinalizedAcknowledgedAt));
        Assert.Equal(applied, await IdentitySnapshotAsync(stores));
    }

    [Fact]
    public async Task CancellationDuringFinalization_PropagatesAndLeavesEffectsPendingForIndependentPass()
    {
        await using var stores = await Stores.CreateAsync(postgres, 2);
        var faults = new Faults();
        await using var factory = new Factory(stores, faults);
        using var owner = await factory.OwnerAsync();
        var actions = await PendingAsync(stores, owner, 2);
        var before = await IdentitySnapshotAsync(stores);
        using var cancellation = new CancellationTokenSource();
        faults.Mode = "cancel";
        faults.Cancellation = cancellation;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => factory.Worker.ReconcileBatchAsync(cancellation.Token));
        Assert.True(faults.Triggered);
        Assert.All(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync(), value => Assert.Null(value.ConsumedAt));
        Assert.All(await stores.Employees.RecoveryEffects.AsNoTracking().ToListAsync(), value => Assert.Null(value.FinalizedAcknowledgedAt));
        Assert.Equal(before, await IdentitySnapshotAsync(stores));
        faults.Mode = "none";
        Assert.All(await RunPassesAsync(factory, 1), value => Assert.Null(value));
        Assert.All(await stores.State.IdentityActionTokens.AsNoTracking().ToListAsync(), value => Assert.NotNull(value.FinalizedAt));
        Assert.Equal(actions.Count, await stores.Employees.RecoveryEffects.CountAsync());
        Assert.Equal(before, await IdentitySnapshotAsync(stores));
    }

    [Fact]
    public async Task InvalidReceipt_RemainsPendingAndCannotAuthorizeWorkerOrAdministrator()
    {
        await using var stores = await Stores.CreateAsync(postgres, 1);
        var faults = new Faults();
        await using var factory = new Factory(stores, faults);
        using var owner = await factory.OwnerAsync();
        var action = Assert.Single(await PendingAsync(stores, owner, 1));
        await stores.State.IdentityActionTokens.Where(value => value.Id == action.Id)
            .ExecuteUpdateAsync(setters => setters.SetProperty(value => value.OwnerSubject, "service:wrong-owner"));
        faults.Mode = "none";
        var before = await IdentitySnapshotAsync(stores);
        await RunPassesAsync(factory, 2);
        await AssertPoisonPendingAsync(stores, [action.Id]);
        await using var scope = factory.Services.CreateAsyncScope();
        await Assert.ThrowsAsync<EmployeeRecoveryUnavailableException>(() => scope.ServiceProvider.GetRequiredService<IEmployeeIdentityAdminService>().DeleteAsync(1000, default));
        Assert.Equal(before, await IdentitySnapshotAsync(stores));
        using var wrong = await owner.PostAsJsonAsync(Root + "password-reset/complete",
            new CompleteEmployeePasswordResetRequest("employee-0@example.com", action.Token, AppliedPassword));
        Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
    }

    [Fact]
    public async Task HealthyReceipt_FinalizesExactlyOnce_PreservesCustomerAndNewEmployeeGeneration()
    {
        await using var stores = await Stores.CreateAsync(postgres, 1);
        var faults = new Faults();
        await using var factory = new Factory(stores, faults);
        using var owner = await factory.OwnerAsync();
        using var anonymous = factory.Client();
        var old = await LoginAsync(anonymous, "employee-0@example.com", OriginalPassword, IdentityKind.Employee);
        var customer = await LoginAsync(anonymous, "customer@example.com", OriginalPassword, IdentityKind.Customer);
        var action = Assert.Single(await PendingAsync(stores, owner, 1));
        var applied = await IdentitySnapshotAsync(stores);
        var newer = await LoginAsync(anonymous, "employee-0@example.com", AppliedPassword, IdentityKind.Employee);
        faults.Mode = "none";
        Assert.All(await RunPassesAsync(factory, 2), value => Assert.Null(value));
        await AssertHealthyAsync(stores, anonymous, action, old, newer, customer, applied);
    }

    private static async Task AssertHealthyAsync(Stores stores, HttpClient anonymous, Pending action, TokenResponse old, TokenResponse newer, TokenResponse customer, string applied)
    {
        var row = await stores.State.IdentityActionTokens.AsNoTracking().SingleAsync(value => value.Id == action.Id);
        Assert.NotNull(row.FinalizedAt);
        Assert.NotNull(row.ConsumedAt);
        Assert.Equal(action.Id, row.EffectActionId);
        Assert.Equal(1, row.RecoveryVersion);
        var receipt = await stores.Employees.RecoveryEffects.AsNoTracking().SingleAsync(value => value.ActionId == action.Id);
        Assert.NotNull(receipt.FinalizedAcknowledgedAt);
        Assert.Equal(applied, await IdentitySnapshotAsync(stores));
        var sessions = await stores.State.RefreshSessions.AsNoTracking().ToListAsync();
        Assert.All(sessions.Where(value => value.IdentityKind == IdentityKind.Customer), value => Assert.Null(value.RevokedAt));
        Assert.All(sessions.Where(value => value.IdentityKind == IdentityKind.Employee && value.IdentityId == row.IdentityId && value.SecurityStamp == receipt.BeforeSecurityStamp), value => Assert.NotNull(value.RevokedAt));
        Assert.All(sessions.Where(value => value.IdentityKind == IdentityKind.Employee && value.IdentityId == row.IdentityId && value.SecurityStamp == receipt.AfterSecurityStamp), value => Assert.Null(value.RevokedAt));
        using var oldRefresh = await anonymous.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(old.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, oldRefresh.StatusCode);
        using var newRefresh = await anonymous.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(newer.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, newRefresh.StatusCode);
        using var customerRefresh = await anonymous.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(customer.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, customerRefresh.StatusCode);
    }

    private static async Task AssertPoisonPendingAsync(Stores stores, Guid[] ids)
    {
        var actions = await stores.State.IdentityActionTokens.AsNoTracking().Where(value => ids.Contains(value.Id)).ToListAsync();
        Assert.Equal(ids.Length, actions.Count);
        Assert.All(actions, value =>
        {
            Assert.Null(value.ConsumedAt);
            Assert.Null(value.FinalizedAt);
            Assert.Null(value.EffectActionId);
        });
        var receipts = await stores.Employees.RecoveryEffects.AsNoTracking().Where(value => ids.Contains(value.ActionId)).ToListAsync();
        Assert.Equal(ids.Length, receipts.Count);
        Assert.All(receipts, value => Assert.Null(value.FinalizedAcknowledgedAt));
    }

    private static async Task<List<Exception?>> RunPassesAsync(Factory factory, int count)
    {
        var failures = new List<Exception?>();
        for (var index = 0; index < count; index++)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            failures.Add(await Record.ExceptionAsync(() => factory.Worker.ReconcileBatchAsync(deadline.Token)));
        }
        return failures;
    }

    private static async Task<List<Pending>> PendingAsync(Stores stores, HttpClient owner, int count, int start = 0)
    {
        var result = new List<Pending>();
        for (var index = start; index < start + count; index++)
        {
            var email = "employee-" + index + "@example.com";
            using var issued = await owner.PostAsJsonAsync(Root + "password-reset/request", new EmployeeActionRequest(email));
            Assert.Equal(HttpStatusCode.OK, issued.StatusCode);
            var challenge = Assert.IsType<EmployeeActionChallenge>(await issued.Content.ReadFromJsonAsync<EmployeeActionChallenge>());
            Assert.NotNull(challenge.Token);
            using var response = await owner.PostAsJsonAsync(Root + "password-reset/complete", new CompleteEmployeePasswordResetRequest(email, challenge.Token, AppliedPassword));
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.DoesNotContain(challenge.Token, await response.Content.ReadAsStringAsync());
            var action = await stores.State.IdentityActionTokens.AsNoTracking().SingleAsync(value => value.IdentityId == "employee-" + index);
            var receipt = await stores.Employees.RecoveryEffects.AsNoTracking().SingleAsync(value => value.ActionId == action.Id);
            var identity = await stores.Employees.Users.AsNoTracking().SingleAsync(value => value.Id == action.IdentityId);
            Assert.Null(action.ConsumedAt);
            Assert.Null(receipt.FinalizedAcknowledgedAt);
            Assert.Equal(receipt.PasswordPayloadHash, identity.PasswordHash);
            Assert.Equal(receipt.AfterSecurityStamp, identity.SecurityStamp);
            Assert.Equal(receipt.AfterConcurrencyStamp, identity.ConcurrencyStamp);
            // Controlled deterministic ordering only; receipt/effect was genuinely committed through HTTP.
            await stores.Employees.RecoveryEffects.Where(value => value.ActionId == action.Id)
                .ExecuteUpdateAsync(setters => setters.SetProperty(value => value.AppliedAt, DateTimeOffset.Parse("2026-01-01T00:00:00Z").AddSeconds(index)));
            result.Add(new(action.Id, challenge.Token));
        }
        return result;
    }

    private static Task<string> IdentitySnapshotAsync(Stores stores) => SnapshotCoreAsync(stores);
    private static async Task<string> SnapshotCoreAsync(Stores stores) => JsonSerializer.Serialize(await stores.Employees.Users.AsNoTracking().OrderBy(value => value.Id).ToListAsync());
    private static async Task<TokenResponse> LoginAsync(HttpClient client, string email, string password, IdentityKind kind)
    {
        using var response = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest(email, password, kind));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return Assert.IsType<TokenResponse>(await response.Content.ReadFromJsonAsync<TokenResponse>());
    }
    private sealed record Pending(Guid Id, string Token);

    private sealed class Faults : DbCommandInterceptor
    {
        private string mode = "pending";
        public string Mode { get => mode; set { mode = value; Triggered = false; } }
        public Guid TargetId { get; set; }
        public bool Triggered { get; private set; }
        public CancellationTokenSource? Cancellation { get; set; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Acknowledged { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void MarkTriggered() => Triggered = true;
        public override ValueTask<InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(System.Data.Common.DbCommand command, CommandEventData eventData, InterceptionResult<System.Data.Common.DbDataReader> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("EmployeeRecoveryEffects", StringComparison.Ordinal)
                && (Mode == "highwater-query" && command.CommandText.Contains("DESC", StringComparison.Ordinal)
                    || Mode == "batch-query" && command.CommandText.Contains("LIMIT 32", StringComparison.Ordinal)))
            {
                Triggered = true;
                throw new InvalidOperationException("Synthetic scan query failure.");
            }
            return ValueTask.FromResult(result);
        }
        public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(System.Data.Common.DbCommand command, CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.StartsWith("UPDATE", StringComparison.Ordinal))
            {
                if (Mode == "block" && command.CommandText.Contains("refresh_sessions", StringComparison.Ordinal) && !Triggered)
                {
                    Triggered = true;
                    Entered.TrySetResult();
                    await Release.Task.WaitAsync(cancellationToken);
                }
                if (command.CommandText.Contains("refresh_sessions", StringComparison.Ordinal)
                    && (Mode is "pending" or "cancel" || Mode == "finalization" && !Triggered))
                {
                    Triggered = true;
                    if (Mode == "cancel")
                    {
                        Cancellation!.Cancel();
                        cancellationToken.ThrowIfCancellationRequested();
                    }
                    throw new InvalidOperationException("Synthetic receipt-local finalization fault.");
                }
                if (Mode == "acknowledgment" && command.CommandText.Contains("EmployeeRecoveryEffects", StringComparison.Ordinal)
                    && command.Parameters.Cast<System.Data.Common.DbParameter>().Any(value => value.Value is Guid id && id == TargetId))
                {
                    Triggered = true;
                    throw new InvalidOperationException("Synthetic receipt-local acknowledgment fault.");
                }
            }
            return result;
        }
        public override ValueTask<int> NonQueryExecutedAsync(System.Data.Common.DbCommand command, CommandExecutedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            if (Mode != "pending" && command.CommandText.StartsWith("UPDATE", StringComparison.Ordinal) && command.CommandText.Contains("EmployeeRecoveryEffects", StringComparison.Ordinal)) Acknowledged.TrySetResult();
            return ValueTask.FromResult(result);
        }
    }

    private sealed class CommitFault(Faults faults) : DbTransactionInterceptor
    {
        public bool Triggered { get; private set; }
        public override Task TransactionCommittedAsync(System.Data.Common.DbTransaction transaction, TransactionEndEventData eventData, CancellationToken cancellationToken = default)
        {
            if (faults.Mode == "auth-commit" && !Triggered)
            {
                Triggered = true;
                faults.MarkTriggered();
                throw new InvalidOperationException("Synthetic postcommit receipt-local fault.");
            }
            return Task.CompletedTask;
        }
    }

    private sealed class Factory(Stores stores, Faults faults) : WebApplicationFactory<Program>
    {
        private readonly RSA signing = RSA.Create(2048);
        private readonly string secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        public CommitFault CommitFault { get; } = new(faults);
        public EmployeeRecoveryWorker Worker => Services.GetRequiredService<EmployeeRecoveryWorker>();
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:CustomerIdentity"] = stores.Customers.Database.GetConnectionString(),
                ["ConnectionStrings:EmployeeIdentity"] = stores.Employees.Database.GetConnectionString(),
                ["ConnectionStrings:RefreshSessions"] = stores.State.Database.GetConnectionString(),
                ["Jwt:Issuer"] = "https://worker-fairness.test",
                ["Jwt:Audience"] = "worker-fairness-test",
                ["Jwt:PrivateKeyPem"] = signing.ExportPkcs8PrivateKeyPem(),
                ["Jwt:KeyId"] = "worker-fairness-test",
                ["ServiceClients:Clients:legacy-intranet:SecretSha256"] = ServiceClientCredential.HashSecret(secret),
                ["ServiceClients:Clients:legacy-intranet:Permissions:0"] = EmployeeSelfServicePermissions.Use,
                ["EmployeeRecovery:Enabled"] = "true",
            }));
            builder.ConfigureTestServices(services =>
            {
                // Suppress only automatic scheduling, never replace the registered recovery service or authentication.
                var worker = services.Single(value => value.ServiceType == typeof(IHostedService) && value.ImplementationType == typeof(EmployeeRecoveryWorker));
                services.Remove(worker);
                services.AddSingleton<EmployeeRecoveryWorker>();
                services.AddDbContext<RefreshSessionDbContext>(options => options.AddInterceptors(faults, CommitFault));
                services.AddDbContext<EmployeeIdentityDbContext>(options => options.AddInterceptors(faults));
            });
        }
        public HttpClient Client(string? token = null)
        {
            var client = CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
            if (token is not null) client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return client;
        }
        public async Task<HttpClient> OwnerAsync()
        {
            using var client = Client();
            using var response = await client.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest("legacy-intranet", secret));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return Client(Assert.IsType<ServiceTokenResponse>(await response.Content.ReadFromJsonAsync<ServiceTokenResponse>()).AccessToken);
        }
        public override async ValueTask DisposeAsync()
        {
            var connections = new List<NpgsqlConnection>();
            await using (var scope = Services.CreateAsyncScope())
            {
                foreach (var context in new DbContext[] { scope.ServiceProvider.GetRequiredService<CustomerIdentityDbContext>(), scope.ServiceProvider.GetRequiredService<EmployeeIdentityDbContext>(), scope.ServiceProvider.GetRequiredService<RefreshSessionDbContext>() })
                {
                    await context.Database.OpenConnectionAsync();
                    connections.Add((NpgsqlConnection)context.Database.GetDbConnection());
                    await context.Database.CloseConnectionAsync();
                }
            }
            await base.DisposeAsync();
            signing.Dispose();
            foreach (var connection in connections) NpgsqlConnection.ClearPool(connection);
        }
    }

    private sealed class Stores(CustomerIdentityDbContext customers, EmployeeIdentityDbContext employees, RefreshSessionDbContext state) : IAsyncDisposable
    {
        public CustomerIdentityDbContext Customers { get; } = customers;
        public EmployeeIdentityDbContext Employees { get; } = employees;
        public RefreshSessionDbContext State { get; } = state;
        public static async Task<Stores> CreateAsync(PostgresFixture postgres, int count)
        {
            var stores = new Stores(await postgres.CreateCustomerContextAsync(), await postgres.CreateEmployeeContextAsync(), await postgres.CreateStateContextAsync());
            for (var index = 0; index < count; index++) stores.Employees.Users.Add(Identity("employee-" + index, "employee-" + index + "@example.com", 1000 + index));
            // Same textual ID in an independent identity namespace; no invented global-ID guarantee.
            stores.Customers.Users.Add(Identity("employee-" + (count - 1), "customer@example.com", 9000));
            await stores.Employees.SaveChangesAsync();
            await stores.Customers.SaveChangesAsync();
            return stores;
        }
        private static LegacyIdentityRow Identity(string id, string email, int databaseId)
        {
            var row = new LegacyIdentityRow { Id = id, DatabaseID = databaseId, UserName = email, NormalizedUserName = email.ToUpperInvariant(), Email = email, NormalizedEmail = email.ToUpperInvariant(), EmailConfirmed = true, SecurityStamp = "before-" + id, ConcurrencyStamp = Guid.NewGuid().ToString() };
            row.PasswordHash = new PasswordHasher<LegacyIdentityRow>().HashPassword(row, OriginalPassword);
            return row;
        }
        public async ValueTask DisposeAsync()
        {
            var connections = new[] { Customers.Database.GetDbConnection(), Employees.Database.GetDbConnection(), State.Database.GetDbConnection() };
            await Customers.DisposeAsync();
            await Employees.DisposeAsync();
            await State.DisposeAsync();
            foreach (var connection in connections) NpgsqlConnection.ClearPool((NpgsqlConnection)connection);
        }
    }
}
