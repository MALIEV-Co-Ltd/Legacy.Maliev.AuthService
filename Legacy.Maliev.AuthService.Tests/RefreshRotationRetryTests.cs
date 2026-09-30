using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

[Collection(PostgresCollection.Name)]
public sealed class RefreshRotationRetryTests(PostgresFixture postgres)
{
    [Fact]
    public async Task ProductionHttpRefresh_RotatesOnce_AndNewRequestReuseRevokesFamily()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        await using var factory = new HttpFactory(fixture);
        using var client = factory.CreateClient();
        using var login = await client.PostAsJsonAsync("/auth/v1/login", new LoginRequest("refresh-retry@example.com", "refresh-retry-password", IdentityKind.Employee));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var original = Assert.IsType<TokenResponse>(await login.Content.ReadFromJsonAsync<TokenResponse>());
        using var refresh = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(original.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
        var replacement = Assert.IsType<TokenResponse>(await refresh.Content.ReadFromJsonAsync<TokenResponse>());
        Assert.NotEqual(original.RefreshToken, replacement.RefreshToken);
        var hash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(original.RefreshToken)));
        var persisted = await fixture.State.RefreshSessions.AsNoTracking().SingleAsync(x => x.TokenHash == hash);
        var rows = await fixture.State.RefreshSessions.AsNoTracking().Where(x => x.FamilyId == persisted.FamilyId).ToListAsync();
        Assert.Equal(2, rows.Count);
        Assert.All(rows, row => Assert.Null(row.RevokedAt));
        Assert.NotNull(persisted.RotatedAt);
        Assert.Equal(Assert.Single(rows, row => row.Id != persisted.Id).Id, persisted.ReplacedById);
        using var reuse = await client.PostAsJsonAsync("/auth/v1/refresh", new RefreshRequest(original.RefreshToken));
        Assert.False(reuse.IsSuccessStatusCode);
        Assert.All(await fixture.State.RefreshSessions.AsNoTracking().Where(x => x.FamilyId == persisted.FamilyId).ToListAsync(), row => Assert.NotNull(row.RevokedAt));
    }

    [Fact]
    public async Task ConcurrentFamilyRevocation_WaitsForRotation_RevokesNewReplacementToo()
    {
        var fault = new PauseRotationFault();
        var observer = new RevokeCommandObserver();
        await using var fixture = await Fixture.CreateAsync(postgres, fault, observer);
        using var rotationScope = fixture.Provider.CreateScope();
        var rotation = rotationScope.ServiceProvider.GetRequiredService<IRefreshSessionStore>()
            .RotateAsync(fixture.Original.TokenHash, Replacement(), default);
        await fault.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        observer.Enabled = true;
        using var revokeScope = fixture.Provider.CreateScope();
        var revoke = revokeScope.ServiceProvider.GetRequiredService<IRefreshSessionStore>()
            .RevokeFamilyAsync(fixture.Original.TokenHash, DateTimeOffset.UtcNow, default);
        try
        {
            await observer.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await using var observation = new NpgsqlConnection(fixture.State.Database.GetConnectionString());
            await observation.OpenAsync();
            var deadline = DateTime.UtcNow.AddSeconds(10);
            var blocked = false;
            while (DateTime.UtcNow < deadline && !blocked)
            {
                await using var command = new NpgsqlCommand("SELECT wait_event_type = 'Lock' FROM pg_stat_activity WHERE pid = @pid", observation);
                command.Parameters.AddWithValue("pid", observer.ProcessId);
                blocked = await command.ExecuteScalarAsync() is true;
                if (!blocked) await Task.Delay(20);
            }
            Assert.True(blocked, "Revoke must be observed waiting on a real PostgreSQL lock before rotation is released.");
        }
        finally { fault.Release.TrySetResult(); }
        await Task.WhenAll(rotation, revoke);
        Assert.Equal(RefreshRotationStatus.Succeeded, (await rotation).Status);
        var rows = await fixture.State.RefreshSessions.AsNoTracking().ToListAsync();
        Assert.Equal(2, rows.Count);
        Assert.All(rows, row => Assert.NotNull(row.RevokedAt));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LostCommitAcknowledgement_LogoutOrStampChangeBeforeRetry_FailsClosed(bool stampChange)
    {
        var fault = new LostCommitFault();
        await using var fixture = await Fixture.CreateAsync(postgres, fault);
        fault.BeforeFailure = async () =>
        {
            if (stampChange)
                await fixture.Employees.Users.Where(user => user.Id == "refresh-retry-employee")
                    .ExecuteUpdateAsync(setters => setters.SetProperty(user => user.SecurityStamp, "changed-stamp"));
            else
            {
                using var logoutScope = fixture.Provider.CreateScope();
                await logoutScope.ServiceProvider.GetRequiredService<IRefreshSessionStore>()
                    .RevokeFamilyAsync(fixture.Original.TokenHash, DateTimeOffset.UtcNow, default);
            }
        };
        using var scope = fixture.Provider.CreateScope();
        var result = await scope.ServiceProvider.GetRequiredService<IRefreshSessionStore>()
            .RotateAsync(fixture.Original.TokenHash, Replacement(), default);
        Assert.True(fault.Injected);
        Assert.Equal(RefreshRotationStatus.Invalid, result.Status);
        Assert.Null(result.IdentityId);
        Assert.All(await fixture.State.RefreshSessions.AsNoTracking().ToListAsync(), row => Assert.NotNull(row.RevokedAt));
    }

    [Fact]
    public async Task LostCommitAcknowledgement_ReceiptWaitsForLogout_MustNotUsePreFenceSnapshot()
    {
        var fault = new LostCommitFault();
        var pause = new PauseRevocationCommit();
        var observer = new RevokeCommandObserver();
        await using var fixture = await Fixture.CreateAsync(postgres, fault, pause, observer);
        Task? logout = null;
        fault.BeforeFailure = async () =>
        {
            pause.Enabled = true;
            logout = Task.Run(async () =>
            {
                using var logoutScope = fixture.Provider.CreateScope();
                await logoutScope.ServiceProvider.GetRequiredService<IRefreshSessionStore>()
                    .RevokeFamilyAsync(fixture.Original.TokenHash, DateTimeOffset.UtcNow, default);
            });
            await pause.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
            observer.Enabled = true;
        };
        using var scope = fixture.Provider.CreateScope();
        var rotation = scope.ServiceProvider.GetRequiredService<IRefreshSessionStore>()
            .RotateAsync(fixture.Original.TokenHash, Replacement(), default);
        try
        {
            await observer.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await using var connection = new NpgsqlConnection(fixture.State.Database.GetConnectionString());
            await connection.OpenAsync();
            var blocked = false;
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (!blocked && DateTime.UtcNow < deadline)
            {
                await using var command = new NpgsqlCommand("SELECT wait_event_type = 'Lock' FROM pg_stat_activity WHERE pid = @pid", connection);
                command.Parameters.AddWithValue("pid", observer.ProcessId);
                blocked = await command.ExecuteScalarAsync() is true;
                if (!blocked) await Task.Delay(20);
            }
            Assert.True(blocked, "Reconciliation must wait on the actual uncommitted logout family fence.");
        }
        finally { pause.Release.TrySetResult(); }
        Assert.NotNull(logout);
        await logout;
        Assert.True(fault.Injected);
        Assert.Equal(RefreshRotationStatus.Invalid, (await rotation).Status);
        Assert.All(await fixture.State.RefreshSessions.AsNoTracking().ToListAsync(), row => Assert.NotNull(row.RevokedAt));
    }

    private sealed class PauseRevocationCommit : DbTransactionInterceptor
    {
        public bool Enabled { get; set; }
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction, TransactionEventData eventData, InterceptionResult result, CancellationToken cancellationToken = default)
        {
            if (Enabled)
            {
                Enabled = false;
                Started.TrySetResult();
                await Release.Task.WaitAsync(cancellationToken);
            }
            return result;
        }
    }

    [Fact]
    public async Task ConcurrentRotation_OnlyOneReplacement_ReuseRevokesWholeFamily()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        var replacements = new[] { Replacement(), Replacement() };
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var tasks = replacements.Select(async replacement =>
        {
            using var scope = fixture.Provider.CreateScope();
            await gate.Task;
            return await scope.ServiceProvider.GetRequiredService<IRefreshSessionStore>()
                .RotateAsync(fixture.Original.TokenHash, replacement, default);
        }).ToArray();
        gate.SetResult();
        var results = await Task.WhenAll(tasks);

        Assert.Single(results, result => result.Status == RefreshRotationStatus.Succeeded);
        Assert.Single(results, result => result.Status == RefreshRotationStatus.Reused);
        var rows = await fixture.State.RefreshSessions.AsNoTracking().ToListAsync();
        Assert.Equal(2, rows.Count);
        Assert.All(rows, row => Assert.NotNull(row.RevokedAt));
        Assert.All(rows, row => Assert.Equal(fixture.Original.FamilyId, row.FamilyId));
    }

    [Fact]
    public async Task KnownRollbackAfterSave_LeavesOriginalActiveAndNoReplacement()
    {
        var fault = new SavedFault(retryable: false);
        await using var fixture = await Fixture.CreateAsync(postgres, fault);
        var replacement = Replacement();
        using var scope = fixture.Provider.CreateScope();
        await Assert.ThrowsAsync<DbUpdateException>(() => scope.ServiceProvider.GetRequiredService<IRefreshSessionStore>()
            .RotateAsync(fixture.Original.TokenHash, replacement, default));

        Assert.True(fault.Injected);
        await AssertUnchangedAsync(fixture);
    }

    [Fact]
    public async Task RetryableFailureAfterSave_RetriesFreshContextAndCommitsOneReplacement()
    {
        var fault = new SavedFault(retryable: true);
        await using var fixture = await Fixture.CreateAsync(postgres, fault);
        var replacement = Replacement();
        using var scope = fixture.Provider.CreateScope();
        var result = await scope.ServiceProvider.GetRequiredService<IRefreshSessionStore>()
            .RotateAsync(fixture.Original.TokenHash, replacement, default);

        Assert.True(fault.Injected);
        Assert.True(fault.Contexts.Distinct().Count() >= 2);
        Assert.Equal(RefreshRotationStatus.Succeeded, result.Status);
        await AssertSuccessfulRotationAsync(fixture, replacement);
    }

    [Fact]
    public async Task LostCommitAcknowledgement_ReconcilesOriginalReplacementWithoutRevokingFamily()
    {
        var fault = new LostCommitFault();
        await using var fixture = await Fixture.CreateAsync(postgres, fault);
        var replacement = Replacement();
        using var scope = fixture.Provider.CreateScope();
        var result = await scope.ServiceProvider.GetRequiredService<IRefreshSessionStore>()
            .RotateAsync(fixture.Original.TokenHash, replacement, default);

        Assert.True(fault.Injected);
        Assert.Equal(RefreshRotationStatus.Succeeded, result.Status);
        await AssertSuccessfulRotationAsync(fixture, replacement);
        using var replayScope = fixture.Provider.CreateScope();
        var replay = await replayScope.ServiceProvider.GetRequiredService<IRefreshSessionStore>()
            .RotateAsync(fixture.Original.TokenHash, Replacement(), default);
        Assert.Equal(RefreshRotationStatus.Reused, replay.Status);
        Assert.All(await fixture.State.RefreshSessions.AsNoTracking().ToListAsync(), row => Assert.NotNull(row.RevokedAt));
    }

    [Fact]
    public async Task CancellationAfterSavedRows_RollsBackAndPropagatesCallerCancellation()
    {
        var fault = new PauseSavedFault();
        await using var fixture = await Fixture.CreateAsync(postgres, fault);
        using var scope = fixture.Provider.CreateScope();
        using var cancellation = new CancellationTokenSource();
        var operation = scope.ServiceProvider.GetRequiredService<IRefreshSessionStore>()
            .RotateAsync(fixture.Original.TokenHash, Replacement(), cancellation.Token);
        var first = await Task.WhenAny(fault.Started.Task, operation, Task.Delay(TimeSpan.FromSeconds(10)));
        if (first == operation) await operation;
        Assert.Same(fault.Started.Task, first);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);
        Assert.True(fault.Injected);
        await AssertUnchangedAsync(fixture);
    }

    [Fact]
    public async Task PrecancelledCaller_DoesNotRotateOrRevoke()
    {
        await using var fixture = await Fixture.CreateAsync(postgres);
        using var scope = fixture.Provider.CreateScope();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => scope.ServiceProvider.GetRequiredService<IRefreshSessionStore>()
            .RotateAsync(fixture.Original.TokenHash, Replacement(), cancellation.Token));
        await AssertUnchangedAsync(fixture);
    }

    private static RefreshSession Replacement() => new()
    {
        Id = Guid.NewGuid(),
        FamilyId = Guid.Empty,
        IdentityId = string.Empty,
        IdentityKind = IdentityKind.Customer,
        TokenHash = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N"),
        CreatedAt = DateTimeOffset.UtcNow,
        ExpiresAt = DateTimeOffset.UtcNow.AddDays(14),
    };

    private static async Task AssertUnchangedAsync(Fixture fixture)
    {
        var row = Assert.Single(await fixture.State.RefreshSessions.AsNoTracking().ToListAsync());
        Assert.Equal(fixture.Original.Id, row.Id);
        Assert.Null(row.RotatedAt);
        Assert.Null(row.ReplacedById);
        Assert.Null(row.RevokedAt);
    }

    private static async Task AssertSuccessfulRotationAsync(Fixture fixture, RefreshSession replacement)
    {
        var rows = await fixture.State.RefreshSessions.AsNoTracking().ToListAsync();
        Assert.Equal(2, rows.Count);
        var original = Assert.Single(rows, row => row.Id == fixture.Original.Id);
        var persisted = Assert.Single(rows, row => row.Id == replacement.Id);
        Assert.Equal(replacement.Id, original.ReplacedById);
        Assert.NotNull(original.RotatedAt);
        Assert.All(rows, row => Assert.Null(row.RevokedAt));
        Assert.Equal(fixture.Original.FamilyId, persisted.FamilyId);
        Assert.Equal("refresh-retry-employee", persisted.IdentityId);
        Assert.Equal(IdentityKind.Employee, persisted.IdentityKind);
        Assert.Equal("refresh-retry-stamp", persisted.SecurityStamp);
        Assert.Equal(replacement.TokenHash, persisted.TokenHash);
    }

    private sealed class SavedFault(bool retryable) : SaveChangesInterceptor
    {
        private int calls;
        public bool Injected { get; private set; }
        public List<Guid> Contexts { get; } = [];
        public override ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            Contexts.Add(eventData.Context!.ContextId.InstanceId);
            if (Interlocked.Increment(ref calls) == 1)
            {
                Injected = true;
                if (retryable) throw new NpgsqlException("Synthetic refresh rollback before commit.", new IOException("Synthetic connection interruption."));
                throw new DbUpdateException("Synthetic nonretryable refresh rollback before commit.");
            }
            return ValueTask.FromResult(result);
        }
    }

    private sealed class LostCommitFault : DbTransactionInterceptor
    {
        private int calls;
        public bool Injected { get; private set; }
        public Func<Task>? BeforeFailure { get; set; }
        public override async Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData eventData, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                Injected = true;
                if (BeforeFailure is not null) await BeforeFailure();
                throw new NpgsqlException("Synthetic refresh lost commit acknowledgement.", new IOException("Synthetic connection interruption."));
            }
        }
    }

    private sealed class PauseRotationFault : SaveChangesInterceptor
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            Started.TrySetResult();
            await Release.Task.WaitAsync(cancellationToken);
            return result;
        }
    }

    private sealed class RevokeCommandObserver : DbCommandInterceptor
    {
        public bool Enabled { get; set; }
        public int ProcessId { get; private set; }
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private void Observe(DbCommand command)
        {
            if (!Enabled) return;
            ProcessId = ((NpgsqlConnection)command.Connection!).ProcessID;
            Started.TrySetResult();
        }
        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            Observe(command);
            return ValueTask.FromResult(result);
        }
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            Observe(command);
            return ValueTask.FromResult(result);
        }
    }

    private sealed class PauseSavedFault : SaveChangesInterceptor
    {
        public bool Injected { get; private set; }
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            Injected = true;
            Started.SetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return result;
        }
    }

    private sealed class Fixture(EmployeeIdentityDbContext employees, CustomerIdentityDbContext customers, RefreshSessionDbContext state, ServiceProvider provider, RefreshSession original) : IAsyncDisposable
    {
        public EmployeeIdentityDbContext Employees { get; } = employees;
        public CustomerIdentityDbContext Customers { get; } = customers;
        public RefreshSessionDbContext State { get; } = state;
        public ServiceProvider Provider { get; } = provider;
        public RefreshSession Original { get; } = original;

        public static async Task<Fixture> CreateAsync(PostgresFixture postgres, params IInterceptor[] faults)
        {
            var employees = await postgres.CreateEmployeeContextAsync();
            var customers = await postgres.CreateCustomerContextAsync();
            var state = await postgres.CreateStateContextAsync();
            var employee = new LegacyIdentityRow
            {
                Id = "refresh-retry-employee",
                UserName = "refresh-retry@example.com",
                NormalizedUserName = "REFRESH-RETRY@EXAMPLE.COM",
                EmailConfirmed = true,
                SecurityStamp = "refresh-retry-stamp",
                LockoutEnabled = true,
            };
            employee.PasswordHash = new Microsoft.AspNetCore.Identity.PasswordHasher<LegacyIdentityRow>().HashPassword(employee, "refresh-retry-password");
            employees.Users.Add(employee);
            await employees.SaveChangesAsync();
            var original = Replacement();
            original.IdentityId = "refresh-retry-employee";
            original.IdentityKind = IdentityKind.Employee;
            original.SecurityStamp = "refresh-retry-stamp";
            original.FamilyId = Guid.NewGuid();
            state.RefreshSessions.Add(original);
            await state.SaveChangesAsync();
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:CustomerIdentity"] = customers.Database.GetConnectionString(),
                ["ConnectionStrings:EmployeeIdentity"] = employees.Database.GetConnectionString(),
                ["ConnectionStrings:RefreshSessions"] = state.Database.GetConnectionString(),
            }).Build();
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddSingleton<IConfiguration>(configuration);
            services.AddLegacyAuthInfrastructure(configuration);
            if (faults.Length > 0) services.AddDbContext<RefreshSessionDbContext>(options => options.AddInterceptors(faults));
            return new Fixture(employees, customers, state, services.BuildServiceProvider(), original);
        }

        public async ValueTask DisposeAsync()
        {
            var connections = new List<NpgsqlConnection>
            {
                (NpgsqlConnection)Employees.Database.GetDbConnection(),
                (NpgsqlConnection)Customers.Database.GetDbConnection(),
                (NpgsqlConnection)State.Database.GetDbConnection(),
            };
            // Normal registration adjusts pool settings, so its pools differ from
            // the migration fixture's connections. Capture those exact pools too.
            await using (var scope = Provider.CreateAsyncScope())
            {
                var contexts = new DbContext[]
                {
                    scope.ServiceProvider.GetRequiredService<EmployeeIdentityDbContext>(),
                    scope.ServiceProvider.GetRequiredService<CustomerIdentityDbContext>(),
                    scope.ServiceProvider.GetRequiredService<RefreshSessionDbContext>(),
                };
                foreach (var context in contexts)
                {
                    await context.Database.OpenConnectionAsync();
                    connections.Add((NpgsqlConnection)context.Database.GetDbConnection());
                    await context.Database.CloseConnectionAsync();
                }
            }
            await Provider.DisposeAsync();
            await Employees.DisposeAsync();
            await Customers.DisposeAsync();
            await State.DisposeAsync();
            // Unique per-test databases must not leave their idle pools consuming
            // the collection container's connection budget. Never clear others.
            foreach (var connection in connections) NpgsqlConnection.ClearPool(connection);
        }
    }

    private sealed class HttpFactory(Fixture fixture) : WebApplicationFactory<Program>
    {
        private readonly RSA signing = RSA.Create(2048);
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:EmployeeIdentity"] = fixture.Employees.Database.GetConnectionString(),
                ["ConnectionStrings:CustomerIdentity"] = fixture.Customers.Database.GetConnectionString(),
                ["ConnectionStrings:RefreshSessions"] = fixture.State.Database.GetConnectionString(),
                ["Jwt:Issuer"] = "https://refresh.test",
                ["Jwt:Audience"] = "refresh-test",
                ["Jwt:PrivateKeyPem"] = signing.ExportPkcs8PrivateKeyPem(),
                ["Jwt:KeyId"] = "refresh-test",
            }));
        }
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing) signing.Dispose();
        }
    }
}
