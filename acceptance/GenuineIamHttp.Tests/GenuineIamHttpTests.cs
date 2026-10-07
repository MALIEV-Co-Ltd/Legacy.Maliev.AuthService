extern alias AuthApi;
extern alias AuthInfrastructure;
extern alias LegacyDefaults;

using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using Testcontainers.PostgreSql;
using AuthProgram = AuthApi::Program;
using Defaults = LegacyDefaults::Microsoft.Extensions.Hosting.Extensions;
using Exchange = LegacyDefaults::Microsoft.Extensions.Hosting.LegacyServiceAuthenticationExtensions;
using Profile = LegacyDefaults::Maliev.Aspire.ServiceDefaults.LegacyAuth.LegacyServiceAccessTokenProvider;

namespace Legacy.Maliev.AuthService.GenuineIamHttp.Tests;

[CollectionDefinition("Genuine IAM HTTP", DisableParallelization = true)]
public sealed class GenuineIamHttpCollection : ICollectionFixture<GenuineIamHttpFixture> { }

[Collection("Genuine IAM HTTP")]
public sealed class GenuineIamHttpTests(GenuineIamHttpFixture fixture)
{
    [Theory]
    [InlineData("allowed", HttpStatusCode.OK)]
    [InlineData("denied", HttpStatusCode.OK)]
    [InlineData("legacy", HttpStatusCode.Forbidden)]
    [InlineData("wrong-key", HttpStatusCode.Forbidden)]
    [InlineData("missing-key", HttpStatusCode.Forbidden)]
    [InlineData("wrong-audience", HttpStatusCode.Unauthorized)]
    [InlineData("anonymous", HttpStatusCode.Unauthorized)]
    [InlineData("caller-bearer", HttpStatusCode.OK)]
    public async Task GenuineIamHttp_AuthIssuedProfileCrossesActualPermissionBoundary(string scenario, HttpStatusCode expected)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var joined = scenario is "allowed" or "denied" or "wrong-key" or "missing-key" or "caller-bearer";
        var authTransport = new ExchangeRecorder(fixture.Auth.Server.CreateHandler());
        var iamTransport = new IamRecorder(new HttpClientHandler { AllowAutoRedirect = false });
        var builder = Host.CreateApplicationBuilder();
        builder.Configuration["Observability:RuntimeMetricsEnabled"] = "false";
        builder.Configuration["ServiceAuthentication:ClientId"] = "legacy-quotation";
        builder.Configuration["ServiceAuthentication:ClientSecret"] = GenuineIamHttpFixture.ClientSecret;
        builder.Configuration["Services:Auth:BaseUrl"] = "https://auth.join.invalid";
        Defaults.AddServiceDefaults(builder);
        Exchange.AddLegacyAuthServiceTokenExchange(builder);
        builder.Services.AddHttpClient(Profile.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => authTransport);
        var downstream = builder.Services.AddHttpClient("GenuineIam", client => client.BaseAddress = fixture.Iam.BaseAddress)
            .ConfigurePrimaryHttpMessageHandler(() => iamTransport);
        if (joined) Exchange.AddLegacyIamServiceAuthentication(downstream);
        using var host = builder.Build();
        using var client = host.Services.GetRequiredService<IHttpClientFactory>().CreateClient("GenuineIam");
        using var request = new HttpRequestMessage(HttpMethod.Post, "/iam/v1/auth/check-permission");
        var permission = scenario == "denied" ? "join.resource.absent" : GenuineIamHttpFixture.PermissionId;
        request.Content = JsonContent.Create(new { principalId = fixture.PrincipalId.ToString("D"), permissionId = permission, resourcePath = "join/owned", bypassCache = true });
        if (scenario != "missing-key") request.Headers.Add("X-Maliev-IAM-Live-Check-Key", scenario == "wrong-key" ? "incorrect-isolated-live-key" : GenuineIamHttpFixture.LiveKey);
        if (scenario == "caller-bearer") request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "untrusted-caller-bearer");
        if (scenario == "legacy") request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await fixture.LoginAsync(fixture.Auth, "service/login", deadline.Token));
        if (scenario == "wrong-audience") request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await fixture.LoginAsync(fixture.WrongAudienceAuth, "service/iam-login", deadline.Token));
        using var response = await client.SendAsync(request, deadline.Token);
        Assert.Equal(expected, response.StatusCode);
        Assert.Equal(1, iamTransport.Requests);
        Assert.Equal("/iam/v1/auth/check-permission", iamTransport.Path);
        if (joined)
        {
            Assert.Equal(new[] { "/auth/v1/service/iam-login" }, authTransport.Paths);
            Assert.True(authTransport.AllUnauthenticated);
            Assert.True(authTransport.CredentialOnly);
            Assert.NotNull(iamTransport.Bearer);
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(iamTransport.Bearer);
            Assert.Equal("system:service:quotation", jwt.Subject);
            Assert.Equal(GenuineIamHttpFixture.IamAudience, Assert.Single(jwt.Audiences));
            Assert.Equal("iam-registration", Assert.Single(jwt.Claims, c => c.Type == "purpose").Value);
            Assert.Equal("iam.auth.check-permission", Assert.Single(jwt.Claims, c => c.Type == "permissions").Value);
            Assert.NotEqual("untrusted-caller-bearer", iamTransport.Bearer);
        }
        else Assert.Empty(authTransport.Paths);
        if (expected == HttpStatusCode.OK)
        {
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(deadline.Token));
            Assert.Equal(fixture.PrincipalId.ToString("D"), body.RootElement.GetProperty("principalId").GetString());
            Assert.Equal(permission, body.RootElement.GetProperty("permissionId").GetString());
            Assert.Equal(scenario != "denied", body.RootElement.GetProperty("allowed").GetBoolean());
            Assert.False(body.RootElement.GetProperty("fromCache").GetBoolean());
        }
        await fixture.AssertPersistedAuthorityUnchangedAsync(deadline.Token);
    }

    [Theory]
    [InlineData("auth-access-token", HttpStatusCode.BadRequest)]
    [InlineData("auth-unknown-refresh", HttpStatusCode.Unauthorized)]
    [InlineData("iam-access-token", HttpStatusCode.Unauthorized)]
    public async Task GenuineIamHttp_ServiceProfileCannotCreateOrRotateRefreshAuthority(string scenario, HttpStatusCode expected)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await fixture.AssertNoRefreshSessionsAsync(deadline.Token);
        var access = await fixture.LoginAsync(fixture.Auth, "service/iam-login", deadline.Token);
        using var client = scenario == "iam-access-token"
            ? new HttpClient { BaseAddress = fixture.Iam.BaseAddress, Timeout = TimeSpan.FromSeconds(30) }
            : fixture.Auth.CreateClient();
        var token = scenario == "auth-unknown-refresh" ? Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) : access;
        using var response = await client.PostAsJsonAsync(scenario == "iam-access-token" ? "/iam/v1/auth/token/refresh" : "/auth/v1/refresh",
            new { refreshToken = token }, deadline.Token);
        Assert.Equal(expected, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(deadline.Token));
        Assert.DoesNotContain(body.RootElement.EnumerateObject(), field => field.Name is "accessToken" or "refreshToken");
        await fixture.AssertNoRefreshSessionsAsync(deadline.Token);
        await fixture.AssertPersistedAuthorityUnchangedAsync(deadline.Token);
    }

    private sealed class ExchangeRecorder(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        public List<string> Paths { get; } = [];
        public bool AllUnauthenticated { get; private set; } = true;
        public bool CredentialOnly { get; private set; } = true;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Paths.Add(request.RequestUri!.AbsolutePath);
            AllUnauthenticated &= request.Headers.Authorization is null;
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            CredentialOnly &= body.RootElement.EnumerateObject().Select(value => value.Name).Order().SequenceEqual(new[] { "clientId", "clientSecret" })
                && body.RootElement.GetProperty("clientId").GetString() == "legacy-quotation"
                && body.RootElement.GetProperty("clientSecret").GetString() == GenuineIamHttpFixture.ClientSecret;
            return await base.SendAsync(request, cancellationToken);
        }
    }

    private sealed class IamRecorder(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        public int Requests { get; private set; }
        public string? Path { get; private set; }
        public string? Bearer { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            Path = request.RequestUri!.AbsolutePath;
            Bearer = request.Headers.Authorization?.Parameter;
            return base.SendAsync(request, cancellationToken);
        }
    }
}

public sealed class GenuineIamHttpFixture : IAsyncLifetime
{
    public static readonly string ClientSecret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    public static readonly string LiveKey = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    public const string Issuer = "https://auth.join.invalid";
    public const string IamAudience = "https://iam.join.invalid";
    public const string PermissionId = "join.resource.read";
    private static readonly string RepositoryRoot = FindRepositoryRoot();
    private readonly RSA signing = RSA.Create(2048);
    private readonly string run = Guid.NewGuid().ToString("N");
    private PostgreSqlContainer? database;
    private NpgsqlConnection? ownedPool;
    private NpgsqlConnection? authPool;
    private RSA? authValidationRsa;
    private RSA? wrongAudienceAuthValidationRsa;
    private string? refreshConnection;
    private string? createdAtUtc;
    private string? containerStartedAtUtc;
    private string? containerImageId;
    private KernelStorageMount? startedKernelMount;
    private bool storagePolicyComplete;
    private readonly OwnedHelperSafety helperSafety = new();
    private readonly List<OwnedProcessLease> quarantinedHelpers = [];
    private bool helperCleanupFailed;
    private readonly OwnedHostDisposal authDisposal = new();
    private readonly OwnedHostDisposal wrongAudienceAuthDisposal = new();
    public AuthFactory Auth { get; private set; } = null!;
    public AuthFactory WrongAudienceAuth { get; private set; } = null!;
    public OwnedIamProcess Iam { get; private set; } = null!;
    public Guid PrincipalId { get; } = Guid.NewGuid();

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "Legacy.Maliev.AuthService.slnx"))) return directory.FullName;
        throw new InvalidOperationException("The owned Auth acceptance source root was not found.");
    }

    public async Task InitializeAsync()
    {
        try
        {
            database = new PostgreSqlBuilder("postgres:18-alpine")
                .WithLabel("maliev.owner", "auth-genuine-iam-http")
                .WithLabel("maliev.run", run)
                .WithLabel("maliev.expires-utc", DateTime.UtcNow.AddMinutes(15).ToString("O"))
                .WithCreateParameterModifier(parameters =>
                {
                    parameters.HostConfig.Memory = 512L * 1024 * 1024;
                    parameters.HostConfig.NanoCPUs = 1_000_000_000;
                    parameters.HostConfig.Tmpfs = new Dictionary<string, string> { ["/var/lib/postgresql"] = "rw,size=134217728" };
                    foreach (var bindings in parameters.HostConfig.PortBindings.Values)
                        foreach (var binding in bindings) binding.HostIP = "127.0.0.1";
                }).Build();
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            await database.StartAsync(deadline.Token);
            await RecordContainerStateAsync("started", deadline.Token);
            ownedPool = new NpgsqlConnection(database.GetConnectionString());
            await ownedPool.OpenAsync(deadline.Token);
            await using (var createRefresh = new NpgsqlCommand("CREATE DATABASE auth_refresh", ownedPool))
                await createRefresh.ExecuteNonQueryAsync(deadline.Token);
            refreshConnection = new NpgsqlConnectionStringBuilder(database.GetConnectionString()) { Database = "auth_refresh" }.ConnectionString;
            authPool = new NpgsqlConnection(refreshConnection);
            Auth = new AuthFactory(signing, IamAudience, refreshConnection);
            authValidationRsa = CaptureValidationRsa(Auth);
            WrongAudienceAuth = new AuthFactory(signing, "https://wrong.join.invalid", refreshConnection);
            wrongAudienceAuthValidationRsa = CaptureValidationRsa(WrongAudienceAuth);
            await using (var scope = Auth.Services.CreateAsyncScope())
                await scope.ServiceProvider.GetRequiredService<AuthInfrastructure::Legacy.Maliev.AuthService.Infrastructure.RefreshSessionDbContext>()
                    .Database.EnsureCreatedAsync(deadline.Token);
            Iam = new OwnedIamProcess();
            await Iam.StartAsync(RepositoryRoot, database.GetConnectionString(), signing.ExportPkcs8PrivateKeyPem(), PrincipalId, PermissionId, LiveKey,
                (entry, token) => WriteLedgerAsync(new { run, iamProcess = entry }, token), deadline.Token);
            await AssertPersistedAuthorityUnchangedAsync(deadline.Token);
        }
        catch (Exception initializationFailure)
        {
            try { await DisposeAsync(); }
            catch (Exception cleanupFailure) { throw new AggregateException("Fixture initialization and cleanup failed.", initializationFailure, cleanupFailure); }
            throw;
        }
    }

    private static RSA CaptureValidationRsa(AuthFactory factory)
        => (factory.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters.IssuerSigningKey as RsaSecurityKey)?.Rsa
            ?? throw new InvalidOperationException("The actual Auth JWT validation RSA is required.");

    public async Task<string> LoginAsync(AuthFactory factory, string path, CancellationToken cancellationToken)
    {
        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync("/auth/v1/" + path, new { clientId = "legacy-quotation", clientSecret = ClientSecret }, cancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        Assert.Equal(new[] { "accessToken", "expiresIn", "tokenType" }, body.RootElement.EnumerateObject().Select(value => value.Name).Order().ToArray());
        Assert.Equal("Bearer", body.RootElement.GetProperty("tokenType").GetString());
        Assert.Equal(900, body.RootElement.GetProperty("expiresIn").GetInt32());
        return body.RootElement.GetProperty("accessToken").GetString()!;
    }

    public async Task AssertPersistedAuthorityUnchangedAsync(CancellationToken cancellationToken)
    {
        await using var connection = new NpgsqlConnection(database!.GetConnectionString());
        await connection.OpenAsync(cancellationToken);
        await using var authority = new NpgsqlCommand("SELECT count(*) FROM principals WHERE principal_id = @principal AND is_active", connection);
        authority.Parameters.AddWithValue("principal", PrincipalId);
        Assert.Equal(1L, await authority.ExecuteScalarAsync(cancellationToken));
        await using var binding = new NpgsqlCommand("SELECT permission_id, resource_path FROM principal_permission_bindings WHERE principal_id = @principal", connection);
        binding.Parameters.AddWithValue("principal", PrincipalId);
        await using var reader = await binding.ExecuteReaderAsync(cancellationToken);
        Assert.True(await reader.ReadAsync(cancellationToken));
        Assert.Equal(PermissionId, reader.GetString(0));
        Assert.Equal("join/owned", reader.GetString(1));
        Assert.False(await reader.ReadAsync(cancellationToken));
    }

    public async Task AssertNoRefreshSessionsAsync(CancellationToken cancellationToken)
    {
        await using var scope = Auth.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthInfrastructure::Legacy.Maliev.AuthService.Infrastructure.RefreshSessionDbContext>();
        Assert.Equal(0, await db.RefreshSessions.CountAsync(cancellationToken));
    }

    public async Task DisposeAsync()
    {
        await OwnedCleanup.RunAsync(
            [("IamHost", token => Iam is null ? Task.CompletedTask : Iam.DisposeAsync(token)),
             ("AuthHost", token => Auth is null ? Task.CompletedTask : authDisposal.WaitAsync(() => Auth.DisposeAsync().AsTask(), token)),
             ("WrongAudienceAuthHost", token => WrongAudienceAuth is null ? Task.CompletedTask : wrongAudienceAuthDisposal.WaitAsync(() => WrongAudienceAuth.DisposeAsync().AsTask(), token)),
             ("AuthValidationRsa", _ => { authValidationRsa?.Dispose(); authValidationRsa = null; return Task.CompletedTask; }),
             ("WrongAudienceAuthValidationRsa", _ => { wrongAudienceAuthValidationRsa?.Dispose(); wrongAudienceAuthValidationRsa = null; return Task.CompletedTask; }),
             ("FixtureRsa", _ => { signing.Dispose(); return Task.CompletedTask; }),
             ("OwnedPool", _ => { if (ownedPool is not null) { try { NpgsqlConnection.ClearPool(ownedPool); } finally { ownedPool.Dispose(); ownedPool = null; } } return Task.CompletedTask; }),
             ("AuthPool", _ => { if (authPool is not null) { try { NpgsqlConnection.ClearPool(authPool); } finally { authPool.Dispose(); authPool = null; } } return Task.CompletedTask; }),
             ("PostgresContainer", RemoveContainerAsync)],
            (name, complete, token) => WriteLedgerAsync(new { run, resource = name, cleanupComplete = complete, remainingOwnership = !complete, leaseMinutes = complete ? 0 : 15 }, token),
            TimeSpan.FromSeconds(30));
        if (helperCleanupFailed)
            throw new OwnedHelperCleanupException([new InvalidOperationException("Owned helper cleanup previously failed; independent quiescence recovery does not erase the failure.")]);
        if (authDisposal.FailureObserved || wrongAudienceAuthDisposal.FailureObserved)
            throw new InvalidOperationException("Owned Auth host cleanup previously failed; completed recovery does not erase the failure.");
        if (!storagePolicyComplete)
            throw new InvalidOperationException("Owned storage policy failed; physical cleanup receipts remain independent.");
    }

    private Task RemoveContainerAsync(CancellationToken cancellationToken)
        => database is null ? Task.CompletedTask : OwnedHostDisposal.AfterShutdownAsync(
            [(Auth is not null, authDisposal), (WrongAudienceAuth is not null, wrongAudienceAuthDisposal)],
            () => RemoveContainerAfterHostShutdownAsync(cancellationToken));

    private async Task RemoveContainerAfterHostShutdownAsync(CancellationToken cancellationToken)
    {
        if (database is null) return;
        if (Iam is not null && !Iam.IsQuiescent)
            throw new InvalidOperationException("Owned IAM helper remains active; preserve its PostgreSQL backend.");
        await VerifyQuarantinedHelpersAsync(cancellationToken);
        helperSafety.RequireQuiescence();
        var id = database.Id;
        JsonElement? lastObservedStorage = null;
        KernelStorageMount? lastKernelMount = null;
        var lastStoragePolicyComplete = false;
        var ownership = await InspectAsync(id, cancellationToken);
        if (ownership.ExitCode != 0 && !OwnedCleanup.IsExactContainerAbsence(id, ownership.ExitCode, ownership.Error))
        {
            await WriteLedgerAsync(new { run, containerId = id, state = "preserved-ownership-unverifiable", leaseMinutes = 15 });
            throw new InvalidOperationException("Container ownership cannot be verified; preserve exact resource.");
        }
        if (ownership.ExitCode == 0)
        {
            using var receipt = JsonDocument.Parse(ownership.Output);
            Assert.Equal(run, receipt.RootElement.GetProperty("labels").GetProperty("maliev.run").GetString());
            Assert.Equal("auth-genuine-iam-http", receipt.RootElement.GetProperty("labels").GetProperty("maliev.owner").GetString());
            if (createdAtUtc is not null) Assert.Equal(createdAtUtc, receipt.RootElement.GetProperty("created").GetString());
            if (containerStartedAtUtc is not null) Assert.Equal(containerStartedAtUtc, receipt.RootElement.GetProperty("state").GetProperty("StartedAt").GetString());
            lastObservedStorage = receipt.RootElement.Clone();
            var storage = await ObserveStoragePolicyAsync(receipt.RootElement, cancellationToken);
            lastKernelMount = storage.Mount;
            lastStoragePolicyComplete = storage.Complete;
            storagePolicyComplete &= storage.Complete;
            var stopped = await helperSafety.MutateAsync(() => DockerAsync(["stop", "--time", "5", id], cancellationToken));
            Assert.Equal(0, stopped.ExitCode);
            var removed = await helperSafety.MutateAsync(() => DockerAsync(["rm", id], cancellationToken));
            Assert.Equal(0, removed.ExitCode);
        }
        else storagePolicyComplete = false; // Missing pre-removal evidence is not a storage-policy pass.
        var state = await InspectAsync(id, cancellationToken);
        Assert.True(OwnedCleanup.IsExactContainerAbsence(id, state.ExitCode, state.Error));
        // Release managed ownership before policy/receipt failures can affect teardown.
        await database.DisposeAsync().AsTask().WaitAsync(cancellationToken);
        database = null;
        await WriteLedgerAsync(new { run, containerId = id, state = "removed", persistentData = storagePolicyComplete ? (bool?)false : null,
            mounts = lastObservedStorage?.GetProperty("mounts"), tmpfs = lastObservedStorage?.GetProperty("tmpfs"),
            declaredVolumes = lastObservedStorage?.GetProperty("volumes"), imageId = lastObservedStorage?.GetProperty("imageId"),
            kernelMount = lastKernelMount, storagePolicyComplete,
            lastStoragePolicyComplete, storagePolicyFault = storagePolicyComplete ? null : "owned-storage-policy-unverified",
            helperCleanupFailed, authDisposalComplete = Auth is null || authDisposal.Complete,
            wrongAudienceAuthDisposalComplete = WrongAudienceAuth is null || wrongAudienceAuthDisposal.Complete,
            authDisposalPreviouslyFailed = authDisposal.FailureObserved,
            wrongAudienceAuthDisposalPreviouslyFailed = wrongAudienceAuthDisposal.FailureObserved,
            cleanupComplete = true, remainingOwnership = false });
    }

    private async Task RecordContainerStateAsync(string state, CancellationToken cancellationToken)
    {
        var observed = await InspectAsync(database!.Id, cancellationToken);
        Assert.Equal(0, observed.ExitCode);
        using var json = JsonDocument.Parse(observed.Output);
        createdAtUtc = json.RootElement.GetProperty("created").GetString();
        containerStartedAtUtc = json.RootElement.GetProperty("state").GetProperty("StartedAt").GetString();
        containerImageId = json.RootElement.GetProperty("imageId").GetString();
        Assert.Equal(512L * 1024 * 1024, json.RootElement.GetProperty("memory").GetInt64());
        Assert.Equal(1_000_000_000L, json.RootElement.GetProperty("nanoCpus").GetInt64());
        foreach (var port in json.RootElement.GetProperty("ports").EnumerateObject())
            if (port.Value.ValueKind == JsonValueKind.Array)
                foreach (var binding in port.Value.EnumerateArray()) Assert.Equal("127.0.0.1", binding.GetProperty("HostIp").GetString());
        var storage = await ObserveStoragePolicyAsync(json.RootElement, cancellationToken);
        startedKernelMount = storage.Mount;
        storagePolicyComplete = storage.Complete;
        await WriteLedgerAsync(new { run, containerId = database.Id, state, startedAtUtc = json.RootElement.GetProperty("state").GetProperty("StartedAt").GetString(), createdAtUtc = json.RootElement.GetProperty("created").GetString(), ownership = json.RootElement.GetProperty("labels").Clone(), mounts = json.RootElement.GetProperty("mounts").Clone(), tmpfs = json.RootElement.GetProperty("tmpfs").Clone(), declaredVolumes = json.RootElement.GetProperty("volumes").Clone(), ports = json.RootElement.GetProperty("ports").Clone(), image = json.RootElement.GetProperty("image").GetString(), imageId = containerImageId, kernelMount = startedKernelMount, storagePolicyComplete, storagePolicyFault = storagePolicyComplete ? null : "owned-storage-policy-unverified", persistentData = storagePolicyComplete ? (bool?)false : null, memoryBytes = 512L * 1024 * 1024, cpuCount = 1, leaseMinutes = 15 });
        if (!storagePolicyComplete) throw new InvalidOperationException("Owned storage policy failed at startup.");
    }

    private static void AssertExactDisposableStorage(JsonElement receipt)
    {
        var tmpfs = Assert.Single(receipt.GetProperty("tmpfs").EnumerateObject());
        Assert.Equal("/var/lib/postgresql", tmpfs.Name);
        Assert.Equal("rw,size=134217728", tmpfs.Value.GetString());
        var volumes = receipt.GetProperty("volumes");
        if (volumes.ValueKind != JsonValueKind.Null)
        {
            Assert.Equal(JsonValueKind.Object, volumes.ValueKind);
            var declarations = volumes.EnumerateObject().ToArray();
            if (declarations.Length != 0)
            {
                var declaration = Assert.Single(declarations);
                Assert.Equal("/var/lib/postgresql", declaration.Name);
                Assert.Equal(JsonValueKind.Object, declaration.Value.ValueKind);
                Assert.Empty(declaration.Value.EnumerateObject());
            }
        }
        Assert.DoesNotContain(receipt.GetProperty("mounts").EnumerateArray(), mount => mount.GetProperty("Type").GetString() is not "tmpfs");
    }

    private sealed record KernelStorageMount(string Target, string FileSystem, string Source, bool ReadWrite, string Size);
    private async Task RecordHelperQuiescenceAsync(OwnedProcessLease helper)
    {
        using var receiptDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        await WriteLedgerAsync(new { run, purpose = helper.ReadersObserved ? "Exact owned container command disposal" : "Exact owned container command",
            processId = helper.ProcessId, startedAtUtc = helper.StartedAtUtc, executable = helper.Executable,
            launchAttempted = helper.StartAttempted, started = helper.Started,
            outputReaderStarted = helper.Output is not null, errorReaderStarted = helper.Error is not null,
            exited = helper.Exited, exitCode = helper.ExitCode, terminationFailed = helper.TerminationFailed,
            readersSettled = helper.ReadersSettled, readersObserved = helper.ReadersObserved,
            handlesDisposed = helper.Disposed,
            outputReaderDisposed = helper.OutputReader is null ? (bool?)null : helper.OutputReaderDisposed,
            errorReaderDisposed = helper.ErrorReader is null ? (bool?)null : helper.ErrorReaderDisposed,
            deadlineDisposed = helper.Deadline is null ? (bool?)null : helper.DeadlineDisposed,
            processHandleDisposed = helper.ProcessHandleDisposed,
            remainingHandleOwnership = !helper.Disposed,
            remainingOwnership = !helper.Exited || !helper.ReadersSettled || !helper.Disposed,
            originalCleanupFailure = helperCleanupFailed || helper.CleanupFaultObserved, leaseSeconds = 15 }, receiptDeadline.Token).WaitAsync(receiptDeadline.Token);
    }

    private async Task VerifyQuarantinedHelpersAsync(CancellationToken cancellationToken)
    {
        if (!helperSafety.IsQuarantined) return;
        List<Exception> failures = [];
        if (quarantinedHelpers.Count == 0)
            throw new OwnedHelperCleanupException([new InvalidOperationException("Quarantined helper ownership is unavailable.")]);
        foreach (var helper in quarantinedHelpers.ToArray())
        {
            try
            {
                // Reconciliation has its own finite deadlines; cancellation cannot skip later stages.
                await helper.ReconcileAsync(RecordHelperQuiescenceAsync);
                if (!helper.Disposed) throw new InvalidOperationException("Owned helper remains retained.");
                quarantinedHelpers.Remove(helper);
            }
            catch (Exception) { failures.Add(new InvalidOperationException("Independent owned helper quiescence verification failed.")); }
        }
        if (failures.Count != 0 || quarantinedHelpers.Count != 0)
            throw new OwnedHelperCleanupException(failures);
        helperSafety.ReleaseAfterVerifiedQuiescence();
    }

    private async Task<(bool Complete, KernelStorageMount? Mount)> ObserveStoragePolicyAsync(JsonElement receipt, CancellationToken cancellationToken)
    {
        return await helperSafety.ObservePolicyAsync(async () =>
        {
            AssertExactDisposableStorage(receipt);
            Assert.Matches("^sha256:[0-9a-f]{64}$", receipt.GetProperty("imageId").GetString()!);
            Assert.Equal(containerImageId, receipt.GetProperty("imageId").GetString());
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromSeconds(2));
            var observed = await DockerAsync(["exec", database!.Id, "cat", "/proc/self/mountinfo"], deadline.Token, 2, 500);
            if (observed.ExitCode != 0) throw new InvalidOperationException("Owned kernel storage observation failed.");
            var entries = observed.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                .Where(parts => parts.Length > 6).ToArray();
            Assert.DoesNotContain(entries, parts => parts[4].StartsWith("/var/lib/postgresql/", StringComparison.Ordinal));
            var matches = entries.Where(parts => parts[4] == "/var/lib/postgresql").ToArray();
            var fields = Assert.Single(matches);
            var separator = Array.IndexOf(fields, "-");
            Assert.True(separator >= 6 && fields.Length > separator + 3);
            Assert.Equal("tmpfs", fields[separator + 1]);
            Assert.Equal("tmpfs", fields[separator + 2]);
            Assert.Contains("rw", fields[5].Split(','));
            var superOptions = fields[separator + 3].Split(',');
            Assert.Contains("rw", superOptions);
            Assert.Equal("size=131072k", Assert.Single(superOptions, option => option.StartsWith("size=", StringComparison.Ordinal)));
            var mount = new KernelStorageMount("/var/lib/postgresql", "tmpfs", "tmpfs", true, "size=131072k");
            if (startedKernelMount is not null) Assert.Equal(startedKernelMount, mount);
            return mount;
        });
    }

    private async Task WriteLedgerAsync<T>(T entry, CancellationToken cancellationToken = default)
    {
        var directory = Environment.GetEnvironmentVariable("GENUINE_IAM_RESOURCE_LEDGER") ?? Path.Combine(AppContext.BaseDirectory, "resource-ledger");
        Directory.CreateDirectory(directory);
        await File.AppendAllTextAsync(Path.Combine(directory, run + ".jsonl"), JsonSerializer.Serialize(entry) + Environment.NewLine, cancellationToken);
    }

    private Task<(int ExitCode, string Output, string Error)> InspectAsync(string containerId, CancellationToken cancellationToken)
        => DockerAsync(["inspect", "--format", "{\"state\":{{json .State}},\"labels\":{{json .Config.Labels}},\"created\":{{json .Created}},\"mounts\":{{json .Mounts}},\"tmpfs\":{{json .HostConfig.Tmpfs}},\"volumes\":{{json .Config.Volumes}},\"ports\":{{json .NetworkSettings.Ports}},\"image\":{{json .Config.Image}},\"imageId\":{{json .Image}},\"memory\":{{json .HostConfig.Memory}},\"nanoCpus\":{{json .HostConfig.NanoCpus}}}", containerId], cancellationToken);

    private async Task<(int ExitCode, string Output, string Error)> DockerAsync(string[] arguments, CancellationToken cancellationToken, int commandSeconds = 15, int reapMilliseconds = 5000)
    {
        helperSafety.RequireQuiescence();
        var start = new ProcessStartInfo("docker") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        var helper = new OwnedProcessLease(start, reapMilliseconds);
        quarantinedHelpers.Add(helper); // Own the handle before instance Start, metadata or readers can fail.
        try
        {
            return await helper.ExecuteAsync(cancellationToken, commandSeconds, RecordHelperQuiescenceAsync);
        }
        catch (OwnedHelperCleanupException)
        {
            helperCleanupFailed = true;
            helperSafety.Quarantine();
            throw;
        }
        finally
        {
            if (helper.CleanupComplete) quarantinedHelpers.Remove(helper);
        }
    }

    public sealed class AuthFactory(RSA signing, string iamAudience, string refreshConnection) : WebApplicationFactory<AuthProgram>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseContentRoot(Path.Combine(RepositoryRoot, ".genuine-iam-source", "Legacy.Maliev.AuthService", "Legacy.Maliev.AuthService.Api"));
            builder.UseEnvironment("Production");
            foreach (var setting in new Dictionary<string, string?>
            {
                ["CORS:AllowedOrigins"] = "https://localhost",
                ["Observability:RuntimeMetricsEnabled"] = "false",
                ["ConnectionStrings:CustomerIdentity"] = "Host=127.0.0.1;Port=1;Database=unused;Username=unused",
                ["ConnectionStrings:EmployeeIdentity"] = "Host=127.0.0.1;Port=1;Database=unused;Username=unused",
                ["ConnectionStrings:RefreshSessions"] = refreshConnection,
                ["Jwt:Issuer"] = Issuer,
                ["Jwt:Audience"] = IamAudience,
                ["Jwt:IamAudience"] = iamAudience,
                ["Jwt:PrivateKeyPem"] = signing.ExportPkcs8PrivateKeyPem(),
                ["Jwt:KeyId"] = "genuine-join",
                ["Jwt:AccessTokenLifetimeSeconds"] = "900",
                ["ServiceClients:Clients:legacy-quotation:SecretSha256"] = AuthInfrastructure::Legacy.Maliev.AuthService.Infrastructure.ServiceClientCredential.HashSecret(ClientSecret),
                ["ServiceClients:Clients:legacy-quotation:IamServiceName"] = "QuotationService",
                ["ServiceClients:Clients:legacy-quotation:Permissions:0"] = "iam.auth.check-permission"
            }) builder.UseSetting(setting.Key, setting.Value);
        }
    }

}
