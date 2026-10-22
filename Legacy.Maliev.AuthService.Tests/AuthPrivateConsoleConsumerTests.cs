using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Maliev.Aspire.ServiceDefaults.Logging;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>Checks Auth's selected private console formatter and terminal dependency registration through real Program services.</summary>
public sealed class AuthPrivateConsoleConsumerTests
{
    internal const string Canary = "auth-private-console-payload-sentinel";

    /// <summary>Checks category-specific Trace configuration cannot make the selected console emit success levels or protected state.</summary>
    /// <param name="level">The actual logger severity delivered to the configured console formatter.</param>
    /// <param name="severity">The expected private severity, or null when the sink must remain quiet.</param>
    /// <returns>A task completing after actual Program DI and formatted-output assertions.</returns>
    [Theory]
    [InlineData(LogLevel.Trace, null)]
    [InlineData(LogLevel.Debug, null)]
    [InlineData(LogLevel.Information, null)]
    [InlineData(LogLevel.Warning, "WARNING")]
    [InlineData(LogLevel.Error, "ERROR")]
    [InlineData(LogLevel.Critical, "CRITICAL")]
    public async Task ActualProgram_PrivateConsoleRejectsPayloadAndSuccessLevels(LogLevel level, string? severity)
    {
        await using var host = new ConsoleHost();
        using var client = host.CreateClient();
        var services = host.Services;
        var providers = services.GetServices<ILoggerProvider>().Where(provider => provider is not FormattedRecorder).ToArray();
        Assert.IsType<ConsoleLoggerProvider>(Assert.Single(providers));
        Assert.Equal(PrivateFailureConsoleFormatter.FormatterName,
            services.GetRequiredService<IOptions<ConsoleLoggerOptions>>().Value.FormatterName);
        Assert.NotNull(services.GetRequiredService<MeterProvider>());
        Assert.NotNull(services.GetRequiredService<TracerProvider>());
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("AuthPrivateConsoleProbe");
        Assert.True(logger.IsEnabled(LogLevel.Trace));
        using var activity = new Activity("AuthPrivateConsoleProbe").SetIdFormat(ActivityIdFormat.W3C).Start();
        using var scope = logger.BeginScope(new Dictionary<string, object?>
        {
            ["Payload"] = Canary,
            ["service"] = Canary,
            ["traceId"] = Canary,
        });
        var state = new Dictionary<string, object?>
        {
            ["EventName"] = "AuthPrivateConsoleProbe",
            ["Operation"] = "PrivateConsoleRegression",
            ["StatusCode"] = 503,
            ["Payload"] = Canary,
            ["Email"] = Canary,
            ["Path"] = "/" + Canary,
            ["Authorization"] = Canary,
            ["exceptionType"] = Canary,
            ["innerExceptionType"] = Canary,
            ["sourceLocation"] = Canary,
            ["service"] = Canary,
            ["deploymentVersion"] = Canary,
            ["traceId"] = Canary,
        };
        logger.Log(level, new EventId(5250), state, new InvalidOperationException(Canary),
            static (_, _) => throw new InvalidOperationException("Protected formatter delegate must not run."));
        Assert.Equal(1, host.Records.ProbeInputs);
        var lines = host.Records.Lines("AuthPrivateConsoleProbe");
        if (severity is null) Assert.Empty(lines);
        else
        {
            var line = Assert.Single(lines);
            Assert.DoesNotContain(Canary, line, StringComparison.Ordinal);
            Assert.DoesNotContain("Protected formatter delegate", line, StringComparison.Ordinal);
            using var json = JsonDocument.Parse(line);
            Assert.Equal(severity, json.RootElement.GetProperty("severity").GetString());
            Assert.Equal("AuthPrivateConsoleProbe", json.RootElement.GetProperty("EventName").GetString());
            Assert.Equal(503, json.RootElement.GetProperty("StatusCode").GetInt32());
            Assert.Equal(activity.TraceId.ToHexString(), json.RootElement.GetProperty("traceId").GetString());
            Assert.Equal(activity.SpanId.ToHexString(), json.RootElement.GetProperty("spanId").GetString());
            Assert.Equal(typeof(InvalidOperationException).FullName, json.RootElement.GetProperty("exceptionType").GetString());
            Assert.False(json.RootElement.TryGetProperty("Payload", out _));
            Assert.False(json.RootElement.TryGetProperty("Path", out _));
        }
        Assert.False(host.Records.Overflowed);
    }

    /// <summary>Checks actual compiler-generated throw sites survive the selected formatter without exporting exception text.</summary>
    /// <param name="closure">Whether the actual throw site belongs to a closure instead of an async state machine.</param>
    /// <returns>A task completing after actual exception provenance and formatted-output assertions.</returns>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ActualProgram_PrivateConsolePreservesRuntimeGeneratedThrowSites(bool closure)
    {
        await using var host = new ConsoleHost();
        using var client = host.CreateClient();
        var failure = closure ? CaptureClosure() : await CaptureAsync();
        var logger = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("AuthPrivateConsoleProbe");
        logger.LogError(failure, "{EventName}", "AuthPrivateConsoleProbe");
        var line = Assert.Single(host.Records.Lines("AuthPrivateConsoleProbe"));
        using var json = JsonDocument.Parse(line);
        var actual = failure.TargetSite!;
        var location = actual.DeclaringType!.FullName + "." + actual.Name;
        Assert.Equal(location, json.RootElement.GetProperty("sourceLocation").GetString());
        Assert.DoesNotContain(Canary, line, StringComparison.Ordinal);
        Assert.Contains("<", location, StringComparison.Ordinal);
        Assert.False(host.Records.Overflowed);
    }

    /// <summary>Checks each real named client has one terminal observer without changing its response, transport failure, or cancellation.</summary>
    /// <param name="name">The existing code-owned named client selected by Auth Program.</param>
    /// <param name="dependency">The bounded diagnostic identity expected for that client.</param>
    /// <returns>A task completing after synthetic primary-transport outcomes pass through the actual registered observer.</returns>
    [Theory]
    [InlineData("IAMService", "IAMService")]
    [InlineData("LegacyAuthServiceTokenExchange", "AuthWorkload")]
    [InlineData("QuotationInvoiceLiveAuthority", "QuotationInvoiceAuthority")]
    [InlineData("InvoiceFinancialOwnership", "InvoiceFinancialOwnership")]
    [InlineData("EmployeeProfileBinding", "EmployeeProfileBinding")]
    [InlineData("CustomerProfileBinding", "CustomerProfileBinding")]
    public async Task ActualNamedClients_ObserveOnlyTerminalFailuresOnce(string name, string dependency)
    {
        await using var host = new ConsoleHost();
        using var serverClient = host.CreateClient();
        using var client = host.Services.GetRequiredService<IHttpClientFactory>().CreateClient(name);
        Assert.Contains(name, host.Transport.SelectedNames);
        foreach (var status in new[] { 200, 404, 503 })
        {
            host.Transport.Status = status;
            var before = host.Records.Lines("DependencyRequestFailure").Count;
            using var response = await client.GetAsync("https://fixture.invalid/" + Canary);
            Assert.Equal((HttpStatusCode)status, response.StatusCode);
            Assert.Equal(before + (status >= 500 ? 1 : 0), host.Records.Lines("DependencyRequestFailure").Count);
        }
        var line = Assert.Single(host.Records.Lines("DependencyRequestFailure"));
        using (var json = JsonDocument.Parse(line))
        {
            Assert.Equal(dependency, json.RootElement.GetProperty("Dependency").GetString());
            Assert.Equal("HttpRequest", json.RootElement.GetProperty("Operation").GetString());
            Assert.Equal(503, json.RootElement.GetProperty("StatusCode").GetInt32());
            Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("exceptionType").ValueKind);
            Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("innerExceptionType").ValueKind);
            Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("sourceLocation").ValueKind);
        }
        Assert.DoesNotContain(Canary, line, StringComparison.Ordinal);
        var failure = new HttpRequestException(Canary, new InvalidOperationException(Canary));
        host.Transport.Failure = failure;
        var returned = await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync("https://fixture.invalid/" + Canary));
        Assert.Same(failure, returned);
        Assert.Equal(2, host.Records.Lines("DependencyRequestFailure").Count);
        var transportLine = host.Records.Lines("DependencyRequestFailure")[1];
        using (var transport = JsonDocument.Parse(transportLine))
        {
            Assert.Equal(typeof(HttpRequestException).FullName, transport.RootElement.GetProperty("exceptionType").GetString());
            Assert.Equal(typeof(InvalidOperationException).FullName, transport.RootElement.GetProperty("innerExceptionType").GetString());
            var actual = returned.TargetSite!;
            Assert.Equal(actual.DeclaringType!.FullName + "." + actual.Name,
                transport.RootElement.GetProperty("sourceLocation").GetString());
            Assert.Equal(dependency, transport.RootElement.GetProperty("Dependency").GetString());
            Assert.Equal("HttpRequest", transport.RootElement.GetProperty("Operation").GetString());
        }
        Assert.DoesNotContain(Canary, transportLine, StringComparison.Ordinal);
        Assert.Equal(0, host.Records.UnsafeFailureInputs);
        host.Transport.Failure = null;
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.GetAsync("https://fixture.invalid/" + Canary, canceled.Token));
        Assert.Equal(2, host.Records.Lines("DependencyRequestFailure").Count);
        Assert.False(host.Records.Overflowed);
    }

    /// <summary>Checks ordinary handled/unhandled responses and failed-health deduplication/reset retain their formatted failure events.</summary>
    /// <returns>A task completing after real HTTP response, privacy, and health-state reset assertions.</returns>
    [Fact]
    public async Task ActualProgram_HandledUnhandledAndHealthResetRemainPrivate()
    {
        await using var host = new ConsoleHost();
        using var client = host.CreateClient();
        using var unauthorized = await client.GetAsync("/auth/v1/employee-identities/1");
        Assert.Equal(HttpStatusCode.Unauthorized, unauthorized.StatusCode);
        using var handled = await client.GetAsync("/__fixture/auth-private-console/returned");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, handled.StatusCode);
        using var unhandled = await client.GetAsync("/__fixture/auth-private-console/throw?payload=" + Canary);
        Assert.Equal(HttpStatusCode.InternalServerError, unhandled.StatusCode);
        Assert.DoesNotContain(Canary, await unhandled.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Single(host.Records.Lines("HandledOperationFailure"));
        Assert.Single(host.Records.Lines("UnhandledRequestFailure"));
        host.Health.Healthy = false;
        foreach (var expected in new[] { 1, 1 })
        {
            using var unhealthy = await client.GetAsync("/auth/readiness");
            Assert.Equal(HttpStatusCode.ServiceUnavailable, unhealthy.StatusCode);
            Assert.Equal(expected, host.Records.Lines("HealthProbeFailure").Count);
        }
        host.Health.Healthy = true;
        using var healthy = await client.GetAsync("/auth/readiness");
        Assert.Equal(HttpStatusCode.OK, healthy.StatusCode);
        host.Health.Healthy = false;
        using var failedAgain = await client.GetAsync("/auth/readiness");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, failedAgain.StatusCode);
        Assert.Equal(2, host.Records.Lines("HealthProbeFailure").Count);
        foreach (var line in host.Records.AllLines) Assert.DoesNotContain(Canary, line, StringComparison.Ordinal);
        Assert.False(host.Records.Overflowed);
    }

    /// <summary>Checks the actual request catch carries bounded throw-site metadata without forwarding an exception to logging providers.</summary>
    /// <param name="asynchronous">Whether the fixture throws from an async state machine instead of an ordinary action.</param>
    /// <returns>A task completing after response, single-event, runtime provenance and formatted privacy assertions.</returns>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ActualProgram_RequestCatchCarriesOnlyTrustedFailureProvenance(bool asynchronous)
    {
        await using var host = new ConsoleHost();
        using var client = host.CreateClient();
        using var response = await client.GetAsync("/__fixture/auth-private-console/" +
            (asynchronous ? "throw-async" : "throw") + "?payload=" + Canary);
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.DoesNotContain(Canary, await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        var line = Assert.Single(host.Records.Lines("UnhandledRequestFailure"));
        using var json = JsonDocument.Parse(line);
        Assert.Equal("CRITICAL", json.RootElement.GetProperty("severity").GetString());
        Assert.Equal(500, json.RootElement.GetProperty("StatusCode").GetInt32());
        Assert.Equal(typeof(Exception).FullName, json.RootElement.GetProperty("exceptionType").GetString());
        var location = json.RootElement.GetProperty("sourceLocation").GetString()!;
        if (asynchronous)
        {
            Assert.Equal(typeof(InvalidOperationException).FullName,
                json.RootElement.GetProperty("innerExceptionType").GetString());
            Assert.StartsWith(typeof(AuthPrivateConsoleFixtureController).FullName + "+<ThrowAsync>d__", location);
            Assert.EndsWith(".MoveNext", location, StringComparison.Ordinal);
        }
        else
        {
            Assert.Equal(typeof(AuthPrivateConsoleFixtureController).FullName + ".Throw", location);
            Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("innerExceptionType").ValueKind);
        }
        Assert.DoesNotContain(Canary, line, StringComparison.Ordinal);
        Assert.False(json.RootElement.TryGetProperty("Path", out _));
        Assert.Equal(0, host.Records.UnsafeFailureInputs);
        Assert.Empty(host.Records.Lines("HandledOperationFailure"));
        Assert.False(host.Records.Overflowed);
    }

    private static async Task<Exception> CaptureAsync()
    {
        try { await ThrowAsync(); }
        catch (Exception failure) { return failure; }
        throw new InvalidOperationException("The async fixture did not throw.");
    }

    private static async Task ThrowAsync()
    {
        await Task.Yield();
        throw new InvalidOperationException(Canary);
    }

    private static Exception CaptureClosure()
    {
        var value = Canary;
        Action throwing = () => throw new InvalidOperationException(value);
        try { throwing(); }
        catch (Exception failure) { return failure; }
        throw new InvalidOperationException("The closure fixture did not throw.");
    }

    private sealed class ConsoleHost : WebApplicationFactory<Program>
    {
        private readonly RSA signing = RSA.Create(2048);
        internal TerminalTransport Transport { get; } = new();
        internal ToggleHealth Health { get; } = new();
        internal FormattedRecorder Records => Services.GetServices<ILoggerProvider>().OfType<FormattedRecorder>().Single();

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Observability:TracingEnabled", "true");
            builder.UseSetting("OTEL_EXPORTER_OTLP_ENDPOINT", "");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.UseSetting("Logging:Console:LogLevel:AuthPrivateConsoleProbe", "Trace");
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:CustomerIdentity"] = "Host=127.0.0.1;Port=1;Database=unused;Username=fixture;Pooling=false",
                ["ConnectionStrings:EmployeeIdentity"] = "Host=127.0.0.1;Port=1;Database=unused;Username=fixture;Pooling=false",
                ["ConnectionStrings:RefreshSessions"] = "Host=127.0.0.1;Port=1;Database=unused;Username=fixture;Pooling=false",
                ["Jwt:Issuer"] = "https://auth-private-console.invalid",
                ["Jwt:Audience"] = "auth-private-console",
                ["Jwt:PrivateKeyPem"] = signing.ExportPkcs8PrivateKeyPem(),
                ["Jwt:KeyId"] = "auth-private-console",
                ["EmployeeRecovery:Enabled"] = "false",
                ["Observability:RuntimeMetricsEnabled"] = "false",
            }));
            builder.ConfigureTestServices(services =>
            {
                services.AddLogging(logging => logging.AddFilter<FormattedRecorder>("AuthPrivateConsoleProbe", LogLevel.Trace));
                services.AddSingleton<ILoggerProvider>(provider => new FormattedRecorder(
                    provider.GetServices<ConsoleFormatter>().Single(formatter => formatter.Name ==
                        provider.GetRequiredService<IOptions<ConsoleLoggerOptions>>().Value.FormatterName)));
                // This verifies observer registration, not real IAM, authentication handlers, retries, or business readiness.
                services.Insert(0, ServiceDescriptor.Singleton<IHttpMessageHandlerBuilderFilter>(Transport));
                services.PostConfigure<HealthCheckServiceOptions>(options =>
                {
                    options.Registrations.Clear();
                    options.Registrations.Add(new HealthCheckRegistration("private-console-fixture", _ => Health, null, ["ready"]));
                });
                services.Configure<HostOptions>(options =>
                {
                    options.StartupTimeout = TimeSpan.FromSeconds(20);
                    options.ShutdownTimeout = TimeSpan.FromSeconds(10);
                });
                services.AddControllers().AddApplicationPart(typeof(AuthPrivateConsoleFixtureController).Assembly);
            });
        }

        public override async ValueTask DisposeAsync()
        {
            try { await base.DisposeAsync(); }
            finally { signing.Dispose(); }
        }
    }

    private sealed class FormattedRecorder(ConsoleFormatter formatter) : ILoggerProvider
    {
        private readonly ConsoleFormatter selected = formatter;
        private readonly ConcurrentQueue<(string Event, string Line)> records = new();
        private int count;
        private int probeInputs;
        private int unsafeFailureInputs;
        internal int UnsafeFailureInputs => Volatile.Read(ref unsafeFailureInputs);
        internal int ProbeInputs => Volatile.Read(ref probeInputs);
        internal bool Overflowed => Volatile.Read(ref count) > 128;
        internal IReadOnlyList<string> AllLines => records.Select(record => record.Line).ToArray();
        internal IReadOnlyList<string> Lines(string name) => records.Where(record => record.Event == name).Select(record => record.Line).ToArray();
        public ILogger CreateLogger(string category) => new Recorder(this, category);
        public void Dispose() { }

        private sealed class Recorder(FormattedRecorder owner, string category) : ILogger
        {
            private readonly LoggerExternalScopeProvider scopes = new();
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => scopes.Push(state);
            public bool IsEnabled(LogLevel level) => true;
            public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> message)
            {
                var name = (state as IEnumerable<KeyValuePair<string, object?>>)?
                    .Take(64).FirstOrDefault(pair => pair.Key == "EventName").Value as string;
                if (name is not ("AuthPrivateConsoleProbe" or "DependencyRequestFailure" or "HandledOperationFailure" or "UnhandledRequestFailure" or "HealthProbeFailure")) return;
                if (exception is not null && name is ("DependencyRequestFailure" or "UnhandledRequestFailure"))
                    Interlocked.Increment(ref owner.unsafeFailureInputs);
                using var writer = new StringWriter();
                var entry = new LogEntry<TState>(level, category, id, state, exception, message);
                if (name == "AuthPrivateConsoleProbe") Interlocked.Increment(ref owner.probeInputs);
                owner.selected.Write(in entry, scopes, writer);
                var line = writer.ToString().Trim();
                if (line.Length == 0) return;
                if (Interlocked.Increment(ref owner.count) <= 128) owner.records.Enqueue((name, line));
            }
        }
    }

    private sealed class TerminalTransport : IHttpMessageHandlerBuilderFilter
    {
        internal int Status { get; set; } = 200;
        internal Exception? Failure { get; set; }
        internal ConcurrentBag<string> SelectedNames { get; } = [];
        public Action<HttpMessageHandlerBuilder> Configure(Action<HttpMessageHandlerBuilder> next) => builder =>
        {
            next(builder);
            if (builder.Name is not ("IAMService" or "LegacyAuthServiceTokenExchange" or "QuotationInvoiceLiveAuthority"
                or "InvoiceFinancialOwnership" or "EmployeeProfileBinding" or "CustomerProfileBinding")) return;
            var observers = builder.AdditionalHandlers.Where(handler =>
                handler.GetType().FullName == "Maliev.Aspire.ServiceDefaults.Diagnostics.PrivateDependencyFailureHandler").ToArray();
            if (observers.Length != 1) throw new InvalidOperationException("The actual named client must have exactly one private observer.");
            SelectedNames.Add(builder.Name);
            foreach (var handler in builder.AdditionalHandlers.Where(handler => !ReferenceEquals(handler, observers[0])).ToArray())
            {
                builder.AdditionalHandlers.Remove(handler);
                handler.Dispose();
            }
            builder.PrimaryHandler.Dispose();
            builder.PrimaryHandler = new Primary(this);
        };

        private sealed class Primary(TerminalTransport owner) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                if (owner.Failure is { } failure) throw failure;
                return Task.FromResult(new HttpResponseMessage((HttpStatusCode)owner.Status));
            }
        }
    }

    private sealed class ToggleHealth : IHealthCheck
    {
        internal bool Healthy { get; set; } = true;
        public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken token = default) =>
            Task.FromResult(Healthy ? HealthCheckResult.Healthy() : HealthCheckResult.Unhealthy(Canary));
    }
}

/// <summary>Provides anonymous synthetic failures solely for the Auth private-console response regression.</summary>
[ApiController]
[AllowAnonymous]
[Route("__fixture/auth-private-console")]
public sealed class AuthPrivateConsoleFixtureController : ControllerBase
{
    /// <summary>Returns a controlled failure without changing the ordinary response observer's ownership.</summary>
    /// <returns>The synthetic 503 response.</returns>
    [HttpGet("returned")]
    public IActionResult Returned() => StatusCode(503, new { error = "fixture-returned-failure" });

    /// <summary>Throws protected text to exercise the actual Program exception response and selected log formatter.</summary>
    /// <returns>No result because the controlled exception reaches the existing exception boundary.</returns>
    [HttpGet("throw")]
    public IActionResult Throw() => throw new Exception(AuthPrivateConsoleConsumerTests.Canary);

    /// <summary>Throws after an actual asynchronous continuation to verify bounded compiler-generated request provenance.</summary>
    /// <returns>No result because the controlled exception reaches the existing exception boundary.</returns>
    [HttpGet("throw-async")]
    public async Task<IActionResult> ThrowAsync()
    {
        await Task.Yield();
        throw new Exception(AuthPrivateConsoleConsumerTests.Canary,
            new InvalidOperationException(AuthPrivateConsoleConsumerTests.Canary));
    }
}
