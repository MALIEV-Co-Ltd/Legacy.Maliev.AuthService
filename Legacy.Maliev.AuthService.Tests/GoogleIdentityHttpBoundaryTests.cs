using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Api.Controllers;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Globalization;
using System.Collections.Concurrent;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class GoogleIdentityHttpBoundaryTests
{
    private const string NonceRoute = "/auth/v1/exchange/google/nonce";
    private const string ExchangeRoute = "/auth/v1/exchange/google";
    private const string Credential = "synthetic-google-credential";
    private static readonly string Nonce = new('n', 64);

    [Fact]
    public async Task NormalProgramUnhandledFailure_GoogleNonceEmitsOneSanitizedCriticalIncident()
    {
        const string correlation = "auth-google-incident";
        const string querySecret = "controlled-private-query";
        const string headerSecret = "controlled-private-header";
        var state = new State { Mode = "nonce_unknown_failure" };
        using var incidents = new IncidentCaptureProvider();
        using var factory = new Factory(state, incidents);
        using var client = TrustedClient(factory);
        Assert.Equal(Environments.Production, factory.Services.GetRequiredService<IHostEnvironment>().EnvironmentName);
        var authorizationHeader = client.DefaultRequestHeaders.Authorization!;
        var authorization = authorizationHeader.ToString();
        client.DefaultRequestHeaders.Add("X-Correlation-ID", correlation);
        client.DefaultRequestHeaders.Add("X-Controlled-Secret", headerSecret);
        var before = DateTimeOffset.UtcNow;
        using var response = await client.PostAsJsonAsync(NonceRoute + "?token=" + querySecret, new GoogleIdentityNonceRequest("intranet"));
        var after = DateTimeOffset.UtcNow;
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType!.MediaType);
        Assert.Equal(correlation, Assert.Single(response.Headers.GetValues("X-Correlation-ID")));
        var body = await response.Content.ReadAsStringAsync();
        using var json = JsonDocument.Parse(body);
        Assert.Equal(new[] { "details", "error", "statusCode", "traceId" }, json.RootElement.EnumerateObject().Select(value => value.Name).Order().ToArray());
        Assert.Equal(500, json.RootElement.GetProperty("statusCode").GetInt32());
        Assert.Equal("An internal server error occurred", json.RootElement.GetProperty("error").GetString());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("details").ValueKind);
        var traceId = json.RootElement.GetProperty("traceId").GetString();
        Assert.False(string.IsNullOrWhiteSpace(traceId));
        var entry = Assert.Single(incidents.Entries);
        Assert.Equal(LogLevel.Critical, entry.Level);
        Assert.Equal("Maliev.Aspire.ServiceDefaults.Middleware.ExceptionHandlingMiddleware", entry.Category);
        Assert.Null(entry.Exception);
        Assert.Equal(new[] { "EventName", "ExceptionType", "IncidentId", "Method", "OccurredAtUtc", "Path", "Service", "StatusCode" }, entry.Values.Keys.Order().ToArray());
        Assert.Equal("UnhandledRequestFailure", entry.Values["EventName"]);
        Assert.Equal("Exception", entry.Values["ExceptionType"]);
        Assert.Equal(traceId, entry.Values["IncidentId"]);
        Assert.Equal("POST", entry.Values["Method"]);
        var route = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>()
            .Single(endpoint => endpoint.Metadata.GetMetadata<ControllerActionDescriptor>()?.MethodInfo.Name == nameof(AuthenticationController.IssueEmployeeGoogleNonce))
            .RoutePattern.RawText;
        Assert.NotNull(route);
        Assert.Equal(NonceRoute.TrimStart('/'), route.TrimStart('/'));
        Assert.Equal(route, entry.Values["Path"]);
        Assert.Equal(factory.Services.GetRequiredService<IHostEnvironment>().ApplicationName, entry.Values["Service"]);
        Assert.Equal(500, entry.Values["StatusCode"]);
        var occurred = DateTimeOffset.ParseExact(Assert.IsType<string>(entry.Values["OccurredAtUtc"]), "O", CultureInfo.InvariantCulture);
        Assert.Equal(TimeSpan.Zero, occurred.Offset);
        Assert.InRange(occurred, before, after);
        var captured = body + entry.Message + JsonSerializer.Serialize(entry.Values);
        foreach (var secret in new[] { querySecret, headerSecret, "controlled-private-exception", authorization, authorizationHeader.Parameter!, Credential, Nonce })
            Assert.DoesNotContain(secret, captured, StringComparison.Ordinal);
        Assert.Equal(new[] { "issue-nonce" }, state.Events);
        Assert.Equal("legacy-intranet", state.ServiceName);
        Assert.Equal("intranet", state.Application);
        Assert.Null(state.Created);
    }

    [Theory]
    [InlineData("anonymous", HttpStatusCode.Unauthorized)]
    [InlineData("unprivileged-service", HttpStatusCode.Forbidden)]
    [InlineData("customer", HttpStatusCode.Forbidden)]
    [InlineData("employee", HttpStatusCode.Forbidden)]
    public async Task UntrustedCallers_CannotIssueNonceOrExchangeCredential(string actor, HttpStatusCode expected)
    {
        var state = new State();
        using var factory = new Factory(state);
        using var client = actor == "anonymous" ? factory.CreateClient(new WebApplicationFactoryClientOptions
        { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false }) : factory.CreateAuthorizedClient(
            actor switch
            {
                "customer" => factory.IssueCustomer(),
                "employee" => factory.IssueEmployee(),
                _ => factory.IssueService([]),
            });
        using var nonce = await client.PostAsJsonAsync(NonceRoute, new GoogleIdentityNonceRequest("intranet"));
        using var exchange = await client.PostAsJsonAsync(ExchangeRoute, Request());
        Assert.Equal(expected, nonce.StatusCode);
        Assert.Equal(expected, exchange.StatusCode);
        Assert.Empty(state.Events);
        Assert.Null(state.Created);
    }

    [Theory]
    [InlineData(NonceRoute)]
    [InlineData(ExchangeRoute)]
    public async Task SignedMachineWithoutServiceName_IsForbiddenBeforeUpstreamAccess(string route)
    {
        var state = new State();
        using var factory = new Factory(state);
        using var client = factory.CreateAuthorizedClient(factory.IssueMachineWithoutName());
        using var response = route == NonceRoute
            ? await client.PostAsJsonAsync(route, new GoogleIdentityNonceRequest("intranet"))
            : await client.PostAsJsonAsync(route, Request());
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(state.Events);
        Assert.Null(state.Created);
    }

    [Theory]
    [InlineData(NonceRoute, "application")]
    [InlineData(ExchangeRoute, "credential")]
    [InlineData(ExchangeRoute, "nonce")]
    public async Task InvalidJsonFields_AreRejectedBeforeGoogleOrSessionAccess(string route, string field)
    {
        var state = new State();
        using var factory = new Factory(state);
        using var client = TrustedClient(factory);
        using var response = route == NonceRoute
            ? await client.PostAsJsonAsync(route, new GoogleIdentityNonceRequest(""))
            : await client.PostAsJsonAsync(route, field == "credential"
                ? Request() with { Credential = "" } : Request() with { Nonce = "short" });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(state.Events);
        Assert.Null(state.Created);
    }

    [Theory]
    [InlineData(NonceRoute)]
    [InlineData(ExchangeRoute)]
    public async Task UnsupportedApplication_IsForbiddenBeforeNonceOrCredentialAccess(string route)
    {
        var state = new State();
        using var factory = new Factory(state);
        using var client = TrustedClient(factory);
        using var response = route == NonceRoute
            ? await client.PostAsJsonAsync(route, new GoogleIdentityNonceRequest("web"))
            : await client.PostAsJsonAsync(route, Request() with { Application = "web" });
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(state.Events);
        Assert.Null(state.Created);
    }

    [Fact]
    public async Task NonceResponse_IsBrowserSafeAndBoundToTheAuthenticatedService()
    {
        var state = new State();
        using var factory = new Factory(state);
        using var client = TrustedClient(factory);
        using var response = await client.PostAsJsonAsync(NonceRoute, new GoogleIdentityNonceRequest("intranet"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<GoogleIdentityNonceResponse>();
        Assert.NotNull(result);
        Assert.Equal(Nonce, result.Nonce);
        Assert.Equal(state.Now.AddMinutes(10), result.ExpiresAtUtc);
        Assert.Equal(new[] { "issue-nonce" }, state.Events);
        Assert.Equal("legacy-intranet", state.ServiceName);
        Assert.Equal("intranet", state.Application);
        Assert.Null(state.Created);
    }

    [Theory]
    [InlineData("invalid_nonce", HttpStatusCode.Unauthorized)]
    [InlineData("invalid_google_credential", HttpStatusCode.Unauthorized)]
    [InlineData("invalid_domain", HttpStatusCode.Forbidden)]
    [InlineData("employee_not_found", HttpStatusCode.Forbidden)]
    [InlineData("service_unavailable", HttpStatusCode.ServiceUnavailable)]
    [InlineData("validation_timeout", HttpStatusCode.ServiceUnavailable)]
    public async Task FailedExchange_MapsPublicStatusWithoutPersistingOrDisclosingInputs(string mode, HttpStatusCode expected)
    {
        var state = new State { Mode = mode };
        using var factory = new Factory(state);
        using var client = TrustedClient(factory);
        using var response = await client.PostAsJsonAsync(ExchangeRoute, Request());
        Assert.Equal(expected, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        var problem = await response.Content.ReadFromJsonAsync<ProblemDetails>();
        Assert.NotNull(problem);
        Assert.Equal((int)expected, problem.Status);
        Assert.Equal(expected switch
        {
            HttpStatusCode.Forbidden => "Google employee access is not permitted.",
            HttpStatusCode.ServiceUnavailable => "Google sign-in is temporarily unavailable.",
            _ => "Authentication failed"
        }, problem.Title);
        Assert.DoesNotContain(Credential, body, StringComparison.Ordinal);
        Assert.DoesNotContain(Nonce, body, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic upstream failure", body, StringComparison.Ordinal);
        Assert.Null(state.Created);
        Assert.DoesNotContain("issue-access", state.Events);
        Assert.Equal("consume", state.Events[0]);
        Assert.Equal("legacy-intranet", state.ServiceName);
        Assert.Equal("intranet", state.Application);
        if (mode == "invalid_nonce") Assert.Equal(new[] { "consume" }, state.Events);
    }

    [Fact]
    public async Task NonceUpstreamTimeout_ReturnsUnavailableWithoutLeakingFailureText()
    {
        var state = new State { Mode = "nonce_timeout" };
        using var factory = new Factory(state);
        using var client = TrustedClient(factory);
        using var response = await client.PostAsJsonAsync(NonceRoute, new GoogleIdentityNonceRequest("intranet"));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.DoesNotContain("synthetic upstream failure", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(new[] { "issue-nonce" }, state.Events);
        Assert.Null(state.Created);
    }

    [Fact]
    public async Task SuccessfulExchange_BindsEmployeeJwtToHashedRefreshSessionAndRejectsNonceReplay()
    {
        var state = new State();
        using var factory = new Factory(state);
        using var client = TrustedClient(factory);
        using var response = await client.PostAsJsonAsync(ExchangeRoute, Request());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var token = await response.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.NotNull(token);
        var session = Assert.IsType<RefreshSession>(state.Created);
        Assert.Equal("Bearer", token.TokenType);
        Assert.Equal(900, token.ExpiresIn);
        Assert.Equal(state.Now.AddDays(14), token.RefreshExpiresAt);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token.RefreshToken))), session.TokenHash);
        Assert.Equal(IdentityKind.Employee, session.IdentityKind);
        Assert.Equal("employee-google-47", session.IdentityId);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token.AccessToken);
        Assert.Equal("employee-google-47", jwt.Subject);
        Assert.Equal("employee", Assert.Single(jwt.Claims, claim => claim.Type == "identity_kind").Value);
        Assert.Contains(jwt.Claims, claim => claim.Type == "permissions" && claim.Value == LegacyAccessTokenPermissions.QuotationsUpdate);
        Assert.DoesNotContain(jwt.Claims, claim => claim.Type == "permissions" && claim.Value == LegacyAccessTokenPermissions.GoogleIdentityExchange);
        Assert.Equal(session.Id.ToString("D"), Assert.Single(jwt.Claims, claim => claim.Type == "sid").Value);
        Assert.Equal(new[] { "consume", "validate", "lookup", "store", "issue-access" }, state.Events);

        using var replay = await client.PostAsJsonAsync(ExchangeRoute, Request());
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        Assert.Equal(1, state.Events.Count(value => value == "store"));
        Assert.Equal(1, state.Events.Count(value => value == "validate"));
    }

    private static GoogleExchangeRequest Request() => new(Credential, "intranet", Nonce);
    private static HttpClient TrustedClient(Factory factory) => factory.CreateAuthorizedClient(
        factory.IssueService([LegacyAccessTokenPermissions.GoogleIdentityExchange]));

    private sealed class Factory(State state, IncidentCaptureProvider? incidents = null) : CustomerIdentityAuthorizationTests.AuthApiFactory
    {
        public string IssueMachineWithoutName()
        {
            var options = Services.GetRequiredService<IOptions<JwtOptions>>().Value;
            using var key = RSA.Create();
            key.ImportFromPem(options.PrivateKeyPem);
            var now = DateTime.UtcNow;
            var token = new JwtSecurityToken(options.Issuer, options.Audience,
                [new Claim("sub", "service:legacy-intranet"), new Claim("identity_kind", "service"),
                    new Claim("permissions", LegacyAccessTokenPermissions.GoogleIdentityExchange)],
                now, now.AddMinutes(5), new SigningCredentials(
                    new RsaSecurityKey(key) { KeyId = options.KeyId }, SecurityAlgorithms.RsaSha256));
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            if (incidents is not null)
            {
                builder.UseEnvironment(Environments.Production);
                builder.ConfigureLogging(logging => logging.AddProvider(incidents));
            }
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<GoogleAuthenticationService>();
                services.AddScoped(provider => new GoogleAuthenticationService(
                    state, state, state, new RecordingIssuer(state, provider.GetRequiredService<IAccessTokenIssuer>()),
                    state, new FakeTimeProvider(state.Now)));
            });
        }
    }

    private sealed class RecordingIssuer(State state, IAccessTokenIssuer issuer) : IAccessTokenIssuer
    {
        public IssuedAccessToken Issue(LegacyIdentity identity, DateTimeOffset now, Guid? employeeSessionId)
        {
            state.Events.Add("issue-access");
            return issuer.Issue(identity, now, employeeSessionId);
        }
    }

    private sealed class State : IGoogleIdentityNonceService, IGoogleIdentityTokenValidator, IGoogleEmployeeIdentityReader, IRefreshSessionStore
    {
        public string Mode { get; init; } = "success";
        public DateTimeOffset Now { get; } = DateTimeOffset.UtcNow;
        public List<string> Events { get; } = [];
        public string? ServiceName { get; private set; }
        public string? Application { get; private set; }
        public RefreshSession? Created { get; private set; }
        private bool consumed;

        public Task<(string Nonce, DateTimeOffset ExpiresAtUtc)> IssueAsync(string serviceName, string application, CancellationToken cancellationToken)
        {
            Events.Add("issue-nonce");
            ServiceName = serviceName;
            Application = application;
            if (Mode == "nonce_timeout") throw new OperationCanceledException("synthetic upstream failure");
            if (Mode == "nonce_unknown_failure") throw new Exception("controlled-private-exception");
            return Task.FromResult((Nonce, Now.AddMinutes(10)));
        }

        public Task<bool> ConsumeAsync(string nonce, string serviceName, string application, CancellationToken cancellationToken)
        {
            Events.Add("consume");
            ServiceName = serviceName;
            Application = application;
            var accepted = !consumed && Mode != "invalid_nonce" && nonce == Nonce;
            consumed = true;
            return Task.FromResult(accepted);
        }

        public Task<GoogleIdentityValidationResult> ValidateAsync(string credential, string application, string expectedNonce, CancellationToken cancellationToken)
        {
            Events.Add("validate");
            if (Mode == "validation_timeout") throw new OperationCanceledException("synthetic upstream failure");
            Assert.Equal(Credential, credential);
            Assert.Equal(Nonce, expectedNonce);
            Assert.Equal("intranet", application);
            return Task.FromResult(Mode is "invalid_domain" or "invalid_google_credential" or "service_unavailable"
                ? new GoogleIdentityValidationResult(false, null, Mode, "synthetic upstream failure")
                : new GoogleIdentityValidationResult(true, new VerifiedGoogleIdentity("google-47", "employee@maliev.test", true, "maliev.test", null, null), null, null));
        }

        public Task<LegacyIdentity?> FindActiveEmployeeByEmailAsync(string email, CancellationToken cancellationToken)
        {
            Events.Add("lookup");
            Assert.Equal("employee@maliev.test", email);
            return Task.FromResult<LegacyIdentity?>(Mode == "employee_not_found" ? null
                : new LegacyIdentity("employee-google-47", email, email, IdentityKind.Employee, 47, "google-security-stamp"));
        }

        public Task CreateAsync(RefreshSession session, CancellationToken cancellationToken)
        {
            Events.Add("store");
            Created = session;
            return Task.CompletedTask;
        }

        public Task<RefreshRotationResult> RotateAsync(string presentedHash, RefreshSession replacement, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Google exchange must not rotate an existing refresh session.");

        public Task RevokeFamilyAsync(string tokenHash, DateTimeOffset now, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Google exchange must not revoke an existing refresh session.");
    }

    private sealed class IncidentCaptureProvider : ILoggerProvider
    {
        public ConcurrentQueue<IncidentEntry> Entries { get; } = new();
        public ILogger CreateLogger(string categoryName) => new IncidentLogger(categoryName, Entries);
        public void Dispose() { }
    }

    private sealed class IncidentLogger(string category, ConcurrentQueue<IncidentEntry> entries) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (category == "Maliev.Aspire.ServiceDefaults.Middleware.ExceptionHandlingMiddleware")
                entries.Enqueue(new IncidentEntry(category, logLevel, exception, formatter(state, exception),
                    ((IEnumerable<KeyValuePair<string, object?>>)state!).Where(pair => pair.Key != "{OriginalFormat}").ToDictionary()));
        }
    }

    private sealed record IncidentEntry(string Category, LogLevel Level, Exception? Exception, string Message,
        Dictionary<string, object?> Values);
}
