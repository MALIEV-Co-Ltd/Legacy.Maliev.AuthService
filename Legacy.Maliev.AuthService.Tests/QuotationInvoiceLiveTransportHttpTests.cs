using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>Normal Program composition and real legacy service-login; external IAM is controlled HTTP only.</summary>
[Collection(PostgresCollection.Name)]
public sealed class QuotationInvoiceLiveTransportHttpTests(PostgresFixture postgres)
{
    [Fact]
    public async Task ExistingOwnWorkloadLogin_ProducesNormalSignedServiceIdentityWithoutIamOrRefresh()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateClient();
        using var response = await client.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest("legacy-auth", Factory.Secret));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var token = Assert.IsType<ServiceTokenResponse>(await response.Content.ReadFromJsonAsync<ServiceTokenResponse>());
        app.ValidateOwnToken(token.AccessToken);
        Assert.Equal("Bearer", token.TokenType);
        Assert.Equal(900, token.ExpiresIn);
        Assert.Equal(0, app.IamRequests);
        Assert.Equal(0, await stores.State.RefreshSessions.CountAsync());
    }

    [Theory]
    [InlineData("{\"allowed\":true}", QuotationInvoiceLiveAuthorityResult.Allowed)]
    [InlineData("{\"allowed\":false}", QuotationInvoiceLiveAuthorityResult.Denied)]
    public async Task NormalRegisteredClient_UsesOwnLoginAndExactUncachedEmployeeWire(string body, QuotationInvoiceLiveAuthorityResult expected)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores, iamBody: body);
        using var client = app.CreateClient();
        await using var scope = app.Services.CreateAsyncScope();
        var authority = scope.ServiceProvider.GetRequiredService<IQuotationInvoiceLiveAuthorityClient>();
        Assert.Equal(expected, await authority.CheckAsync("literal-employee", 84));
        Assert.Equal(expected, await authority.CheckAsync("literal-employee", 84));
        Assert.Equal(1, app.ExchangeRequests);
        Assert.Equal(2, app.IamRequests);
        Assert.Equal(0, await stores.State.RefreshSessions.CountAsync());
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"allowed\":null}")]
    [InlineData("{\"allowed\":\"false\"}")]
    [InlineData("{\"allowed\":[]}")]
    [InlineData("{\"allowed\":true,\"allowed\":false}")]
    [InlineData("{\"allowed\":false,\"allowed\":true}")]
    [InlineData("{\"Allowed\":true,\"allowed\":false}")]
    [InlineData("not-json")]
    public async Task MalformedLiveResponse_IsUnavailableNotDefaultDenial(string body)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores, iamBody: body);
        using var client = app.CreateClient();
        await using var scope = app.Services.CreateAsyncScope();
        var authority = scope.ServiceProvider.GetRequiredService<IQuotationInvoiceLiveAuthorityClient>();
        Assert.Equal(QuotationInvoiceLiveAuthorityResult.Unavailable, await authority.CheckAsync("literal-employee", 84));
        Assert.Equal(1, app.IamRequests);
        Assert.Equal(1, app.ExchangeRequests);
    }

    [Theory]
    [InlineData("own-secret")]
    [InlineData("own-client")]
    [InlineData("auth-origin")]
    [InlineData("iam-origin")]
    [InlineData("live-key")]
    public async Task MissingConfiguration_RemainsRequestUnavailableWithoutBreakingOldLogin(string missing)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores, missing: missing);
        using var client = app.CreateClient();
        using var original = await client.PostAsJsonAsync("/auth/v1/service/login", new ServiceLoginRequest("legacy-auth", Factory.Secret));
        Assert.Equal(HttpStatusCode.OK, original.StatusCode);
        app.ValidateOwnToken(Assert.IsType<ServiceTokenResponse>(await original.Content.ReadFromJsonAsync<ServiceTokenResponse>()).AccessToken);
        await using var scope = app.Services.CreateAsyncScope();
        Assert.Equal(QuotationInvoiceLiveAuthorityResult.Unavailable,
            await scope.ServiceProvider.GetRequiredService<IQuotationInvoiceLiveAuthorityClient>().CheckAsync("literal-employee", 84));
        Assert.Equal(0, app.IamRequests);
        Assert.Equal(0, app.ExchangeRequests);
    }

    [Theory]
    [InlineData("wrong-machine")]
    [InlineData("wrong-audience")]
    [InlineData("forged")]
    [InlineData("duplicate-sub")]
    [InlineData("duplicate-aud")]
    [InlineData("duplicate-kind")]
    [InlineData("duplicate-iat")]
    [InlineData("duplicate-exp")]
    [InlineData("employee-kind")]
    [InlineData("session-claim")]
    [InlineData("executor-claim")]
    [InlineData("session-id-claim")]
    [InlineData("family-claim")]
    [InlineData("employee-id-claim")]
    [InlineData("stamp-claim")]
    [InlineData("expired")]
    [InlineData("future-iat")]
    [InlineData("multiple-audiences")]
    public async Task LoginResponseWrongTrust_DoesNotSendCredentialedIamRequest(string mutation)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores, tokenMutation: mutation);
        using var client = app.CreateClient();
        await using var scope = app.Services.CreateAsyncScope();
        Assert.Equal(QuotationInvoiceLiveAuthorityResult.Unavailable,
            await scope.ServiceProvider.GetRequiredService<IQuotationInvoiceLiveAuthorityClient>().CheckAsync("literal-employee", 84));
        Assert.Equal(1, app.ExchangeRequests);
        Assert.Equal(0, app.IamRequests);
    }

    [Theory]
    [InlineData("exchange-hang")]
    [InlineData("iam-hang")]
    public async Task StreamingBodyDeadline_IsUnavailableAndDoesNotPoisonNextRequest(string phase)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores) { StreamMode = phase };
        using var client = app.CreateClient();
        await using var scope = app.Services.CreateAsyncScope();
        var authority = scope.ServiceProvider.GetRequiredService<IQuotationInvoiceLiveAuthorityClient>();
        var pending = authority.CheckAsync("literal-employee", 84);
        Assert.False(pending.IsCompleted);
        await app.StreamStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        app.Clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(QuotationInvoiceLiveAuthorityResult.Unavailable, await pending.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(app.StreamCancelled.Task.IsCompleted);
        app.StreamMode = null;
        Assert.Equal(QuotationInvoiceLiveAuthorityResult.Allowed, await authority.CheckAsync("literal-employee", 84));
    }

    [Theory]
    [InlineData("exchange-hang")]
    [InlineData("iam-hang")]
    public async Task CallerAbortDuringBody_PropagatesWhileSharedExchangeBackgroundRemainsBounded(string phase)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores) { StreamMode = phase };
        using var client = app.CreateClient();
        await using var scope = app.Services.CreateAsyncScope();
        using var abort = new CancellationTokenSource();
        var pending = scope.ServiceProvider.GetRequiredService<IQuotationInvoiceLiveAuthorityClient>().CheckAsync("literal-employee", 84, abort.Token);
        Assert.False(pending.IsCompleted);
        await app.StreamStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        abort.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        if (phase == "exchange-hang")
        {
            Assert.False(app.StreamCancelled.Task.IsCompleted);
            app.Clock.Advance(TimeSpan.FromSeconds(10));
        }
        await app.StreamCancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Theory]
    [InlineData("exchange-oversize")]
    [InlineData("iam-oversize")]
    public async Task OversizedBody_IsUnavailableWithoutUnboundedRead(string phase)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores) { StreamMode = phase };
        using var client = app.CreateClient();
        await using var scope = app.Services.CreateAsyncScope();
        Assert.Equal(QuotationInvoiceLiveAuthorityResult.Unavailable,
            await scope.ServiceProvider.GetRequiredService<IQuotationInvoiceLiveAuthorityClient>().CheckAsync("literal-employee", 84));
        Assert.Equal(1, app.ExchangeRequests);
        Assert.Equal(phase == "iam-oversize" ? 1 : 0, app.IamRequests);
    }

    [Theory]
    [InlineData("exchange-chunked-overflow")]
    [InlineData("iam-chunked-overflow")]
    public async Task StreamingBodyWithoutDeclaredLength_RejectsOverflow(string phase)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores) { StreamMode = phase };
        using var client = app.CreateClient();
        await using var scope = app.Services.CreateAsyncScope();
        Assert.Equal(QuotationInvoiceLiveAuthorityResult.Unavailable,
            await scope.ServiceProvider.GetRequiredService<IQuotationInvoiceLiveAuthorityClient>().CheckAsync("literal-employee", 84));
        Assert.Equal(1, app.ExchangeRequests);
        Assert.Equal(phase.StartsWith("iam-", StringComparison.Ordinal) ? 1 : 0, app.IamRequests);
    }

    [Theory]
    [InlineData("exchange-headers-hang")]
    [InlineData("iam-headers-hang")]
    public async Task HeadersDeadline_IsUnavailableBeforeBodyArrives(string phase)
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores) { StreamMode = phase };
        using var client = app.CreateClient();
        await using var scope = app.Services.CreateAsyncScope();
        var pending = scope.ServiceProvider.GetRequiredService<IQuotationInvoiceLiveAuthorityClient>().CheckAsync("literal-employee", 84);
        await app.StreamStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(pending.IsCompleted);
        app.Clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(QuotationInvoiceLiveAuthorityResult.Unavailable, await pending.WaitAsync(TimeSpan.FromSeconds(5)));
        await app.StreamCancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Theory]
    [InlineData("exchange", 307)]
    [InlineData("exchange", 308)]
    [InlineData("iam", 307)]
    [InlineData("iam", 308)]
    public async Task ActualPrimary_DoesNotFollowCredentialBearingRedirect(string phase, int status)
    {
        await using var trap = new RedirectTrap(status);
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores) { RealPrimaryPhase = phase, RealOrigin = trap.Origin };
        using var client = app.CreateClient();
        await using var scope = app.Services.CreateAsyncScope();
        Assert.Equal(QuotationInvoiceLiveAuthorityResult.Unavailable,
            await scope.ServiceProvider.GetRequiredService<IQuotationInvoiceLiveAuthorityClient>().CheckAsync("literal-employee", 84));
        Assert.Equal(1, trap.SourceRequests);
        Assert.Equal(0, trap.LeakRequests);
        Assert.Equal(phase == "exchange" ? "/auth/v1/service/login" : "/iam/v1/auth/check-permission", trap.SourcePath);
        Assert.Equal(phase == "iam", trap.SawBearer);
        Assert.True(trap.SawBody);
    }

    [Fact]
    public async Task CallerAlreadyCancelled_PropagatesWithoutAnyTransport()
    {
        await using var stores = await Stores.CreateAsync(postgres);
        await using var app = new Factory(stores);
        using var client = app.CreateClient();
        await using var scope = app.Services.CreateAsyncScope();
        using var abort = new CancellationTokenSource();
        abort.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            scope.ServiceProvider.GetRequiredService<IQuotationInvoiceLiveAuthorityClient>().CheckAsync("literal-employee", 84, abort.Token));
        Assert.Equal(0, app.ExchangeRequests);
        Assert.Equal(0, app.IamRequests);
    }

    private sealed class Factory(Stores stores, string iamBody = "{\"allowed\":true}", string? missing = null, string? tokenMutation = null)
        : WebApplicationFactory<Program>
    {
        internal const string Secret = "synthetic-own-auth-workload-secret";
        private const string LiveKey = "synthetic-live-permission-key";
        private readonly RSA key = RSA.Create(2048);
        public int ExchangeRequests { get; private set; }
        public int IamRequests { get; private set; }
        public string? StreamMode { get; set; }
        public string? RealPrimaryPhase { get; set; }
        public string? RealOrigin { get; set; }
        public FakeTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow);
        public TaskCompletionSource StreamStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource StreamCancelled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment(RealPrimaryPhase is null ? "Production" : "Testing");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                var values = new Dictionary<string, string?>
                {
                    ["ConnectionStrings:EmployeeIdentity"] = stores.Employees.Database.GetConnectionString(),
                    ["ConnectionStrings:CustomerIdentity"] = stores.Customers.Database.GetConnectionString(),
                    ["ConnectionStrings:RefreshSessions"] = stores.State.Database.GetConnectionString(),
                    ["Jwt:Issuer"] = "https://transport-auth.test",
                    ["Jwt:Audience"] = "transport-access",
                    ["Jwt:PrivateKeyPem"] = key.ExportPkcs8PrivateKeyPem(),
                    ["Jwt:KeyId"] = "transport-key",
                    ["Jwt:AccessTokenLifetimeSeconds"] = "900",
                    ["ServiceClients:Clients:legacy-auth:SecretSha256"] = ServiceClientCredential.HashSecret(Secret),
                    ["ServiceClients:Clients:legacy-auth:Permissions:0"] = "legacy.iam.permissions.check",
                    ["ServiceAuthentication:ClientId"] = missing == "own-client" ? null : "legacy-auth",
                    ["ServiceAuthentication:ClientSecret"] = missing == "own-secret" ? null : Secret,
                    ["Services:Auth:BaseUrl"] = missing == "auth-origin" ? null : RealPrimaryPhase == "exchange" ? RealOrigin : "https://transport-auth.test",
                    ["Services:IAMService:BaseUrl"] = missing == "iam-origin" ? null : RealPrimaryPhase == "iam" ? RealOrigin : "https://controlled-iam.test",
                    ["IAM:LivePermissionChecks:Credential"] = missing == "live-key" ? null : LiveKey,
                };
                configuration.AddInMemoryCollection(values);
            });
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(Clock);
                services.AddSingleton<IHttpMessageHandlerBuilderFilter>(new BoundaryFilter(this));
            });
        }

        public void ValidateOwnToken(string token)
        {
            var principal = new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = "https://transport-auth.test",
                ValidateAudience = true,
                ValidAudience = "transport-access",
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new RsaSecurityKey(key),
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                ValidateLifetime = true,
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
                ClockSkew = TimeSpan.Zero,
                LifetimeValidator = (notBefore, expires, _, _) => expires > Clock.GetUtcNow().UtcDateTime && (notBefore is null || notBefore <= Clock.GetUtcNow().UtcDateTime),
            }, out var jwt);
            Assert.Equal("RS256", Assert.IsType<JwtSecurityToken>(jwt).Header.Alg);
            Assert.Equal("service:legacy-auth", Assert.Single(principal.Claims, x => x.Type == "sub").Value);
            Assert.Equal("service", Assert.Single(principal.Claims, x => x.Type == "identity_kind").Value);
            Assert.DoesNotContain(principal.Claims, x => x.Type is "sid" or "executor");
            Assert.Equal("legacy.iam.permissions.check", Assert.Single(principal.Claims, x => x.Type == "permissions").Value);
        }

        private async Task<HttpResponseMessage> ExchangeAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            ExchangeRequests++;
            if (StreamMode == "exchange-headers-hang") await WaitForDeadlineAsync(cancellationToken);
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("https://transport-auth.test/auth/v1/service/login", request.RequestUri!.AbsoluteUri);
            Assert.Null(request.Headers.Authorization);
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            Assert.Equal("legacy-auth", body.RootElement.GetProperty("clientId").GetString());
            Assert.Equal(Secret, body.RootElement.GetProperty("clientSecret").GetString());
            using var actual = CreateClient();
            using var forwarded = new HttpRequestMessage(request.Method, request.RequestUri)
            {
                Content = new StringContent(body.RootElement.GetRawText(), Encoding.UTF8, "application/json"),
            };
            var response = await actual.SendAsync(forwarded, cancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var normalBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            var token = Assert.IsType<ServiceTokenResponse>(JsonSerializer.Deserialize<ServiceTokenResponse>(normalBytes, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
            ValidateOwnToken(token.AccessToken);
            response.Content.Dispose();
            response.Content = new ByteArrayContent(normalBytes);
            response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            if (StreamMode == "exchange-hang") response.Content = new StreamContent(new BlockingBody(this));
            if (StreamMode == "exchange-oversize") response.Content = new StringContent(new string(' ', 32769));
            if (StreamMode == "exchange-chunked-overflow") response.Content = new StreamContent(new UnknownLengthBody());
            if (tokenMutation is not null)
            {
                var parsed = new JwtSecurityTokenHandler().ReadJwtToken(token.AccessToken);
                var claims = parsed.Claims.Where(x => x.Type is not ("iss" or "aud" or "nbf" or "exp") && (tokenMutation != "wrong-machine" || x.Type != "sub")).ToList();
                if (tokenMutation == "wrong-machine") claims.Add(new Claim("sub", "service:legacy-intranet"));
                using var forged = RSA.Create(2048);
                var signingKey = tokenMutation == "forged" ? forged : key;
                var changed = new JwtSecurityToken("https://transport-auth.test", tokenMutation == "wrong-audience" ? "other-audience" : "transport-access",
                    claims, DateTime.UtcNow.AddSeconds(-1), DateTime.UtcNow.AddMinutes(15), new SigningCredentials(new RsaSecurityKey(signingKey), SecurityAlgorithms.RsaSha256));
                response.Content = JsonContent.Create(token with { AccessToken = new JwtSecurityTokenHandler().WriteToken(changed) });
                if (tokenMutation is not ("wrong-machine" or "wrong-audience" or "forged"))
                    response.Content = JsonContent.Create(token with { AccessToken = MutateSignedPayload(token.AccessToken, tokenMutation) });
            }
            return response;
        }

        private async Task<HttpResponseMessage> IamAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            IamRequests++;
            if (StreamMode == "iam-headers-hang") await WaitForDeadlineAsync(cancellationToken);
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("https://controlled-iam.test/iam/v1/auth/check-permission", request.RequestUri!.AbsoluteUri);
            Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
            ValidateOwnToken(request.Headers.Authorization.Parameter!);
            Assert.Equal(LiveKey, Assert.Single(request.Headers.GetValues("X-Maliev-IAM-Live-Check-Key")));
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            Assert.Equal("literal-employee", body.RootElement.GetProperty("principalId").GetString());
            Assert.Equal("legacy.quotations.update", body.RootElement.GetProperty("permissionId").GetString());
            Assert.Equal("/quotations/84", body.RootElement.GetProperty("resourcePath").GetString());
            Assert.True(body.RootElement.GetProperty("bypassCache").GetBoolean());
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = StreamMode == "iam-hang" ? new StreamContent(new BlockingBody(this))
                    : StreamMode == "iam-chunked-overflow" ? new StreamContent(new UnknownLengthBody())
                    : new StringContent(StreamMode == "iam-oversize" ? new string(' ', 32769) : iamBody, Encoding.UTF8, "application/json"),
            };
        }

        private async Task WaitForDeadlineAsync(CancellationToken cancellationToken)
        {
            StreamStarted.TrySetResult();
            try { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); }
            catch (OperationCanceledException) { StreamCancelled.TrySetResult(); throw; }
        }

        private string MutateSignedPayload(string token, string mutation)
        {
            var parts = token.Split('.');
            var raw = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[1]));
            using var original = JsonDocument.Parse(raw);
            if (mutation.StartsWith("duplicate-", StringComparison.Ordinal))
            {
                var property = mutation == "duplicate-kind" ? "identity_kind" : mutation[10..];
                raw = raw[..^1] + "," + JsonSerializer.Serialize(property) + ":" + original.RootElement.GetProperty(property).GetRawText() + "}";
            }
            else if (mutation == "session-claim") raw = raw[..^1] + ",\"sid\":\"synthetic-session\"}";
            else if (mutation.EndsWith("-claim", StringComparison.Ordinal))
            {
                var claim = mutation switch { "executor-claim" => "executor", "session-id-claim" => "session_id", "family-claim" => "family_id", "employee-id-claim" => "employee_id", _ => "security_stamp" };
                raw = raw[..^1] + "," + JsonSerializer.Serialize(claim) + ":\"synthetic-ambiguous-identity\"}";
            }
            else
            {
                var name = mutation switch { "employee-kind" => "identity_kind", "expired" => "exp", "future-iat" => "iat", _ => "aud" };
                var replacement = mutation switch
                {
                    "employee-kind" => "\"employee\"",
                    "expired" => (Clock.GetUtcNow().ToUnixTimeSeconds() - 1).ToString(System.Globalization.CultureInfo.InvariantCulture),
                    "future-iat" => (Clock.GetUtcNow().ToUnixTimeSeconds() + 1000).ToString(System.Globalization.CultureInfo.InvariantCulture),
                    _ => "[\"transport-access\",\"other-audience\"]",
                };
                raw = raw.Replace(JsonSerializer.Serialize(name) + ":" + original.RootElement.GetProperty(name).GetRawText(), JsonSerializer.Serialize(name) + ":" + replacement, StringComparison.Ordinal);
            }
            var input = parts[0] + "." + Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(raw));
            return input + "." + Base64UrlEncoder.Encode(key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        private sealed class BlockingBody(Factory app) : Stream
        {
            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                app.StreamStarted.TrySetResult();
                try { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); }
                catch (OperationCanceledException) { app.StreamCancelled.TrySetResult(); throw; }
                return 0;
            }
            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override void Flush() => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }

        private sealed class BoundaryFilter(Factory app) : IHttpMessageHandlerBuilderFilter
        {
            public Action<HttpMessageHandlerBuilder> Configure(Action<HttpMessageHandlerBuilder> next) => builder =>
            {
                next(builder);
                if (builder.Name is "LegacyAuthServiceTokenExchange" or "QuotationInvoiceLiveAuthority")
                {
                    Assert.False(Assert.IsType<HttpClientHandler>(builder.PrimaryHandler).AllowAutoRedirect);
                    Assert.DoesNotContain(builder.AdditionalHandlers, x => x is Microsoft.Extensions.Http.Resilience.ResilienceHandler);
                }
                if (builder.Name == "LegacyAuthServiceTokenExchange" && app.RealPrimaryPhase != "exchange") builder.PrimaryHandler = new BoundaryHandler(app.ExchangeAsync);
                if (builder.Name == "QuotationInvoiceLiveAuthority" && app.RealPrimaryPhase != "iam") builder.PrimaryHandler = new BoundaryHandler(app.IamAsync);
            };
        }

        private sealed class BoundaryHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken);
        }

        public override async ValueTask DisposeAsync()
        {
            await base.DisposeAsync();
            key.Dispose();
        }
    }

    private sealed class UnknownLengthBody : Stream
    {
        private int remaining = 32769;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var count = Math.Min(buffer.Length, remaining);
            buffer.Span[..count].Fill((byte)' ');
            remaining -= count;
            return ValueTask.FromResult(count);
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class RedirectTrap : IAsyncDisposable
    {
        private readonly HttpListener listener = new();
        private readonly CancellationTokenSource stop = new();
        private readonly Task loop;
        public string Origin { get; }
        public int SourceRequests { get; private set; }
        public int LeakRequests { get; private set; }
        public string? SourcePath { get; private set; }
        public bool SawBearer { get; private set; }
        public bool SawBody { get; private set; }
        public RedirectTrap(int status)
        {
            var reservation = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            reservation.Start();
            var port = ((IPEndPoint)reservation.LocalEndpoint).Port;
            reservation.Stop();
            Origin = $"http://127.0.0.1:{port}";
            listener.Prefixes.Add(Origin + "/");
            listener.Start();
            loop = RunAsync(status);
        }
        private async Task RunAsync(int status)
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    var context = await listener.GetContextAsync().WaitAsync(stop.Token);
                    if (context.Request.Url!.AbsolutePath == "/leak") LeakRequests++;
                    else
                    {
                        SourceRequests++;
                        SourcePath = context.Request.Url.AbsolutePath;
                        SawBearer = context.Request.Headers["Authorization"]?.StartsWith("Bearer ", StringComparison.Ordinal) == true;
                        using var sink = new MemoryStream();
                        await context.Request.InputStream.CopyToAsync(sink, stop.Token);
                        SawBody = sink.Length > 0;
                    }
                    context.Response.StatusCode = status;
                    context.Response.RedirectLocation = Origin + "/leak";
                    context.Response.ContentLength64 = 0;
                    context.Response.Close();
                }
            }
            catch (Exception exception) when (stop.IsCancellationRequested && exception is OperationCanceledException or HttpListenerException or ObjectDisposedException) { }
        }
        public async ValueTask DisposeAsync()
        {
            stop.Cancel();
            listener.Close();
            await loop.WaitAsync(TimeSpan.FromSeconds(5));
            stop.Dispose();
        }
    }

    private sealed class Stores(EmployeeIdentityDbContext employees, CustomerIdentityDbContext customers, RefreshSessionDbContext state) : IAsyncDisposable
    {
        public EmployeeIdentityDbContext Employees { get; } = employees;
        public CustomerIdentityDbContext Customers { get; } = customers;
        public RefreshSessionDbContext State { get; } = state;
        public static async Task<Stores> CreateAsync(PostgresFixture postgres)
            => new(await postgres.CreateEmployeeContextAsync(), await postgres.CreateCustomerContextAsync(), await postgres.CreateStateContextAsync());
        public async ValueTask DisposeAsync()
        {
            var connections = new[] { (NpgsqlConnection)Employees.Database.GetDbConnection(), (NpgsqlConnection)Customers.Database.GetDbConnection(), (NpgsqlConnection)State.Database.GetDbConnection() };
            await Employees.DisposeAsync();
            await Customers.DisposeAsync();
            await State.DisposeAsync();
            foreach (var connection in connections) NpgsqlConnection.ClearPool(connection);
        }
    }
}
