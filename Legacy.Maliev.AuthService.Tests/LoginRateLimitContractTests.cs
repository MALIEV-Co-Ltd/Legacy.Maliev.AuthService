using System.Net;
using System.Net.Http.Json;
using System.Collections;
using System.Reflection;
using Legacy.Maliev.AuthService.Api.Controllers;
using Legacy.Maliev.AuthService.Api.Security;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class LoginRateLimitContractTests
{
    [Fact]
    public async Task UndefinedNumericIdentityKind_IsRejectedByHttpPipelineBeforeCredentialVerification()
    {
        var validator = new RecordingCredentialValidator();
        using var limiter = new LoginAttemptRateLimiter(TimeProvider.System);
        await using var application = await StartLoginApplicationAsync(validator, limiter);
        using var client = new HttpClient { BaseAddress = ResolveAddress(application) };

        var response = await client.PostAsJsonAsync(
            "/auth/v1/login",
            new
            {
                userName = "employee@maliev.com",
                password = "invalid",
                identityKind = 37,
            });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, validator.CallCount);
        Assert.Equal(0, limiter.TrackedPartitionCount);
    }

    [Fact]
    public async Task ConcurrentExpiryCleanup_DoesNotSplitOneIdentityAcrossOrphanAndReplacementWindows()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 7, 17, 0, 0, 0, TimeSpan.Zero));
        using var limiter = new LoginAttemptRateLimiter(clock);
        var filter = new LoginRateLimitFilter(limiter);
        var request = new LoginRequest("employee@maliev.com", "invalid", IdentityKind.Employee);

        for (var attempt = 0; attempt < 255; attempt++)
        {
            var context = CreateContext(request);
            await filter.OnActionExecutionAsync(context, Next(context, static () => { }));
        }

        clock.Advance(TimeSpan.FromMinutes(1));
        var syncRoot = GetOnlyPartitionSyncRoot(limiter);
        var executed = 0;
        Thread? cleanupThread = null;
        Thread? staleReferenceThread = null;
        Task cleanupTask;
        Task staleReferenceTask;

        Monitor.Enter(syncRoot);
        try
        {
            cleanupTask = Task.Run(async () =>
            {
                cleanupThread = Thread.CurrentThread;
                var context = CreateContext(request);
                await filter.OnActionExecutionAsync(
                    context,
                    Next(context, () => Interlocked.Increment(ref executed)));
            });
            Assert.True(SpinWait.SpinUntil(
                () => IsWaiting(cleanupThread),
                TimeSpan.FromSeconds(5)),
                "Cleanup request did not block on the expired partition as expected.");

            staleReferenceTask = Task.Run(async () =>
            {
                staleReferenceThread = Thread.CurrentThread;
                var context = CreateContext(request);
                await filter.OnActionExecutionAsync(
                    context,
                    Next(context, () => Interlocked.Increment(ref executed)));
            });
            Assert.True(SpinWait.SpinUntil(
                () => IsWaiting(staleReferenceThread),
                TimeSpan.FromSeconds(5)),
                "Concurrent request did not retain and wait on the expiring partition as expected.");
        }
        finally
        {
            Monitor.Exit(syncRoot);
        }

        await Task.WhenAll(cleanupTask!, staleReferenceTask!);
        for (var attempt = 0; attempt < LoginAttemptRateLimiter.PermitLimit; attempt++)
        {
            var context = CreateContext(request);
            await filter.OnActionExecutionAsync(
                context,
                Next(context, () => Interlocked.Increment(ref executed)));
        }

        Assert.Equal(LoginAttemptRateLimiter.PermitLimit, executed);
    }

    [Fact]
    public async Task IdentifierSpray_IsGloballyBoundedWithoutRetainingUnboundedPartitions()
    {
        using var limiter = new LoginAttemptRateLimiter(TimeProvider.System);
        var filter = new LoginRateLimitFilter(limiter);
        var executed = 0;

        for (var attempt = 0; attempt < LoginAttemptRateLimiter.GlobalPermitLimit + 100; attempt++)
        {
            var context = CreateContext(new LoginRequest(
                $"spray-{attempt}@maliev.com",
                "invalid",
                IdentityKind.Employee));
            await filter.OnActionExecutionAsync(context, Next(context, () => executed++));
        }

        Assert.Equal(LoginAttemptRateLimiter.GlobalPermitLimit, executed);
        Assert.InRange(
            limiter.TrackedPartitionCount,
            1,
            LoginAttemptRateLimiter.GlobalPermitLimit);
    }

    [Fact]
    public async Task DifferentEmployeeIdentifiersBehindOneBffIp_DoNotShareTheAccountBucket()
    {
        using var limiter = new LoginAttemptRateLimiter(TimeProvider.System);
        var filter = new LoginRateLimitFilter(limiter);
        var executed = 0;

        for (var attempt = 0; attempt < LoginAttemptRateLimiter.PermitLimit; attempt++)
        {
            var context = CreateContext(new LoginRequest("first@maliev.com", "invalid", IdentityKind.Employee));
            await filter.OnActionExecutionAsync(context, Next(context, () => executed++));
            Assert.Null(context.Result);
        }

        var secondEmployee = CreateContext(
            new LoginRequest("second@maliev.com", "invalid", IdentityKind.Employee));
        await filter.OnActionExecutionAsync(secondEmployee, Next(secondEmployee, () => executed++));

        Assert.Null(secondEmployee.Result);
        Assert.Equal(LoginAttemptRateLimiter.PermitLimit + 1, executed);
    }

    [Fact]
    public async Task SameNormalizedIdentifier_IsBoundedAcrossWhitespaceCasingAndSpoofedForwardingHeaders()
    {
        using var limiter = new LoginAttemptRateLimiter(TimeProvider.System);
        var filter = new LoginRateLimitFilter(limiter);
        var executed = 0;

        for (var attempt = 0; attempt < LoginAttemptRateLimiter.PermitLimit; attempt++)
        {
            var identifier = attempt % 2 == 0 ? " Employee@Maliev.com " : "employee@maliev.COM";
            var context = CreateContext(
                new LoginRequest(identifier, "invalid", IdentityKind.Employee),
                forwardedFor: $"203.0.113.{attempt + 1}");
            await filter.OnActionExecutionAsync(context, Next(context, () => executed++));
            Assert.Null(context.Result);
        }

        var rejected = CreateContext(
            new LoginRequest("  EMPLOYEE@MALIEV.COM  ", "invalid", IdentityKind.Employee),
            forwardedFor: "198.51.100.250");
        await filter.OnActionExecutionAsync(rejected, Next(rejected, () => executed++));

        var result = Assert.IsType<StatusCodeResult>(rejected.Result);
        Assert.Equal(StatusCodes.Status429TooManyRequests, result.StatusCode);
        Assert.Equal(LoginAttemptRateLimiter.PermitLimit, executed);
        var retryAfter = Assert.Single(rejected.HttpContext.Response.Headers.RetryAfter);
        Assert.True(int.TryParse(retryAfter, out var retryAfterSeconds));
        Assert.InRange(retryAfterSeconds, 1, 60);
    }

    [Fact]
    public async Task EmployeeAndCustomerWithSameIdentifier_UseSeparateCompositePartitions()
    {
        using var limiter = new LoginAttemptRateLimiter(TimeProvider.System);
        var filter = new LoginRateLimitFilter(limiter);

        for (var attempt = 0; attempt < LoginAttemptRateLimiter.PermitLimit; attempt++)
        {
            var employee = CreateContext(
                new LoginRequest("member@maliev.com", "invalid", IdentityKind.Employee));
            await filter.OnActionExecutionAsync(employee, Next(employee, static () => { }));
            Assert.Null(employee.Result);
        }

        var customer = CreateContext(
            new LoginRequest("member@maliev.com", "invalid", IdentityKind.Customer));
        await filter.OnActionExecutionAsync(customer, Next(customer, static () => { }));

        Assert.Null(customer.Result);
    }

    [Fact]
    public async Task Rejection_DoesNotExposeTheSensitiveIdentifier()
    {
        const string sensitiveIdentifier = "private.employee@maliev.com";
        using var limiter = new LoginAttemptRateLimiter(TimeProvider.System);
        var filter = new LoginRateLimitFilter(limiter);

        for (var attempt = 0; attempt <= LoginAttemptRateLimiter.PermitLimit; attempt++)
        {
            var context = CreateContext(
                new LoginRequest(sensitiveIdentifier, "invalid", IdentityKind.Employee));
            await filter.OnActionExecutionAsync(context, Next(context, static () => { }));
            if (attempt == LoginAttemptRateLimiter.PermitLimit)
            {
                Assert.IsType<StatusCodeResult>(context.Result);
                Assert.DoesNotContain(
                    sensitiveIdentifier,
                    context.HttpContext.Response.Headers.ToString(),
                    StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(
                    sensitiveIdentifier,
                    context.Result?.ToString(),
                    StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    private static ActionExecutingContext CreateContext(LoginRequest request, string? forwardedFor = null)
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("10.42.0.17");
        if (forwardedFor is not null)
        {
            httpContext.Request.Headers["X-Forwarded-For"] = forwardedFor;
        }

        var actionContext = new ActionContext(
            httpContext,
            new RouteData(),
            new ActionDescriptor(),
            new ModelStateDictionary());
        return new ActionExecutingContext(
            actionContext,
            [],
            new Dictionary<string, object?> { ["request"] = request },
            new object());
    }

    private static ActionExecutionDelegate Next(ActionExecutingContext context, Action callback) => () =>
    {
        callback();
        return Task.FromResult(new ActionExecutedContext(context, [], context.Controller));
    };

    private static async Task<WebApplication> StartLoginApplicationAsync(
        RecordingCredentialValidator validator,
        LoginAttemptRateLimiter limiter)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
        builder.Services.AddControllers().AddApplicationPart(typeof(AuthenticationController).Assembly);
        builder.Services.AddSingleton(limiter);
        builder.Services.AddSingleton<LoginRateLimitFilter>();
        builder.Services.AddSingleton(new AuthenticationService(
            validator,
            new MissingIdentityReader(),
            new NoopTokenIssuer(),
            new NoopRefreshSessionStore(),
            TimeProvider.System));
        builder.Services.AddSingleton(new ServiceAuthenticationService(
            Options.Create(new ServiceClientOptions()),
            new NoopTokenIssuer(),
            TimeProvider.System));

        var application = builder.Build();
        application.MapControllers();
        await application.StartAsync();
        return application;
    }

    private static Uri ResolveAddress(WebApplication application)
    {
        var server = application.Services.GetRequiredService<IServer>();
        var address = Assert.Single(server.Features.Get<IServerAddressesFeature>()!.Addresses);
        return new Uri(address, UriKind.Absolute);
    }

    private static object GetOnlyPartitionSyncRoot(LoginAttemptRateLimiter limiter)
    {
        var partitions = typeof(LoginAttemptRateLimiter)
            .GetField("partitions", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(limiter)!;
        var values = Assert.IsAssignableFrom<IEnumerable>(
            partitions.GetType().GetProperty("Values")!.GetValue(partitions));
        var window = Assert.Single(values.Cast<object>());
        return window.GetType().GetProperty("SyncRoot")!.GetValue(window)!;
    }

    private static bool IsWaiting(Thread? thread) =>
        thread is not null && (thread.ThreadState & ThreadState.WaitSleepJoin) != 0;

    private sealed class RecordingCredentialValidator : ILegacyCredentialValidator
    {
        public int CallCount { get; private set; }

        public Task<LegacyIdentity?> ValidateAsync(
            string userName,
            string password,
            IdentityKind kind,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult<LegacyIdentity?>(null);
        }
    }

    private sealed class MissingIdentityReader : ILegacyIdentityReader
    {
        public Task<LegacyIdentity?> FindActiveAsync(
            string identityId,
            IdentityKind kind,
            CancellationToken cancellationToken) => Task.FromResult<LegacyIdentity?>(null);
    }

    private sealed class NoopTokenIssuer : IAccessTokenIssuer, IServiceAccessTokenIssuer
    {
        public IssuedAccessToken Issue(LegacyIdentity identity, DateTimeOffset now) => new("unused", 900);

        public IssuedAccessToken IssueService(
            string clientId,
            IReadOnlyList<string> permissions,
            DateTimeOffset now) => new("unused", 900);
    }

    private sealed class NoopRefreshSessionStore : IRefreshSessionStore
    {
        public Task CreateAsync(RefreshSession session, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<RefreshRotationResult> RotateAsync(
            string presentedHash,
            RefreshSession replacement,
            CancellationToken cancellationToken) => Task.FromResult(
                new RefreshRotationResult(RefreshRotationStatus.Invalid, null, null, null));

        public Task RevokeFamilyAsync(
            string tokenHash,
            DateTimeOffset now,
            CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
