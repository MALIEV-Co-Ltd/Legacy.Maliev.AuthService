using System.Net;
using Legacy.Maliev.AuthService.Api.Security;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class LoginRateLimitContractTests
{
    [Fact]
    public async Task IdentifierSpray_IsGloballyBoundedWithoutRetainingUnboundedPartitions()
    {
        using var limiter = new LoginAttemptRateLimiter();
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
        using var limiter = new LoginAttemptRateLimiter();
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
        using var limiter = new LoginAttemptRateLimiter();
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
        using var limiter = new LoginAttemptRateLimiter();
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
        using var limiter = new LoginAttemptRateLimiter();
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
}
