using System.Globalization;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Legacy.Maliev.AuthService.Application;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Legacy.Maliev.AuthService.Api.Security;

/// <summary>Bounds repeated human sign-in attempts by normalized identity without retaining the identifier.</summary>
public sealed class LoginAttemptRateLimiter : IDisposable
{
    /// <summary>Gets the maximum attempts allowed for one normalized identity in a window.</summary>
    public const int PermitLimit = 10;

    /// <summary>Gets the process-wide ceiling that bounds identifier-spray work in one window.</summary>
    public const int GlobalPermitLimit = 1000;

    private static readonly TimeSpan Window = TimeSpan.FromMinutes(1);
    private const int CleanupInterval = 256;
    private readonly byte[] partitionKeySecret = RandomNumberGenerator.GetBytes(32);
    private readonly ConcurrentDictionary<string, LoginWindow> partitions = new(StringComparer.Ordinal);
    private readonly FixedWindowRateLimiter globalLimiter;
    private readonly TimeProvider timeProvider;
    private int cleanupCounter;

    /// <summary>Initializes the process-local, privacy-preserving login limiter.</summary>
    public LoginAttemptRateLimiter(TimeProvider timeProvider)
    {
        this.timeProvider = timeProvider;
        globalLimiter = new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions
        {
            PermitLimit = GlobalPermitLimit,
            Window = Window,
            QueueLimit = 0,
            AutoReplenishment = true,
        });
    }

    /// <summary>Gets the current number of privacy-preserving identity partitions retained in memory.</summary>
    public int TrackedPartitionCount => partitions.Count;

    /// <summary>Attempts to acquire one sign-in permit for the request's normalized identity partition.</summary>
    internal LoginRateLimitDecision AttemptAcquire(LoginRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        using var globalLease = globalLimiter.AttemptAcquire();
        if (!globalLease.IsAcquired)
        {
            return LoginRateLimitDecision.Rejected(GetRetryAfter(globalLease));
        }

        var now = timeProvider.GetUtcNow();
        if (Interlocked.Increment(ref cleanupCounter) % CleanupInterval == 0)
        {
            RemoveExpiredPartitions(now);
        }

        var normalizedIdentifier = request.UserName.Trim().ToUpperInvariant();
        var compositeIdentity = string.Create(
            CultureInfo.InvariantCulture,
            $"{(int)request.IdentityKind}:{normalizedIdentifier}");
        var partitionKey = Convert.ToHexString(HMACSHA256.HashData(
            partitionKeySecret,
            Encoding.UTF8.GetBytes(compositeIdentity)));
        while (true)
        {
            var window = partitions.GetOrAdd(partitionKey, _ => new LoginWindow(now.Add(Window)));
            lock (window.SyncRoot)
            {
                if (!partitions.TryGetValue(partitionKey, out var current) || !ReferenceEquals(current, window))
                {
                    continue;
                }

                if (now >= window.ResetsAt)
                {
                    window.Count = 0;
                    window.ResetsAt = now.Add(Window);
                }

                if (window.Count >= PermitLimit)
                {
                    return LoginRateLimitDecision.Rejected(window.ResetsAt - now);
                }

                window.Count++;
                return LoginRateLimitDecision.Acquired;
            }
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        globalLimiter.Dispose();
        partitions.Clear();
        CryptographicOperations.ZeroMemory(partitionKeySecret);
    }

    private static TimeSpan GetRetryAfter(RateLimitLease lease) =>
        lease.TryGetMetadata(MetadataName.RetryAfter, out TimeSpan retryAfter)
            ? retryAfter
            : Window;

    private void RemoveExpiredPartitions(DateTimeOffset now)
    {
        foreach (var partition in partitions)
        {
            var window = partition.Value;
            lock (window.SyncRoot)
            {
                if (now >= window.ResetsAt)
                {
                    ((ICollection<KeyValuePair<string, LoginWindow>>)partitions).Remove(partition);
                }
            }
        }
    }

    private sealed class LoginWindow(DateTimeOffset resetsAt)
    {
        public object SyncRoot { get; } = new();

        public int Count { get; set; }

        public DateTimeOffset ResetsAt { get; set; } = resetsAt;
    }
}

internal readonly record struct LoginRateLimitDecision(bool IsAcquired, TimeSpan RetryAfter)
{
    public static LoginRateLimitDecision Acquired { get; } = new(true, TimeSpan.Zero);

    public static LoginRateLimitDecision Rejected(TimeSpan retryAfter) => new(false, retryAfter);
}

/// <summary>Applies identity-aware sign-in throttling after MVC has safely bound the login request.</summary>
public sealed class LoginRateLimitFilter(LoginAttemptRateLimiter limiter) : IAsyncActionFilter
{
    /// <inheritdoc />
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        if (!context.ActionArguments.TryGetValue("request", out var value) || value is not LoginRequest request)
        {
            await next();
            return;
        }

        var decision = limiter.AttemptAcquire(request);
        if (decision.IsAcquired)
        {
            await next();
            return;
        }

        var retryAfterSeconds = Math.Max(1, (int)Math.Ceiling(decision.RetryAfter.TotalSeconds));
        context.HttpContext.Response.Headers.RetryAfter = retryAfterSeconds.ToString(CultureInfo.InvariantCulture);
        context.Result = new StatusCodeResult(StatusCodes.Status429TooManyRequests);
    }
}
