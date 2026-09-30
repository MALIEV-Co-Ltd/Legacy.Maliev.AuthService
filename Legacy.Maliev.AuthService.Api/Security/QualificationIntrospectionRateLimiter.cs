using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.Extensions.Options;

namespace Legacy.Maliev.AuthService.Api.Security;

/// <summary>One authenticated workload partition, fixed sixty-second window and no queue.</summary>
public sealed class QualificationIntrospectionRateLimiter(TimeProvider timeProvider, IOptionsMonitor<QualificationIntrospectionOptions> options)
{
    private readonly object sync = new();
    private DateTimeOffset resetsAt;
    private int count;

    /// <summary>Acquires immediately only for the already admitted immutable workload subject.</summary>
    public bool AttemptAcquire(string validatedSubject)
    {
        if (validatedSubject != QualificationIntrospectionContract.Caller) return false;
        var limit = options.CurrentValue.PermitLimit;
        lock (sync)
        {
            var now = timeProvider.GetUtcNow();
            if (now >= resetsAt) { count = 0; resetsAt = now.AddSeconds(60); }
            if (count >= limit) return false;
            count++;
            return true;
        }
    }
}
