using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Persists only nonce hashes and atomically consumes a matching nonce.</summary>
public sealed class GoogleIdentityNonceService(
    RefreshSessionDbContext dbContext,
    IConfiguration configuration,
    TimeProvider timeProvider) : IGoogleIdentityNonceService
{
    private readonly TimeSpan lifetime = TimeSpan.FromMinutes(Math.Clamp(
        configuration.GetValue("GoogleIdentity:NonceLifetimeMinutes", 10), 1, 15));

    /// <inheritdoc />
    public async Task<(string Nonce, DateTimeOffset ExpiresAtUtc)> IssueAsync(
        string serviceName,
        string application,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        await dbContext.GoogleIdentityNonces
            .Where(existing => existing.ExpiresAt <= now)
            .ExecuteDeleteAsync(cancellationToken);

        var nonce = ToBase64Url(RandomNumberGenerator.GetBytes(32));
        var record = new GoogleIdentityNonce
        {
            Id = Guid.NewGuid(),
            NonceHash = Hash(nonce),
            ServiceName = Normalize(serviceName),
            Application = Normalize(application),
            CreatedAt = now,
            ExpiresAt = now.Add(lifetime),
        };
        dbContext.GoogleIdentityNonces.Add(record);
        await dbContext.SaveChangesAsync(cancellationToken);
        return (nonce, record.ExpiresAt);
    }

    /// <inheritdoc />
    public async Task<bool> ConsumeAsync(
        string nonce,
        string serviceName,
        string application,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(nonce))
        {
            return false;
        }

        var now = timeProvider.GetUtcNow();
        var deleted = await dbContext.GoogleIdentityNonces
            .Where(existing =>
                existing.NonceHash == Hash(nonce) &&
                existing.ServiceName == Normalize(serviceName) &&
                existing.Application == Normalize(application) &&
                existing.ExpiresAt > now)
            .ExecuteDeleteAsync(cancellationToken);
        return deleted == 1;
    }

    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string Normalize(string value) => value.Trim().ToLowerInvariant();

    private static string ToBase64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
