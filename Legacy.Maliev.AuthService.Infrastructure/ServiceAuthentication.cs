using Legacy.Maliev.AuthService.Application;
using Microsoft.Extensions.Options;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Configured legacy machine identities.</summary>
public sealed class ServiceClientOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "ServiceClients";
    /// <summary>Credentials keyed by stable client identifier.</summary>
    public Dictionary<string, ServiceClientCredential> Clients { get; set; } = new(StringComparer.Ordinal);
}

/// <summary>Hashed secret and least-privilege permissions for one service.</summary>
public sealed class ServiceClientCredential
{
    /// <summary>Lowercase SHA-256 hex of the runtime client secret.</summary>
    [Required, RegularExpression("^[a-fA-F0-9]{64}$")] public string SecretSha256 { get; set; } = string.Empty;
    /// <summary>Permissions embedded in the issued token.</summary>
    public List<string> Permissions { get; set; } = [];
    /// <summary>Hashes a secret without retaining it.</summary>
    public static string HashSecret(string secret) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));
}

/// <summary>Authenticates configured services without account enumeration or refresh sessions.</summary>
public sealed class ServiceAuthenticationService(IOptions<ServiceClientOptions> options, IServiceAccessTokenIssuer issuer, TimeProvider timeProvider)
{
    private static readonly byte[] MissingClientHash = SHA256.HashData("invalid-service-client"u8);

    /// <summary>Validates a machine credential and returns a short-lived token.</summary>
    public Task<ServiceAuthenticationResult> LoginAsync(ServiceLoginRequest request)
    {
        var presented = SHA256.HashData(Encoding.UTF8.GetBytes(request.ClientSecret));
        var exists = options.Value.Clients.TryGetValue(request.ClientId, out var credential);
        var expected = exists && TryDecode(credential!.SecretSha256, out var configured) ? configured : MissingClientHash;
        if (!CryptographicOperations.FixedTimeEquals(presented, expected) || !exists)
        {
            return Task.FromResult(ServiceAuthenticationResult.Failed());
        }

        var permissions = credential!.Permissions
            .Where(permission => !string.IsNullOrWhiteSpace(permission))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        return Task.FromResult(ServiceAuthenticationResult.Success(issuer.IssueService(request.ClientId, permissions, timeProvider.GetUtcNow())));
    }

    private static bool TryDecode(string value, out byte[] bytes)
    {
        try { bytes = Convert.FromHexString(value); return bytes.Length == 32; }
        catch (FormatException) { bytes = []; return false; }
    }
}