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
    /// <summary>Optional server-owned canonical service name for the separate IAM profile.</summary>
    public string? IamServiceName { get; set; }
    /// <summary>Hashes a secret without retaining it.</summary>
    public static string HashSecret(string secret) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));
}

/// <summary>Authenticates configured services without account enumeration or refresh sessions.</summary>
public sealed class ServiceAuthenticationService(IOptions<ServiceClientOptions> options, IServiceAccessTokenIssuer issuer, TimeProvider timeProvider, IIamServiceAccessTokenIssuer? iamIssuer = null)
{
    private static readonly byte[] MissingClientHash = SHA256.HashData("invalid-service-client"u8);

    /// <summary>Validates a machine credential and returns a short-lived token.</summary>
    public Task<ServiceAuthenticationResult> LoginAsync(ServiceLoginRequest request)
    {
        if (!TryAuthenticate(request, out var credential))
        {
            return Task.FromResult(ServiceAuthenticationResult.Failed());
        }

        var permissions = credential!.Permissions
            .Where(permission => !string.IsNullOrWhiteSpace(permission))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (permissions.Any(permission => permission.Contains('*', StringComparison.Ordinal)))
        {
            return Task.FromResult(ServiceAuthenticationResult.Failed());
        }

        var registered = LegacyServicePermissionRegistry.ResolveAuthenticatedClientPermissions(request.ClientId, permissions);
        return Task.FromResult(ServiceAuthenticationResult.Success(issuer.IssueService(request.ClientId, registered, timeProvider.GetUtcNow())));
    }

    /// <summary>Authenticates an explicitly enrolled IAM caller without changing legacy service issuance.</summary>
    public Task<ServiceAuthenticationResult> LoginIamAsync(ServiceLoginRequest request)
    {
        if (!TryAuthenticate(request, out var credential) || iamIssuer is null || !iamIssuer.IsIamProfileConfigured
            || !IamServiceTokenProfile.IsCanonicalServiceName(credential!.IamServiceName)
            || credential.Permissions is null
            || credential.Permissions.Any(permission => string.IsNullOrWhiteSpace(permission) || permission.Contains('*', StringComparison.Ordinal))
            || !credential.Permissions.Contains(IamServiceTokenProfile.CheckPermission, StringComparer.Ordinal))
            return Task.FromResult(ServiceAuthenticationResult.Failed());
        var profile = new IamServiceTokenProfile(credential.IamServiceName!);
        return Task.FromResult(ServiceAuthenticationResult.Success(iamIssuer.IssueIamService(request.ClientId, profile, timeProvider.GetUtcNow())));
    }

    private bool TryAuthenticate(ServiceLoginRequest request, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out ServiceClientCredential? credential)
    {
        var presented = SHA256.HashData(Encoding.UTF8.GetBytes(request.ClientSecret));
        var exists = options.Value.Clients.TryGetValue(request.ClientId, out credential);
        var expected = exists && TryDecode(credential!.SecretSha256, out var configured) ? configured : MissingClientHash;
        return CryptographicOperations.FixedTimeEquals(presented, expected) && exists && credential is not null;
    }

    private static bool TryDecode(string value, out byte[] bytes)
    {
        try { bytes = Convert.FromHexString(value); return bytes.Length == 32; }
        catch (FormatException) { bytes = []; return false; }
    }
}
