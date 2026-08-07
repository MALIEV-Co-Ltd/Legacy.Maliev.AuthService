using Microsoft.Extensions.Options;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Fails closed when a configured machine credential cannot be verified safely.</summary>
public sealed class ServiceClientOptionsValidator : IValidateOptions<ServiceClientOptions>
{
    private static readonly Regex SecretHashPattern = new("^[a-fA-F0-9]{64}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, ServiceClientOptions options)
    {
        if (options.Clients is null)
        {
            return ValidateOptionsResult.Fail("ServiceClients:Clients must not be null.");
        }

        var failures = new List<string>();
        foreach (var (clientId, credential) in options.Clients)
        {
            if (string.IsNullOrWhiteSpace(clientId))
            {
                failures.Add("ServiceClients contains an empty client identifier.");
                continue;
            }

            if (credential is null)
            {
                failures.Add($"ServiceClients client '{clientId}' has no credential configuration.");
                continue;
            }

            if (!SecretHashPattern.IsMatch(credential.SecretSha256 ?? string.Empty))
            {
                failures.Add($"ServiceClients client '{clientId}' must provide a 64-character hexadecimal SecretSha256.");
            }

            if (credential.Permissions is null || credential.Permissions.Any(permission =>
                    string.IsNullOrWhiteSpace(permission) || permission.Contains('*', StringComparison.Ordinal)))
            {
                failures.Add($"ServiceClients client '{clientId}' contains an empty or wildcard permission.");
            }
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
