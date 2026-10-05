namespace Legacy.Maliev.AuthService.Application;

/// <summary>Registers narrow capabilities for credential-verified legacy machine clients.</summary>
public static class LegacyServicePermissionRegistry
{
    /// <summary>Preserves configured grants and adds the registered Web currency-read capability.</summary>
    /// <param name="clientId">Client whose configured credential has already been verified.</param>
    /// <param name="configuredPermissions">Validated nonwildcard configured permissions.</param>
    /// <returns>Explicit grants for the unchanged normal service-token issuer.</returns>
    public static IReadOnlyList<string> ResolveAuthenticatedClientPermissions(
        string clientId,
        IReadOnlyList<string> configuredPermissions)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        ArgumentNullException.ThrowIfNull(configuredPermissions);
        if (!string.Equals(clientId, "legacy-web", StringComparison.Ordinal))
        {
            return configuredPermissions;
        }

        return configuredPermissions
            .Append(LegacyAccessTokenPermissions.CatalogCurrenciesRead)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }
}
