namespace Legacy.Maliev.AuthService.Application;

/// <summary>Permissions assigned directly by the legacy identity token boundary.</summary>
public static class LegacyAccessTokenPermissions
{
    /// <summary>Allows an authenticated employee to read the legacy material catalog.</summary>
    public const string CatalogMaterialsRead = "legacy-catalog.materials.read";
}
