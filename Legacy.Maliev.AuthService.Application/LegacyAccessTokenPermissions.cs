namespace Legacy.Maliev.AuthService.Application;

/// <summary>Permissions assigned directly by the legacy identity token boundary.</summary>
public static class LegacyAccessTokenPermissions
{
    /// <summary>Allows an authenticated employee to read the legacy material catalog.</summary>
    public const string CatalogMaterialsRead = "legacy-catalog.materials.read";
    /// <summary>Allows an authenticated employee to create a legacy catalog material.</summary>
    public const string CatalogMaterialsCreate = "legacy-catalog.materials.create";
    /// <summary>Allows an authenticated employee to update a legacy catalog material.</summary>
    public const string CatalogMaterialsUpdate = "legacy-catalog.materials.update";
    /// <summary>Allows an authenticated employee to list and search legacy customer profiles.</summary>
    public const string CustomersList = "legacy-customer.customers.list";
    /// <summary>Allows an authenticated employee to create a legacy customer profile.</summary>
    public const string CustomersCreate = "legacy-customer.customers.create";
}
