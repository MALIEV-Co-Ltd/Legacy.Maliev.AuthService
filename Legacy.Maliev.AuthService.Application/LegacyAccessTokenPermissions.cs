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
    /// <summary>Allows an authenticated employee to read a legacy customer profile.</summary>
    public const string CustomersRead = "legacy-customer.customers.read";
    /// <summary>Allows an authenticated employee to create a legacy customer identity.</summary>
    public const string CustomerIdentitiesCreate = "legacy-auth.customer-identities.create";
    /// <summary>Allows an authenticated employee to create a legacy employee identity.</summary>
    public const string EmployeeIdentitiesCreate = "legacy-auth.employee-identities.create";
    /// <summary>Allows an authenticated employee to list legacy employee profiles.</summary>
    public const string EmployeesList = "legacy-employee.employees.list";
    /// <summary>Allows an authenticated employee to read a legacy employee profile.</summary>
    public const string EmployeesRead = "legacy-employee.employees.read";
    /// <summary>Allows an authenticated employee to read legacy orders.</summary>
    public const string OrdersRead = "legacy.orders.read";
    /// <summary>Allows an authenticated employee to create a legacy order.</summary>
    public const string OrdersCreate = "legacy.orders.create";
    /// <summary>Allows an authenticated employee to read legacy order catalog data.</summary>
    public const string OrderCatalogRead = "legacy.order-catalog.read";
    /// <summary>Allows an authenticated employee to update a legacy order.</summary>
    public const string OrdersUpdate = "legacy.orders.update";
    /// <summary>Allows an authenticated employee to read legacy order-file metadata.</summary>
    public const string OrderFilesRead = "legacy.order-files.read";
    /// <summary>Allows an authenticated employee to create legacy order-file metadata.</summary>
    public const string OrderFilesWrite = "legacy.order-files.write";
    /// <summary>Allows an authenticated employee to delete legacy order-file metadata.</summary>
    public const string OrderFilesDelete = "legacy.order-files.delete";
    /// <summary>Allows an authenticated employee to read legacy order status history and transitions.</summary>
    public const string OrderStatusRead = "legacy.order-status.read";
    /// <summary>Allows an authenticated employee to transition a legacy order status.</summary>
    public const string OrderStatusWrite = "legacy.order-status.write";
    /// <summary>Allows an authenticated employee to upload a scanned legacy order file.</summary>
    public const string FileUploadsCreate = "legacy-file.uploads.create";
    /// <summary>Allows an authenticated employee to request a signed URL for a clean legacy order file.</summary>
    public const string FileUploadsRead = "legacy-file.uploads.read";
    /// <summary>Allows an authenticated employee to delete a legacy order file from storage.</summary>
    public const string FileUploadsDelete = "legacy-file.uploads.delete";
}
