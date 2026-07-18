namespace Legacy.Maliev.AuthService.Api.Authorization;

/// <summary>Permissions for the Intranet BFF employee identity lifecycle.</summary>
public static class EmployeeSelfServicePermissions
{
    /// <summary>Confirm and recover an employee identity through the trusted Intranet BFF.</summary>
    public const string Use = "legacy-auth.employee-self-service";
}
