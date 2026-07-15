namespace Legacy.Maliev.AuthService.Api.Authorization;

/// <summary>Permissions for the public website BFF's customer identity lifecycle.</summary>
public static class CustomerSelfServicePermissions
{
    /// <summary>Register, confirm, and recover a customer identity through the trusted BFF.</summary>
    public const string Use = "legacy-auth.customer-self-service";
}