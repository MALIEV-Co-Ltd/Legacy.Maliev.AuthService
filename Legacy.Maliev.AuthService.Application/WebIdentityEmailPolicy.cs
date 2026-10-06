namespace Legacy.Maliev.AuthService.Application;

/// <summary>Validates a new Web email-shaped username using the source default Identity user policy.</summary>
public static class WebIdentityEmailPolicy
{
    /// <summary>Checks the email after the Web writer's existing trimming, without mutating any identity.</summary>
    public static bool Accepts(string? email)
    {
        var value = email?.Trim();
        return AdministrativeIdentityPolicy.Accepts(value, value);
    }
}
