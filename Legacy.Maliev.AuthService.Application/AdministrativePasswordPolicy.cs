namespace Legacy.Maliev.AuthService.Application;

/// <summary>Retains the original customer and employee administration creation policy.</summary>
public static class AdministrativePasswordPolicy
{
    /// <summary>Requires six distinct UTF-16 characters within the existing request length bounds.</summary>
    public static bool Accepts(string? password) => password is { Length: >= 6 and <= 1024 }
        && password.Distinct().Take(6).Count() == 6;
}
