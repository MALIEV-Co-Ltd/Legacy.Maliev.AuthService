using System.ComponentModel.DataAnnotations;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>The default Identity 8 user-name alphabet and unique-email input policy for administrative writes.</summary>
public static class AdministrativeIdentityPolicy
{
    private const string AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

    /// <summary>Validates the new administrative user fields without normalizing or mutating them.</summary>
    public static bool Accepts(string? userName, string? email) =>
        !string.IsNullOrWhiteSpace(userName) && userName.All(AllowedUserNameCharacters.Contains) &&
        !string.IsNullOrWhiteSpace(email) && new EmailAddressAttribute().IsValid(email);
}

/// <summary>A new administrative identity write was rejected without changing the identity.</summary>
public sealed class AdministrativeIdentityValidationException : Exception
{
    /// <summary>Creates a generic rejection without retaining supplied identity fields.</summary>
    public AdministrativeIdentityValidationException() : base("Invalid identity fields") { }
}

/// <summary>The supplied identity version no longer identifies the current row.</summary>
public sealed class AdministrativeIdentityConflictException : Exception
{
    /// <summary>Creates a generic conflict without retaining identity fields or version tokens.</summary>
    public AdministrativeIdentityConflictException() : base("Identity version changed") { }
}

/// <summary>A conditional identity write has an unavailable or uncertain outcome.</summary>
public sealed class AdministrativeIdentityUnavailableException : Exception
{
    /// <summary>Creates a generic unavailable result without exposing the underlying database failure.</summary>
    public AdministrativeIdentityUnavailableException() : base("Identity update unavailable") { }
}
