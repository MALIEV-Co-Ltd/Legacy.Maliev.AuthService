namespace Legacy.Maliev.AuthService.Domain;

/// <summary>Identifies which unchanged legacy identity database owns an account.</summary>
public enum IdentityKind
{
    /// <summary>Public website customer identity.</summary>
    Customer,

    /// <summary>Internal intranet employee identity.</summary>
    Employee,
}