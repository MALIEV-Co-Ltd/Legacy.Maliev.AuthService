namespace Legacy.Maliev.AuthService.Domain;

/// <summary>A validated account projected from an unchanged legacy identity schema.</summary>
public sealed record LegacyIdentity(
    string Id,
    string UserName,
    string? Email,
    IdentityKind Kind,
    int? DatabaseId,
    string? SecurityStamp);