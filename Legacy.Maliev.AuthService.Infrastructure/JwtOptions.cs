using System.ComponentModel.DataAnnotations;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Asymmetric JWT settings supplied through the consolidated legacy secret.</summary>
public sealed class JwtOptions
{
    /// <summary>Gets the configuration section name.</summary>
    public const string SectionName = "Jwt";

    /// <summary>Gets or sets the issuer.</summary>
    [Required]
    public required string Issuer { get; set; }

    /// <summary>Gets or sets the audience.</summary>
    [Required]
    public required string Audience { get; set; }

    /// <summary>Gets or sets the PEM private key.</summary>
    [Required]
    public required string PrivateKeyPem { get; set; }

    /// <summary>Gets or sets a stable public key identifier.</summary>
    [Required]
    public required string KeyId { get; set; }

    /// <summary>Gets or sets access token lifetime in seconds.</summary>
    [Range(300, 1800)]
    public int AccessTokenLifetimeSeconds { get; set; } = 900;
}