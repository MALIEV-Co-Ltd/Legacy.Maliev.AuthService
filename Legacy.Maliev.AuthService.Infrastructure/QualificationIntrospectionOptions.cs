using System.ComponentModel.DataAnnotations;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Default-off, bounded qualification bridge admission.</summary>
public sealed class QualificationIntrospectionOptions
{
    /// <summary>Gets or sets explicit bridge activation; provisioning is separate.</summary>
    public bool Enabled { get; set; }
    /// <summary>Gets or sets permits in the fixed sixty-second, zero-queue window.</summary>
    [Range(1, 30)]
    public int PermitLimit { get; set; } = 30;
}
