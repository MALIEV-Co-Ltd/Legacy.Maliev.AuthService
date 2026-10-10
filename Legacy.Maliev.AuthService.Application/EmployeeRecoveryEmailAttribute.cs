using System.ComponentModel.DataAnnotations;
using System.Net.Mail;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>Preserves the historical employee recovery bare-address parsing predicate.</summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Parameter, AllowMultiple = false)]
public sealed class EmployeeRecoveryEmailAttribute : ValidationAttribute
{
    /// <summary>Creates a safe address-validation error without echoing the input.</summary>
    public EmployeeRecoveryEmailAttribute() : base("Enter a valid email address.") { }

    /// <summary>Requires parsing to preserve the supplied address exactly; Required handles null.</summary>
    public override bool IsValid(object? value) => value is null
        || value is string email && MailAddress.TryCreate(email, out var parsed)
        && string.Equals(parsed.Address, email, StringComparison.Ordinal);
}
