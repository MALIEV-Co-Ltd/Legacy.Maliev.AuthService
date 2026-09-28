using System.ComponentModel.DataAnnotations;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>The narrow invoice-create employee delegation contract.</summary>
public static class InvoiceDelegationContract
{
    /// <summary>The only service identity allowed to request this delegation.</summary>
    public const string IntranetServiceSubject = "service:legacy-intranet";
    /// <summary>The intended verifier and operation, distinct from ordinary access-token audiences.</summary>
    public const string Audience = "legacy-accounting:invoice-create";
    /// <summary>The only operation authorized by the delegation.</summary>
    public const string Scope = LegacyAccessTokenPermissions.AccountingCreate;
    /// <summary>The upper bound on a newly issued delegation lifetime.</summary>
    public const int LifetimeSeconds = 120;
}

/// <summary>Server-to-server request; the employee token must never come from browser JSON.</summary>
public sealed record InvoiceDelegationRequest(
    [Required, StringLength(16384, MinimumLength = 1)] string EmployeeAccessToken,
    [Range(1, int.MaxValue)] int QuotationId,
    [Required, StringLength(36, MinimumLength = 36)] string OperationId);

/// <summary>A short-lived Accounting-specific JWT, without a refresh token.</summary>
public sealed record InvoiceDelegationTokenResponse(string AccessToken, string TokenType, int ExpiresIn);
