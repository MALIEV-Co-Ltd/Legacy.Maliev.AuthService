using System.ComponentModel.DataAnnotations;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>Separate authority for Accounting to complete one employee-authorized quotation.</summary>
public static class QuotationInvoiceCapabilityContract
{
    /// <summary>The sole requesting service.</summary>
    public const string Requester = "service:legacy-intranet";
    /// <summary>The sole executing service.</summary>
    public const string Executor = "service:legacy-accounting";
    /// <summary>The exact issuance grant; wildcard grants do not qualify.</summary>
    public const string IssuePermission = "legacy-auth.quotation-invoice-completion.issue";
    /// <summary>The distinct verifier audience.</summary>
    public const string Audience = "legacy-quotation:invoice-complete";
    /// <summary>The single authorized operation.</summary>
    public const string Scope = "legacy.quotation.invoice-complete";
    /// <summary>The maximum lifetime, additionally bounded by current employee authority.</summary>
    public const int MaximumLifetimeSeconds = 120;
}

/// <summary>Server-held employee credential and immutable quotation operation.</summary>
public sealed record QuotationInvoiceCapabilityRequest(
    [Required, StringLength(16384, MinimumLength = 1)] string EmployeeAccessToken,
    [Range(1, int.MaxValue)] int QuotationId,
    [Required, StringLength(36, MinimumLength = 36)] string OperationId,
    [Range(1, int.MaxValue)] int? InvoiceId = null);

/// <summary>A separate short-lived capability; no refresh credential is issued.</summary>
public sealed record QuotationInvoiceCapabilityResponse(string AccessToken, string TokenType, int ExpiresIn);

/// <summary>Opaque issuance outcomes distinguish invalid authority from infrastructure failure.</summary>
public enum QuotationInvoiceCapabilityStatus
{
    /// <summary>The supplied operation or bounded credential violates the wire contract.</summary>
    InvalidRequest,
    /// <summary>Employee authority is invalid or no longer current.</summary>
    Unauthorized,
    /// <summary>The requester or employee lacks the required operation permission.</summary>
    Forbidden,
    /// <summary>No fresh trustworthy live decision is available.</summary>
    Unavailable,
    /// <summary>A current narrow capability was issued.</summary>
    Issued,
}

/// <summary>The issuance result, without identity details on failure.</summary>
public sealed record QuotationInvoiceCapabilityResult(QuotationInvoiceCapabilityStatus Status, QuotationInvoiceCapabilityResponse? Token = null);

/// <summary>Signs only the separately verified quotation completion authority.</summary>
public interface IQuotationInvoiceCapabilityTokenIssuer
{
    /// <summary>Issues a separate bounded capability after current authority validation.</summary>
    IssuedAccessToken IssueQuotationInvoiceCapability(string employeeSubject, int quotationId, Guid operationId, DateTimeOffset now, int lifetimeSeconds);
}
