using System.Globalization;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>The exact, read-only Accounting proof used for invoice-bound capability issuance.</summary>
public static class InvoiceFinancialOwnershipContract
{
    /// <summary>The sole readback contract version.</summary>
    public const int Version = 1;
    /// <summary>The dedicated Accounting readback permission.</summary>
    public const string ReadPermission = "legacy.accounting.invoice-financial-ownership.read";
    /// <summary>The immutable financial binding frame version carried in the capability.</summary>
    public const string BindingVersion = "invoice-creation-financial-v1";

    /// <summary>Accepts only the immutable version-one metadata and canonical UTC source version.</summary>
    public static bool IsCanonical(InvoiceFinancialOwnership? value)
    {
        if (value is null || value.ContractVersion != Version || value.QuotationId <= 0 || value.InvoiceId <= 0
            || !Guid.TryParseExact(value.OperationId, "D", out var operation) || operation == Guid.Empty
            || value.OperationId != operation.ToString("D")
            || value.OriginIssuer is not { Length: > 0 and <= 512 } || value.OriginIssuer != value.OriginIssuer.Trim()
            || value.EmployeeSubject is not { Length: > 0 and <= 256 } || value.EmployeeSubject != value.EmployeeSubject.Trim()
            || value.EmployeeSubject.StartsWith("service:", StringComparison.Ordinal)
            || value.RequesterSubject != QuotationInvoiceCapabilityContract.Requester
            || value.FinancialBinding is not { Length: 64 }
            || value.FinancialBinding.Any(character => character is not (>= '0' and <= '9' or >= 'A' and <= 'F'))
            || !DateTime.TryParseExact(value.OriginalQuotationVersion, "O", CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind, out var version)
            || version.Kind != DateTimeKind.Utc || version == DateTime.MinValue
            || version.ToString("O", CultureInfo.InvariantCulture) != value.OriginalQuotationVersion) return false;
        return true;
    }
}

/// <summary>Metadata independently read from Accounting's immutable admission and committed financial rows.</summary>
public sealed record InvoiceFinancialOwnership(
    int ContractVersion, string OperationId, int QuotationId, int InvoiceId,
    string OriginIssuer, string EmployeeSubject, string RequesterSubject,
    string OriginalQuotationVersion, string FinancialBinding);

/// <summary>Distinguishes unavailable readback from explicit absence of qualifying financial authority.</summary>
public enum InvoiceFinancialOwnershipStatus
{
    /// <summary>No trustworthy current readback is available.</summary>
    Unavailable,
    /// <summary>No qualifying immutable financial operation exists.</summary>
    Denied,
    /// <summary>The readback passed the exact structural contract.</summary>
    Verified,
}

/// <summary>A readback outcome; metadata is present only for a verified contract.</summary>
public sealed record InvoiceFinancialOwnershipResult(InvoiceFinancialOwnershipStatus Status, InvoiceFinancialOwnership? Ownership = null);

/// <summary>Reads a fixed Accounting operation without accepting caller-provided authority metadata.</summary>
public interface IInvoiceFinancialOwnershipClient
{
    /// <summary>Obtains an uncached, authenticated and bounded readback for one canonical operation.</summary>
    Task<InvoiceFinancialOwnershipResult> ReadAsync(Guid operationId, CancellationToken cancellationToken = default);
}

/// <summary>Signs the invoice-bound extension only after current authority and financial proof validation.</summary>
public interface IQuotationInvoiceAttachmentTokenIssuer
{
    /// <summary>Includes invoice, immutable financial binding and original quotation version in the scoped proof.</summary>
    IssuedAccessToken IssueQuotationInvoiceAttachment(string employeeSubject, InvoiceFinancialOwnership ownership,
        DateTimeOffset now, int lifetimeSeconds);
}
