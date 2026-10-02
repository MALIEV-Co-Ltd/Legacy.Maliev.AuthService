namespace Legacy.Maliev.AuthService.Application;

/// <summary>Fresh, scoped quotation authority; availability is distinct from denial.</summary>
public enum QuotationInvoiceLiveAuthorityResult
{
    /// <summary>No trustworthy live decision is available.</summary>
    Unavailable,
    /// <summary>The live authority explicitly allowed the exact operation.</summary>
    Allowed,
    /// <summary>The live authority explicitly denied the exact operation.</summary>
    Denied,
}

/// <summary>Checks employee quotation-update authority without changing the request principal.</summary>
public interface IQuotationInvoiceLiveAuthorityClient
{
    /// <summary>Checks the literal employee and quotation through an uncached live boundary.</summary>
    Task<QuotationInvoiceLiveAuthorityResult> CheckAsync(string employeeId, int quotationId, CancellationToken cancellationToken = default);
}
