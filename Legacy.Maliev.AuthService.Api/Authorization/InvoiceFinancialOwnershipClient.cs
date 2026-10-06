using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Legacy.Maliev.AuthService.Application;
using Maliev.Aspire.ServiceDefaults.LegacyAuth;

namespace Legacy.Maliev.AuthService.Api.Authorization;

/// <summary>Reads only fixed, authenticated Accounting financial-operation metadata without retries or redirects.</summary>
public sealed class InvoiceFinancialOwnershipClient(
    IConfiguration configuration, IHostEnvironment environment, IHttpClientFactory clients,
    ILegacyServiceAccessTokenProvider tokens, QuotationInvoiceLiveAuthorityClient ownAuthority, TimeProvider clock)
    : IInvoiceFinancialOwnershipClient
{
    /// <summary>The isolated financial readback transport.</summary>
    public const string HttpClientName = "InvoiceFinancialOwnership";

    /// <inheritdoc />
    public async Task<InvoiceFinancialOwnershipResult> ReadAsync(Guid operationId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (operationId == Guid.Empty || configuration["ServiceAuthentication:ClientId"] != "legacy-auth"
            || !QuotationAuthorityTransportBoundary.TryOrigin(configuration["Services:Auth:BaseUrl"], environment, out _)
            || !QuotationAuthorityTransportBoundary.TryOrigin(configuration["Services:AccountingService:BaseUrl"], environment, out var origin))
            return new(InvoiceFinancialOwnershipStatus.Unavailable);
        try
        {
            var token = await tokens.GetAccessTokenAsync(cancellationToken);
            if (string.IsNullOrWhiteSpace(token)) return new(InvoiceFinancialOwnershipStatus.Unavailable);
            if (!ownAuthority.ValidateOwnToken(token, InvoiceFinancialOwnershipContract.ReadPermission))
            {
                tokens.Invalidate(token);
                return new(InvoiceFinancialOwnershipStatus.Unavailable);
            }
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10), clock);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            using var request = new HttpRequestMessage(HttpMethod.Get,
                new Uri(origin, "/internal/invoice-creation/operations/" + operationId.ToString("D") + "/financial-ownership"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };
            using var response = await clients.CreateClient(HttpClientName).SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, linked.Token);
            if (response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Conflict)
                return new(InvoiceFinancialOwnershipStatus.Denied);
            if (response.StatusCode != HttpStatusCode.OK) return new(InvoiceFinancialOwnershipStatus.Unavailable);
            var bytes = await QuotationAuthorityTransportBoundary.ReadBoundedAsync(response.Content, linked.Token);
            if (!ownAuthority.ValidateOwnToken(token, InvoiceFinancialOwnershipContract.ReadPermission))
                return new(InvoiceFinancialOwnershipStatus.Unavailable);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return new(InvoiceFinancialOwnershipStatus.Unavailable);
            string[] names = ["ContractVersion", "OperationId", "QuotationId", "InvoiceId", "OriginIssuer",
                "EmployeeSubject", "RequesterSubject", "OriginalQuotationVersion", "FinancialBinding"];
            var properties = root.EnumerateObject().ToArray();
            if (properties.Length != names.Length || names.Any(name => properties.Count(value => value.Name == name) != 1))
                return new(InvoiceFinancialOwnershipStatus.Unavailable);
            foreach (var name in names.Where(value => value is not ("ContractVersion" or "QuotationId" or "InvoiceId")))
                if (root.GetProperty(name).ValueKind != JsonValueKind.String) return new(InvoiceFinancialOwnershipStatus.Unavailable);
            foreach (var name in new[] { "ContractVersion", "QuotationId", "InvoiceId" })
                if (root.GetProperty(name).ValueKind != JsonValueKind.Number || !root.GetProperty(name).TryGetInt32(out _))
                    return new(InvoiceFinancialOwnershipStatus.Unavailable);
            var ownership = new InvoiceFinancialOwnership(root.GetProperty("ContractVersion").GetInt32(),
                root.GetProperty("OperationId").GetString()!, root.GetProperty("QuotationId").GetInt32(), root.GetProperty("InvoiceId").GetInt32(),
                root.GetProperty("OriginIssuer").GetString()!, root.GetProperty("EmployeeSubject").GetString()!,
                root.GetProperty("RequesterSubject").GetString()!, root.GetProperty("OriginalQuotationVersion").GetString()!,
                root.GetProperty("FinancialBinding").GetString()!);
            return InvoiceFinancialOwnershipContract.IsCanonical(ownership) && ownership.OperationId == operationId.ToString("D")
                ? new(InvoiceFinancialOwnershipStatus.Verified, ownership) : new(InvoiceFinancialOwnershipStatus.Unavailable);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException or JsonException
            or ArgumentException or InvalidOperationException or IOException)
        {
            return new(InvoiceFinancialOwnershipStatus.Unavailable);
        }
    }
}
