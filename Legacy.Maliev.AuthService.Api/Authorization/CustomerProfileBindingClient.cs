using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.AuthService.Application;
using Maliev.Aspire.ServiceDefaults.LegacyAuth;

namespace Legacy.Maliev.AuthService.Api.Authorization;

/// <summary>Reads selected customer profiles with separately verified Auth workload read authority.</summary>
public sealed class CustomerProfileBindingClient(
    IConfiguration configuration, IHostEnvironment environment, IHttpClientFactory clients,
    ILegacyServiceAccessTokenProvider tokens, QuotationInvoiceLiveAuthorityClient ownAuthority, TimeProvider clock)
    : ICustomerProfileBindingClient
{
    /// <summary>Isolated profile transport without redirects or retries.</summary>
    public const string HttpClientName = "CustomerProfileBinding";
    /// <summary>Existing Customer resource-read permission; never grants caller write authority.</summary>
    public const string ReadPermission = "legacy-customer.customers.read";

    /// <inheritdoc />
    public async Task<CustomerProfileBindingResult> ReadAsync(int databaseId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (configuration["ServiceAuthentication:ClientId"] != "legacy-auth"
            || !QuotationAuthorityTransportBoundary.TryOrigin(configuration["Services:Auth:BaseUrl"], environment, out _)
            || !QuotationAuthorityTransportBoundary.TryOrigin(configuration["Services:CustomerService:BaseUrl"], environment, out var origin))
            return new(CustomerProfileBindingStatus.Unavailable);
        try
        {
            var token = await tokens.GetAccessTokenAsync(cancellationToken);
            if (string.IsNullOrWhiteSpace(token)) return new(CustomerProfileBindingStatus.Unavailable);
            if (!ownAuthority.ValidateOwnToken(token, ReadPermission))
            {
                tokens.Invalidate(token);
                return new(CustomerProfileBindingStatus.Unavailable);
            }
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10), clock);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            using var request = new HttpRequestMessage(HttpMethod.Get,
                new Uri(origin, "/customers/" + databaseId.ToString(CultureInfo.InvariantCulture)));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };
            using var response = await clients.CreateClient(HttpClientName).SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, linked.Token);
            if (!ownAuthority.ValidateOwnToken(token, ReadPermission)) return new(CustomerProfileBindingStatus.Unavailable);
            if (response.StatusCode == HttpStatusCode.NotFound) return new(CustomerProfileBindingStatus.Missing);
            if (response.StatusCode != HttpStatusCode.OK) return new(CustomerProfileBindingStatus.Unavailable);
            var bytes = await QuotationAuthorityTransportBoundary.ReadBoundedAsync(response.Content, linked.Token);
            if (!ownAuthority.ValidateOwnToken(token, ReadPermission)) return new(CustomerProfileBindingStatus.Unavailable);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return new(CustomerProfileBindingStatus.Unavailable);
            var properties = root.EnumerateObject().ToArray();
            if (properties.Select(value => value.Name).Distinct(StringComparer.Ordinal).Count() != properties.Length
                || properties.Any(value => new[] { "Id", "Email", "Telephone", "Fax", "Mobile" }.Any(name =>
                    string.Equals(value.Name, name, StringComparison.OrdinalIgnoreCase) && value.Name != name))
                || !root.TryGetProperty("Id", out var id) || !id.TryGetInt32(out var actualId) || actualId != databaseId
                || !root.TryGetProperty("Email", out var email) || email.ValueKind != JsonValueKind.String
                || string.IsNullOrWhiteSpace(email.GetString()) || email.GetString()!.EnumerateRunes().Count() > 256
                || !ReadNullable(root, "Telephone", out var telephone)
                || !ReadNullable(root, "Fax", out var fax) || !ReadNullable(root, "Mobile", out var mobile))
                return new(CustomerProfileBindingStatus.Unavailable);
            return new(CustomerProfileBindingStatus.Verified, new(actualId, email.GetString()!, telephone, fax, mobile));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException or JsonException
            or ArgumentException or InvalidOperationException or IOException)
        {
            return new(CustomerProfileBindingStatus.Unavailable);
        }
    }

    private static bool ReadNullable(JsonElement root, string name, out string? value)
    {
        value = null;
        if (!root.TryGetProperty(name, out var element)) return true; // Producer omits null values.
        if (element.ValueKind is not (JsonValueKind.String or JsonValueKind.Null)) return false;
        value = element.GetString();
        return value is null || value.EnumerateRunes().Count() <= 256;
    }
}
