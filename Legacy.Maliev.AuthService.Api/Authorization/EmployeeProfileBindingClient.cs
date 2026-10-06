using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Legacy.Maliev.AuthService.Application;
using Maliev.Aspire.ServiceDefaults.LegacyAuth;

namespace Legacy.Maliev.AuthService.Api.Authorization;

/// <summary>Reads selected employee profiles through the existing authenticated Employee route.</summary>
public sealed class EmployeeProfileBindingClient(
    IConfiguration configuration, IHostEnvironment environment, IHttpClientFactory clients,
    ILegacyServiceAccessTokenProvider tokens, QuotationInvoiceLiveAuthorityClient ownAuthority, TimeProvider clock)
    : IEmployeeProfileBindingClient
{
    /// <summary>Isolated profile transport without redirects or retries.</summary>
    public const string HttpClientName = "EmployeeProfileBinding";
    /// <summary>Existing Employee producer permission, never taken from the incoming caller.</summary>
    public const string ReadPermission = "legacy-employee.employees.read";

    /// <inheritdoc />
    public async Task<EmployeeProfileBindingResult> ReadAsync(int databaseId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (configuration["ServiceAuthentication:ClientId"] != "legacy-auth"
            || !QuotationAuthorityTransportBoundary.TryOrigin(configuration["Services:Auth:BaseUrl"], environment, out _)
            || !QuotationAuthorityTransportBoundary.TryOrigin(configuration["Services:EmployeeService:BaseUrl"], environment, out var origin))
            return new(EmployeeProfileBindingStatus.Unavailable);
        try
        {
            var token = await tokens.GetAccessTokenAsync(cancellationToken);
            if (string.IsNullOrWhiteSpace(token)) return new(EmployeeProfileBindingStatus.Unavailable);
            if (!ownAuthority.ValidateOwnToken(token, ReadPermission))
            {
                tokens.Invalidate(token);
                return new(EmployeeProfileBindingStatus.Unavailable);
            }
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10), clock);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            using var request = new HttpRequestMessage(HttpMethod.Get,
                new Uri(origin, "/employees/" + databaseId.ToString(CultureInfo.InvariantCulture)));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };
            using var response = await clients.CreateClient(HttpClientName).SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, linked.Token);
            if (!ownAuthority.ValidateOwnToken(token, ReadPermission)) return new(EmployeeProfileBindingStatus.Unavailable);
            if (response.StatusCode == HttpStatusCode.NotFound) return new(EmployeeProfileBindingStatus.Missing);
            if (response.StatusCode != HttpStatusCode.OK) return new(EmployeeProfileBindingStatus.Unavailable);
            var bytes = await QuotationAuthorityTransportBoundary.ReadBoundedAsync(response.Content, linked.Token);
            if (!ownAuthority.ValidateOwnToken(token, ReadPermission)) return new(EmployeeProfileBindingStatus.Unavailable);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return new(EmployeeProfileBindingStatus.Unavailable);
            var properties = root.EnumerateObject().ToArray();
            if (properties.Select(value => value.Name).Distinct(StringComparer.Ordinal).Count() != properties.Length
                || !root.TryGetProperty("Id", out var id) || !id.TryGetInt32(out var actualId) || actualId != databaseId
                || !root.TryGetProperty("Email", out var email) || email.ValueKind != JsonValueKind.String
                || string.IsNullOrWhiteSpace(email.GetString()) || email.GetString()!.Length > 320)
                return new(EmployeeProfileBindingStatus.Unavailable);
            string? phoneNumber = null;
            if (root.TryGetProperty("PhoneNumber", out var phone))
            {
                if (phone.ValueKind is not (JsonValueKind.String or JsonValueKind.Null)) return new(EmployeeProfileBindingStatus.Unavailable);
                phoneNumber = phone.GetString();
                if (phoneNumber?.Length > 256) return new(EmployeeProfileBindingStatus.Unavailable);
            }
            return new(EmployeeProfileBindingStatus.Verified, new(actualId, email.GetString()!, phoneNumber));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException or JsonException
            or ArgumentException or InvalidOperationException or IOException)
        {
            return new(EmployeeProfileBindingStatus.Unavailable);
        }
    }
}
