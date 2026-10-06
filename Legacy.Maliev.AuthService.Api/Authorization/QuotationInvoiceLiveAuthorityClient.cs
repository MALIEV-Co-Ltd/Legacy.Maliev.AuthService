using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Maliev.Aspire.ServiceDefaults.LegacyAuth;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.AuthService.Api.Authorization;

/// <summary>Obtains an uncached employee decision using independently validated own workload identity.</summary>
public sealed class QuotationInvoiceLiveAuthorityClient(
    IConfiguration configuration, IHostEnvironment environment, IHttpClientFactory clientFactory,
    ILegacyServiceAccessTokenProvider tokenProvider, IOptions<JwtOptions> jwtOptions, IOptionsMonitor<JwtBearerOptions> bearerOptions, TimeProvider timeProvider) : IQuotationInvoiceLiveAuthorityClient
{
    /// <summary>Named capability-specific transport; not the general permission-policy client.</summary>
    public const string HttpClientName = "QuotationInvoiceLiveAuthority";

    /// <inheritdoc />
    public async Task<QuotationInvoiceLiveAuthorityResult> CheckAsync(string employeeId, int quotationId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var secret = configuration["ServiceAuthentication:ClientSecret"];
        var liveKey = configuration["IAM:LivePermissionChecks:Credential"];
        if (string.IsNullOrWhiteSpace(employeeId) || employeeId.Length > 512 || quotationId <= 0
            || configuration["ServiceAuthentication:ClientId"] != "legacy-auth"
            || string.IsNullOrWhiteSpace(secret) || secret.Length > 4096
            || string.IsNullOrWhiteSpace(liveKey) || liveKey.Length > 4096 || liveKey != liveKey.Trim() || liveKey.Any(char.IsControl)
            || !QuotationAuthorityTransportBoundary.TryOrigin(configuration["Services:Auth:BaseUrl"], environment, out _)
            || !QuotationAuthorityTransportBoundary.TryOrigin(configuration["Services:IAMService:BaseUrl"], environment, out var iamOrigin)) return QuotationInvoiceLiveAuthorityResult.Unavailable;
        try
        {
            var token = await tokenProvider.GetAccessTokenAsync(cancellationToken);
            if (string.IsNullOrWhiteSpace(token)) return QuotationInvoiceLiveAuthorityResult.Unavailable;
            if (!ValidateOwnToken(token))
            {
                tokenProvider.Invalidate(token);
                return QuotationInvoiceLiveAuthorityResult.Unavailable;
            }
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10), timeProvider);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(iamOrigin, "/iam/v1/auth/check-permission"))
            {
                Content = JsonContent.Create(new { PrincipalId = employeeId, PermissionId = "legacy.quotations.update", ResourcePath = $"/quotations/{quotationId.ToString(System.Globalization.CultureInfo.InvariantCulture)}", BypassCache = true }),
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Add("X-Maliev-IAM-Live-Check-Key", liveKey);
            using var response = await clientFactory.CreateClient(HttpClientName).SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linked.Token);
            if (!response.IsSuccessStatusCode) return QuotationInvoiceLiveAuthorityResult.Unavailable;
            var bytes = await QuotationAuthorityTransportBoundary.ReadBoundedAsync(response.Content, linked.Token);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) return QuotationInvoiceLiveAuthorityResult.Unavailable;
            var allowed = document.RootElement.EnumerateObject().Where(x => string.Equals(x.Name, "allowed", StringComparison.OrdinalIgnoreCase)).ToArray();
            return allowed.Length != 1 ? QuotationInvoiceLiveAuthorityResult.Unavailable : allowed[0].Value.ValueKind switch
            {
                JsonValueKind.True => QuotationInvoiceLiveAuthorityResult.Allowed,
                JsonValueKind.False => QuotationInvoiceLiveAuthorityResult.Denied,
                _ => QuotationInvoiceLiveAuthorityResult.Unavailable,
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException or JsonException or ArgumentException or InvalidOperationException or IOException)
        {
            return QuotationInvoiceLiveAuthorityResult.Unavailable;
        }
    }

    internal bool ValidateOwnToken(string token, string? requiredPermission = null)
    {
        try
        {
            if (token.Length > 16384) return false;
            var parts = token.Split('.');
            if (parts.Length != 3) return false;
            using var header = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(parts[0]), new JsonDocumentOptions { MaxDepth = 16 });
            if (header.RootElement.ValueKind != JsonValueKind.Object) return false;
            var algorithms = header.RootElement.EnumerateObject().Where(x => x.Name == "alg").ToArray();
            if (algorithms.Length != 1 || algorithms[0].Value.ValueKind != JsonValueKind.String || algorithms[0].Value.GetString() != "RS256"
                || header.RootElement.EnumerateObject().Count(x => x.Name == "kid") > 1 || header.RootElement.EnumerateObject().Count(x => x.Name == "typ") > 1) return false;
            using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(parts[1]), new JsonDocumentOptions { MaxDepth = 16 });
            if (payload.RootElement.ValueKind != JsonValueKind.Object) return false;
            var properties = payload.RootElement.EnumerateObject().ToArray();
            foreach (var name in new[] { "iss", "aud", "sub", "identity_kind", "iat", "exp", "name" })
                if (properties.Count(x => x.Name == name) != 1) return false;
            if (properties.Count(x => x.Name == "nbf") > 1) return false;
            if (properties.Any(x => x.Name is "sid" or "session_id" or "family_id" or "employee_id" or "employeeId" or "EmployeeID" or "security_stamp" or "role" or "roles" or "executor")) return false;
            var root = payload.RootElement;
            var options = jwtOptions.Value;
            if (root.GetProperty("iss").ValueKind != JsonValueKind.String || root.GetProperty("iss").GetString() != options.Issuer
                || root.GetProperty("aud").ValueKind != JsonValueKind.String || root.GetProperty("aud").GetString() != options.Audience
                || root.GetProperty("sub").ValueKind != JsonValueKind.String || root.GetProperty("sub").GetString() != "service:legacy-auth"
                || root.GetProperty("identity_kind").ValueKind != JsonValueKind.String || root.GetProperty("identity_kind").GetString() != "service"
                || root.GetProperty("name").ValueKind != JsonValueKind.String || root.GetProperty("name").GetString() != "legacy-auth"
                || root.GetProperty("iat").ValueKind != JsonValueKind.Number || !root.GetProperty("iat").TryGetInt64(out var issued)
                || root.GetProperty("exp").ValueKind != JsonValueKind.Number || !root.GetProperty("exp").TryGetInt64(out var expires)) return false;
            var now = timeProvider.GetUtcNow().ToUnixTimeSeconds();
            if (issued < 0 || issued > now || expires <= now || expires <= issued || expires - issued > 1800) return false;
            if (root.TryGetProperty("nbf", out var notBefore) && (notBefore.ValueKind != JsonValueKind.Number || !notBefore.TryGetInt64(out var nbf) || nbf > now)) return false;
            var parameters = bearerOptions.Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters.Clone();
            parameters.ValidateLifetime = false; // Exact TimeProvider lifetime checks above, without wall-clock skew.
            var principal = new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(token, parameters, out _);
            return requiredPermission is null || principal.FindAll("permissions").Count(claim => claim.Value == requiredPermission) == 1;
        }
        catch (Exception exception) when (exception is SecurityTokenException or JsonException or FormatException or ArgumentException or CryptographicException or InvalidOperationException)
        {
            return false;
        }
    }
}
