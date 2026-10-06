using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Checks current employee authority before and after the uncached live quotation check.</summary>
public sealed class QuotationInvoiceCapabilityService(
    IOptions<JwtOptions> options,
    IQuotationInvoiceCapabilityTokenIssuer issuer,
    TimeProvider clock,
    RefreshSessionDbContext sessions,
    ILegacyIdentityReader identities,
    IQuotationInvoiceLiveAuthorityClient live,
    IInvoiceFinancialOwnershipClient financial,
    IQuotationInvoiceAttachmentTokenIssuer attachmentIssuer)
{
    /// <summary>Issues no capability from stale sessions, ambiguous claims or unavailable live authority.</summary>
    public async Task<QuotationInvoiceCapabilityResult> IssueAsync(ClaimsPrincipal caller, string? callerToken,
        QuotationInvoiceCapabilityRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request is null || request.EmployeeAccessToken is not { Length: > 0 and <= 16384 }
            || request.QuotationId <= 0 || request.InvoiceId is <= 0 || !Guid.TryParseExact(request.OperationId, "D", out var operationId)
            || operationId == Guid.Empty || request.OperationId != operationId.ToString("D"))
            return new(QuotationInvoiceCapabilityStatus.InvalidRequest);
        if (!HasUnambiguousPayload(callerToken) || Single(caller, "sub") != QuotationInvoiceCapabilityContract.Requester
            || Single(caller, "identity_kind") != "service" || caller.HasClaim(x => x.Type == "executor")
            || !caller.HasClaim("permissions", QuotationInvoiceCapabilityContract.IssuePermission))
            return new(QuotationInvoiceCapabilityStatus.Forbidden);

        if (!HasUnambiguousPayload(request.EmployeeAccessToken)) return new(QuotationInvoiceCapabilityStatus.Unauthorized);
        using var rsa = RSA.Create();
        rsa.ImportFromPem(options.Value.PrivateKeyPem);
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false, MaximumTokenSizeInBytes = 16384 };
        ClaimsPrincipal employee;
        JwtSecurityToken jwt;
        try
        {
            employee = handler.ValidateToken(request.EmployeeAccessToken,
                LegacyJwtBearerConfiguration.CreateValidationParameters(options.Value,
                    new RsaSecurityKey(rsa) { KeyId = options.Value.KeyId }), out var validated);
            jwt = (JwtSecurityToken)validated;
        }
        catch (Exception exception) when (exception is SecurityTokenException or ArgumentException or InvalidCastException)
        {
            return new(QuotationInvoiceCapabilityStatus.Unauthorized);
        }

        var subject = Single(employee, "sub");
        var sid = Single(employee, "sid");
        var now = clock.GetUtcNow();
        if (string.IsNullOrWhiteSpace(subject) || subject.Length > 256 || subject.StartsWith("service:", StringComparison.Ordinal)
            || Single(employee, "identity_kind") != "employee" || employee.HasClaim(x => x.Type == "executor")
            || !Guid.TryParseExact(sid, "D", out var sessionId) || sessionId == Guid.Empty || sid != sessionId.ToString("D")
            || employee.FindAll("user_id").Concat(employee.FindAll(ClaimTypes.NameIdentifier)).Any(x => x.Value != subject)
            || jwt.Audiences.Count() != 1 || jwt.Audiences.Single() != options.Value.Audience
            || !long.TryParse(Single(employee, "iat"), NumberStyles.None, CultureInfo.InvariantCulture, out var iat)
            || iat > now.ToUnixTimeSeconds()
            || iat < now.AddSeconds(-options.Value.AccessTokenLifetimeSeconds - 30).ToUnixTimeSeconds()
            || !long.TryParse(Single(employee, "exp"), NumberStyles.None, CultureInfo.InvariantCulture, out var exp)
            || !long.TryParse(Single(employee, "nbf"), NumberStyles.None, CultureInfo.InvariantCulture, out var nbf)
            || nbf > now.ToUnixTimeSeconds()
            || exp <= now.ToUnixTimeSeconds()) return new(QuotationInvoiceCapabilityStatus.Unauthorized);

        if (!employee.HasClaim("permissions", LegacyAccessTokenPermissions.AccountingCreate)
            || !employee.HasClaim("permissions", LegacyAccessTokenPermissions.QuotationsUpdate))
            return new(QuotationInvoiceCapabilityStatus.Forbidden);
        if (await CurrentSessionAsync(subject, sessionId, cancellationToken) is null)
            return new(QuotationInvoiceCapabilityStatus.Unauthorized);

        InvoiceFinancialOwnership? ownership = null;
        if (request.InvoiceId is { } invoiceId)
        {
            var readback = await financial.ReadAsync(operationId, cancellationToken);
            if (readback.Status != InvoiceFinancialOwnershipStatus.Verified)
                return new(readback.Status == InvoiceFinancialOwnershipStatus.Denied
                    ? QuotationInvoiceCapabilityStatus.Forbidden : QuotationInvoiceCapabilityStatus.Unavailable);
            ownership = readback.Ownership;
            if (ownership is null || !InvoiceFinancialOwnershipContract.IsCanonical(ownership)
                || ownership.OriginIssuer != options.Value.Issuer || ownership.EmployeeSubject != subject
                || ownership.RequesterSubject != QuotationInvoiceCapabilityContract.Requester
                || ownership.QuotationId != request.QuotationId || ownership.InvoiceId != invoiceId
                || ownership.OperationId != operationId.ToString("D"))
                return new(QuotationInvoiceCapabilityStatus.Forbidden);
        }

        var decision = await live.CheckAsync(subject, request.QuotationId, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (decision != QuotationInvoiceLiveAuthorityResult.Allowed)
            return new(decision == QuotationInvoiceLiveAuthorityResult.Denied
                ? QuotationInvoiceCapabilityStatus.Forbidden : QuotationInvoiceCapabilityStatus.Unavailable);

        if (ownership is not null)
        {
            var observedAgain = await financial.ReadAsync(operationId, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            if (observedAgain.Status == InvoiceFinancialOwnershipStatus.Denied)
                return new(QuotationInvoiceCapabilityStatus.Forbidden);
            if (observedAgain.Status != InvoiceFinancialOwnershipStatus.Verified || observedAgain.Ownership != ownership)
                return new(QuotationInvoiceCapabilityStatus.Unavailable);
        }

        // Fresh no-tracking reads after the await, never the pre-check's tracked projection.
        var session = await CurrentSessionAsync(subject, sessionId, cancellationToken);
        now = clock.GetUtcNow();
        if (session is null || exp <= now.ToUnixTimeSeconds() || nbf > now.ToUnixTimeSeconds() || iat > now.ToUnixTimeSeconds())
            return new(QuotationInvoiceCapabilityStatus.Unauthorized);
        var expires = Math.Min(Math.Min(exp, session.ExpiresAt.ToUnixTimeSeconds()),
            now.ToUnixTimeSeconds() + QuotationInvoiceCapabilityContract.MaximumLifetimeSeconds);
        var lifetime = expires - now.ToUnixTimeSeconds();
        if (lifetime <= 0) return new(QuotationInvoiceCapabilityStatus.Unauthorized);
        cancellationToken.ThrowIfCancellationRequested();
        var token = ownership is null
            ? issuer.IssueQuotationInvoiceCapability(subject, request.QuotationId, operationId,
                DateTimeOffset.FromUnixTimeSeconds(now.ToUnixTimeSeconds()), (int)lifetime)
            : attachmentIssuer.IssueQuotationInvoiceAttachment(subject, ownership,
                DateTimeOffset.FromUnixTimeSeconds(now.ToUnixTimeSeconds()), (int)lifetime);
        return new(QuotationInvoiceCapabilityStatus.Issued, new(token.Value, "Bearer", token.ExpiresInSeconds));
    }

    private async Task<RefreshSession?> CurrentSessionAsync(string subject, Guid sessionId, CancellationToken cancellationToken)
    {
        var session = await sessions.RefreshSessions.AsNoTracking().SingleOrDefaultAsync(x => x.Id == sessionId, cancellationToken);
        if (session is null || session.IdentityId != subject || session.IdentityKind != IdentityKind.Employee
            || session.RevokedAt is not null || session.ExpiresAt <= clock.GetUtcNow() || string.IsNullOrWhiteSpace(session.SecurityStamp)) return null;
        var identity = await identities.FindActiveAsync(subject, IdentityKind.Employee, cancellationToken);
        if (identity is null || string.IsNullOrWhiteSpace(identity.SecurityStamp) || identity.SecurityStamp != session.SecurityStamp) return null;
        return await sessions.RefreshSessions.AsNoTracking().AnyAsync(x => x.FamilyId == session.FamilyId && x.RevokedAt != null, cancellationToken)
            ? null : session;
    }

    private static string? Single(ClaimsPrincipal principal, string type)
    {
        var claims = principal.FindAll(type).Take(2).ToArray();
        return claims.Length == 1 ? claims[0].Value : null;
    }

    private static bool HasUnambiguousPayload(string? token)
    {
        if (token is not { Length: > 0 and <= 16384 }) return false;
        var segments = token.Split('.');
        if (segments.Length != 3) return false;
        try
        {
            using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(segments[1]), new JsonDocumentOptions { MaxDepth = 8 });
            if (payload.RootElement.ValueKind != JsonValueKind.Object) return false;
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in payload.RootElement.EnumerateObject())
            {
                if (!names.Add(property.Name)) return false;
                if (property.Name is "iat" or "nbf" or "exp"
                    && (property.Value.ValueKind != JsonValueKind.Number || !property.Value.TryGetInt64(out _))) return false;
            }
            return true;
        }
        catch (Exception exception) when (exception is JsonException or FormatException or ArgumentException) { return false; }
    }
}
