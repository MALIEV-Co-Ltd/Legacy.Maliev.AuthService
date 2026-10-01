using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Validates the server-held employee JWT before issuing a narrow service delegation.</summary>
public sealed class InvoiceDelegationService(
    IOptions<JwtOptions> options,
    IInvoiceDelegationTokenIssuer issuer,
    TimeProvider timeProvider,
    RefreshSessionDbContext sessions,
    ILegacyIdentityReader identities)
{
    /// <summary>Returns no token unless both the trusted service identity and employee token satisfy the contract.</summary>
    public async Task<InvoiceDelegationTokenResponse?> IssueAsync(
        string? serviceSubject,
        InvoiceDelegationRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!string.Equals(serviceSubject, InvoiceDelegationContract.IntranetServiceSubject, StringComparison.Ordinal) ||
            request.QuotationId <= 0 ||
            request.EmployeeAccessToken is not { Length: > 0 and <= 16384 } ||
            !Guid.TryParseExact(request.OperationId, "D", out var operationId) ||
            operationId == Guid.Empty ||
            !string.Equals(request.OperationId, operationId.ToString("D"), StringComparison.Ordinal))
        {
            return null;
        }

        using var rsa = RSA.Create();
        rsa.ImportFromPem(options.Value.PrivateKeyPem);
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false, MaximumTokenSizeInBytes = 16384 };
        ClaimsPrincipal employee;
        JwtSecurityToken jwt;
        try
        {
            employee = handler.ValidateToken(
                request.EmployeeAccessToken,
                LegacyJwtBearerConfiguration.CreateValidationParameters(
                    options.Value, new RsaSecurityKey(rsa) { KeyId = options.Value.KeyId }),
                out var validatedToken);
            jwt = (JwtSecurityToken)validatedToken;
        }
        catch (SecurityTokenException) { return null; }
        catch (ArgumentException) { return null; }
        catch (InvalidCastException) { return null; }

        var subjects = employee.FindAll(JwtRegisteredClaimNames.Sub).ToArray();
        var kinds = employee.FindAll("identity_kind").ToArray();
        var issuedAt = employee.FindAll(JwtRegisteredClaimNames.Iat).ToArray();
        var bindings = employee.FindAll("sid").ToArray();
        var now = timeProvider.GetUtcNow();
        if (subjects.Length != 1 || string.IsNullOrWhiteSpace(subjects[0].Value) || subjects[0].Value.Length > 256 ||
            subjects[0].Value.StartsWith("service:", StringComparison.Ordinal) ||
            kinds.Length != 1 || kinds[0].Value != "employee" ||
            !employee.HasClaim("permissions", InvoiceDelegationContract.Scope) ||
            issuedAt.Length != 1 ||
            !long.TryParse(issuedAt[0].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var issuedAtSeconds) ||
            jwt.Audiences.Count() != 1 ||
            jwt.Audiences.Single() != options.Value.Audience ||
            issuedAtSeconds > now.AddSeconds(30).ToUnixTimeSeconds() ||
            issuedAtSeconds < now.AddSeconds(-options.Value.AccessTokenLifetimeSeconds - 30).ToUnixTimeSeconds())
        {
            return null;
        }

        var subject = subjects[0].Value;
        if (employee.FindAll("user_id").Concat(employee.FindAll(ClaimTypes.NameIdentifier)).Any(claim => claim.Value != subject)
            || bindings.Length != 1 || !Guid.TryParseExact(bindings[0].Value, "D", out var sessionId)
            || sessionId == Guid.Empty || bindings[0].Value != sessionId.ToString("D")) return null;

        var session = await sessions.RefreshSessions.AsNoTracking().SingleOrDefaultAsync(row => row.Id == sessionId, cancellationToken);
        if (session is null || session.IdentityId != subject || session.IdentityKind != IdentityKind.Employee
            || session.RevokedAt is not null || string.IsNullOrWhiteSpace(session.SecurityStamp)) return null;
        var identity = await identities.FindActiveAsync(subject, IdentityKind.Employee, cancellationToken);
        if (identity is null || string.IsNullOrWhiteSpace(identity.SecurityStamp) || identity.SecurityStamp != session.SecurityStamp) return null;
        if (await sessions.RefreshSessions.AsNoTracking().AnyAsync(row => row.FamilyId == session.FamilyId && row.RevokedAt != null, cancellationToken)) return null;

        cancellationToken.ThrowIfCancellationRequested();
        now = timeProvider.GetUtcNow();
        if (!jwt.Payload.ContainsKey("exp") || jwt.ValidTo == DateTime.MinValue
            || now >= new DateTimeOffset(jwt.ValidTo, TimeSpan.Zero) || now >= session.ExpiresAt) return null;
        cancellationToken.ThrowIfCancellationRequested();
        var token = issuer.IssueInvoiceDelegation(subject, request.QuotationId, operationId, now);
        return new(token.Value, "Bearer", token.ExpiresInSeconds);
    }
}
