using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Read-only qualification authority using normal JWT trust and exact durable binding.</summary>
public sealed class QualificationIntrospectionService(
    IOptionsMonitor<JwtBearerOptions> bearerOptions,
    RefreshSessionDbContext sessions,
    ILegacyIdentityReader identities,
    TimeProvider timeProvider) : IQualificationIntrospectionService
{
    /// <inheritdoc />
    public async Task<QualificationIntrospectionResponse> EvaluateAsync(QualificationIntrospectionRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var denied = new QualificationIntrospectionResponse(false, null, request.Permission, request.Purpose, request.RequestId);
        if (request.Permission is not (QualificationIntrospectionContract.Read or QualificationIntrospectionContract.Update) ||
            request.Purpose != QualificationIntrospectionContract.Purpose || request.RequestId <= 0 ||
            string.IsNullOrWhiteSpace(request.EmployeeAccessToken) || request.EmployeeAccessToken.Length > 16384) return denied;
        ClaimsPrincipal employee;
        SecurityToken validated;
        try
        {
            employee = new JwtSecurityTokenHandler { MapInboundClaims = false, MaximumTokenSizeInBytes = 16384 }
                .ValidateToken(request.EmployeeAccessToken, bearerOptions.Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters, out validated);
        }
        catch (SecurityTokenException) { return denied; }
        catch (ArgumentException) { return denied; }
        var subject = ExactSubject(employee, "employee");
        var bindings = employee.FindAll("sid").ToArray();
        if (subject is null || subject.StartsWith("service:", StringComparison.Ordinal) || bindings.Length != 1 ||
            !Guid.TryParseExact(bindings[0].Value, "D", out var sid) || sid == Guid.Empty || bindings[0].Value != sid.ToString("D")) return denied;
        var row = await sessions.RefreshSessions.AsNoTracking().SingleOrDefaultAsync(x => x.Id == sid, cancellationToken);
        if (row is null || row.IdentityId != subject || row.IdentityKind != IdentityKind.Employee || row.RevokedAt is not null ||
            string.IsNullOrWhiteSpace(row.SecurityStamp)) return denied;
        var identity = await identities.FindActiveAsync(subject, IdentityKind.Employee, cancellationToken);
        if (identity is null || string.IsNullOrWhiteSpace(identity.SecurityStamp) || identity.SecurityStamp != row.SecurityStamp) return denied;
        if (await sessions.RefreshSessions.AsNoTracking().AnyAsync(x => x.FamilyId == row.FamilyId && x.RevokedAt != null, cancellationToken)) return denied;
        cancellationToken.ThrowIfCancellationRequested();
        var now = timeProvider.GetUtcNow();
        if (validated is not JwtSecurityToken jwt || !jwt.Payload.ContainsKey("exp") || jwt.ValidTo == DateTime.MinValue ||
            now >= new DateTimeOffset(jwt.ValidTo, TimeSpan.Zero) || now >= row.ExpiresAt) return denied;
        return new(true, subject, request.Permission, request.Purpose, request.RequestId);
    }

    internal static string? ExactSubject(ClaimsPrincipal principal, string kind)
    {
        var subjects = principal.FindAll("sub").ToArray();
        var kinds = principal.FindAll("identity_kind").ToArray();
        if (subjects.Length != 1 || string.IsNullOrWhiteSpace(subjects[0].Value) || subjects[0].Value.Length > 256 ||
            kinds.Length != 1 || kinds[0].Value != kind) return null;
        var subject = subjects[0].Value;
        return principal.FindAll("user_id").Concat(principal.FindAll(ClaimTypes.NameIdentifier)).Any(x => x.Value != subject) ? null : subject;
    }
}

/// <summary>Exact workload admission, independent from employee qualification grants.</summary>
public sealed class QualificationCallerAuthorizer(IOptionsMonitor<ServiceClientOptions> options) : IQualificationCallerAuthorizer
{
    /// <inheritdoc />
    public QualificationCallerAuthorization Authorize(ClaimsPrincipal caller)
    {
        if (QualificationIntrospectionService.ExactSubject(caller, "service") != QualificationIntrospectionContract.Caller ||
            caller.FindAll("permissions").Count(x => x.Value == QualificationIntrospectionContract.Capability) != 1 ||
            caller.FindAll("permissions").Any(x => x.Value.Contains('*', StringComparison.Ordinal))) return QualificationCallerAuthorization.Denied;
        try
        {
            var current = options.CurrentValue;
            return current.Clients.TryGetValue("legacy-quotation", out var client) && client.Permissions.Contains(QualificationIntrospectionContract.Capability, StringComparer.Ordinal)
                ? QualificationCallerAuthorization.Allowed : QualificationCallerAuthorization.Denied;
        }
        catch (OptionsValidationException) { return QualificationCallerAuthorization.Unavailable; }
    }
}
