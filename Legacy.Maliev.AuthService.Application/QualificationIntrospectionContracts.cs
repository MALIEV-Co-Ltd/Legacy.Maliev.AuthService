using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Text.Json.Serialization;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>The narrowly scoped employee qualification authority request.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record QualificationIntrospectionRequest(
    [Required, StringLength(16384)] string EmployeeAccessToken,
    [Required] string Permission,
    [Required] string Purpose,
    [Range(1, int.MaxValue)] int RequestId);

/// <summary>A non-enumerating, uncached point-in-time authority decision.</summary>
public sealed record QualificationIntrospectionResponse(bool Allowed, string? Subject, string Permission, string Purpose, int RequestId);

/// <summary>Frozen qualification-only bridge values; not an employee grant resolver.</summary>
public static class QualificationIntrospectionContract
{
    /// <summary>The only admitted workload.</summary>
    public const string Caller = "service:legacy-quotation";
    /// <summary>The dedicated workload capability.</summary>
    public const string Capability = "legacy-auth.quotation-qualification.introspect";
    /// <summary>The only admitted purpose.</summary>
    public const string Purpose = "quotation-request-qualification";
    /// <summary>Existing uniform source employee read permission.</summary>
    public const string Read = "legacy.quotation-requests.read";
    /// <summary>Existing uniform source employee update permission.</summary>
    public const string Update = "legacy.quotation-requests.update";
    /// <summary>Maximum bounded request bytes.</summary>
    public const int MaxBodyBytes = 24576;
}

/// <summary>Evaluates an independently validated employee token against live authority.</summary>
public interface IQualificationIntrospectionService
{
    /// <summary>Returns a decision without mutating identity or session state.</summary>
    Task<QualificationIntrospectionResponse> EvaluateAsync(QualificationIntrospectionRequest request, CancellationToken cancellationToken);
}

/// <summary>Request-current workload admission result.</summary>
public enum QualificationCallerAuthorization
{
    /// <summary>The exact caller has its current capability.</summary>
    Allowed,
    /// <summary>The caller or capability is not admitted.</summary>
    Denied,
    /// <summary>Authoritative configuration cannot be evaluated.</summary>
    Unavailable,
}

/// <summary>Checks the normal validated workload before endpoint admission.</summary>
public interface IQualificationCallerAuthorizer
{
    /// <summary>Checks exact immutable caller and workload capability.</summary>
    QualificationCallerAuthorization Authorize(ClaimsPrincipal caller);
}
