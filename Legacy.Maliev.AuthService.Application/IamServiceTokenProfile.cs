namespace Legacy.Maliev.AuthService.Application;

/// <summary>Server-owned IAM admission profile, separate from the legacy service token.</summary>
public sealed record IamServiceTokenProfile(string ServiceName)
{
    /// <summary>Exact permission required by the genuine IAM check-permission controller.</summary>
    public const string CheckPermission = "iam.auth.check-permission";
    /// <summary>Fixed IAM service-account role.</summary>
    public const string Role = "service-account";
    /// <summary>Fixed purpose required by the genuine IAM live-check guard.</summary>
    public const string Purpose = "iam-registration";
    /// <summary>Gets the subject derived by the genuine IAM live-check guard.</summary>
    public string Subject => "system:service:" + ServiceName.ToLowerInvariant().Replace("service", string.Empty, StringComparison.Ordinal);
    /// <summary>Validates a bounded, server-configured canonical service name.</summary>
    public static bool IsCanonicalServiceName(string? value) => value is { Length: > 7 and <= 64 }
        && char.IsAsciiLetter(value[0]) && value.EndsWith("Service", StringComparison.Ordinal)
        && value.All(char.IsAsciiLetterOrDigit);
}

/// <summary>Signs only server-owned IAM admission profiles.</summary>
public interface IIamServiceAccessTokenIssuer
{
    /// <summary>Gets whether the separate server-owned IAM target audience is configured.</summary>
    bool IsIamProfileConfigured { get; }
    /// <summary>Issues an IAM service token using the configured RSA issuer and explicit separate IAM audience.</summary>
    IssuedAccessToken IssueIamService(string clientId, IamServiceTokenProfile profile, DateTimeOffset now);
}
