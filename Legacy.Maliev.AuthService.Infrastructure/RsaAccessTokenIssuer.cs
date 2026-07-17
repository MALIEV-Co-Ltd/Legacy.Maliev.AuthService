using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Issues RS256 access tokens whose private key is supplied only at runtime.</summary>
public sealed class RsaAccessTokenIssuer : IAccessTokenIssuer, IServiceAccessTokenIssuer, IDisposable
{
    private readonly JwtOptions options;
    private readonly RSA rsa;

    /// <summary>Initializes and validates the runtime signing key.</summary>
    public RsaAccessTokenIssuer(IOptions<JwtOptions> options)
    {
        this.options = options.Value;
        rsa = RSA.Create();
        rsa.ImportFromPem(this.options.PrivateKeyPem);
    }

    /// <inheritdoc />
    public IssuedAccessToken Issue(LegacyIdentity identity, DateTimeOffset now)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, identity.Id),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Name, identity.UserName),
            new("identity_kind", identity.Kind.ToString().ToLowerInvariant()),
        };

        if (!string.IsNullOrWhiteSpace(identity.Email))
        {
            claims.Add(new(JwtRegisteredClaimNames.Email, identity.Email));
        }

        if (identity.DatabaseId is not null)
        {
            claims.Add(new("legacy_database_id", identity.DatabaseId.Value.ToString()));
        }

        if (identity.Kind == IdentityKind.Employee)
        {
            claims.Add(new("permissions", LegacyAccessTokenPermissions.CatalogMaterialsRead));
            claims.Add(new("permissions", LegacyAccessTokenPermissions.CatalogMaterialsCreate));
            claims.Add(new("permissions", LegacyAccessTokenPermissions.CatalogMaterialsUpdate));
            claims.Add(new("permissions", LegacyAccessTokenPermissions.CustomersList));
        }

        return Issue(claims, now);
    }

    /// <inheritdoc />
    public IssuedAccessToken IssueService(string clientId, IReadOnlyList<string> permissions, DateTimeOffset now)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, $"service:{clientId}"),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Name, clientId),
            new("identity_kind", "service"),
        };
        claims.AddRange(permissions.Select(permission => new Claim("permissions", permission)));
        return Issue(claims, now);
    }

    private IssuedAccessToken Issue(IEnumerable<Claim> claims, DateTimeOffset now)
    {
        var key = new RsaSecurityKey(rsa) { KeyId = options.KeyId };
        var token = new JwtSecurityToken(
            options.Issuer,
            options.Audience,
            claims,
            now.UtcDateTime,
            now.AddSeconds(options.AccessTokenLifetimeSeconds).UtcDateTime,
            new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
        return new(new JwtSecurityTokenHandler().WriteToken(token), options.AccessTokenLifetimeSeconds);
    }

    /// <inheritdoc />
    public void Dispose() => rsa.Dispose();
}
