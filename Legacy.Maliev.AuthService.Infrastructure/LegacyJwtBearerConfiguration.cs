using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Validates employee access tokens with the public component of the runtime signing key.</summary>
public sealed class LegacyJwtBearerConfiguration(IOptions<JwtOptions> jwtOptions)
    : IConfigureNamedOptions<JwtBearerOptions>
{
    /// <inheritdoc />
    public void Configure(string? name, JwtBearerOptions options)
    {
        if (!string.Equals(name, JwtBearerDefaults.AuthenticationScheme, StringComparison.Ordinal))
        {
            return;
        }

        var jwt = jwtOptions.Value;
        var rsa = RSA.Create();
        rsa.ImportFromPem(jwt.PrivateKeyPem);
        options.MapInboundClaims = false;
        options.TokenValidationParameters = CreateValidationParameters(jwt, new RsaSecurityKey(rsa) { KeyId = jwt.KeyId });
    }

    /// <summary>Applies the same issuer, audience, signing and lifetime checks to employee-token exchange.</summary>
    internal static TokenValidationParameters CreateValidationParameters(JwtOptions jwt, SecurityKey signingKey) => new()
    {
        ValidateIssuer = true,
        ValidIssuer = jwt.Issuer,
        ValidateAudience = true,
        ValidAudience = jwt.Audience,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        RequireSignedTokens = true,
        RequireExpirationTime = true,
        ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
        IssuerSigningKey = signingKey,
        ClockSkew = TimeSpan.FromSeconds(30),
    };

    /// <inheritdoc />
    public void Configure(JwtBearerOptions options) => Configure(JwtBearerDefaults.AuthenticationScheme, options);
}
