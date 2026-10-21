using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Google.Apis.Auth;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Legacy.Maliev.AuthService.Tests;

// The public SDK verification seam uses owned loopback JWKS and ephemeral RSA.
// This does not replace or prove the production Google certificate-fetch path.
/// <summary>
/// Verifies the pinned Google SDK and production audience guard using locally signed credentials.
/// </summary>
/// <param name="fixture">The shared fixture supplying the authentication host or local signing-certificate endpoint.</param>
public sealed class GoogleSdk177AcceptanceTests(GoogleSdk177JwksFixture fixture)
    : IClassFixture<GoogleSdk177JwksFixture>
{
    /// <summary>
    /// Verifies genuinely signed claims from an accepted issuer reach the existing consumer.
    /// </summary>
    /// <param name="issuer">The accepted issuer whose signed claims are verified by the actual SDK.</param>
    /// <returns>A task that completes after the regression assertions finish.</returns>
    [Theory]
    [InlineData("https://accounts.google.com")]
    [InlineData("accounts.google.com")]
    public async Task ActualSdk_ValidSignedClaimsReachExistingConsumer(string issuer)
    {
        var claims = fixture.Claims();
        claims["iss"] = issuer;
        var result = await CreateValidator().ValidateAsync(fixture.Sign(claims), "intranet", "owned-nonce", default);

        Assert.True(result.Succeeded);
        Assert.Null(result.ErrorCode);
        var identity = Assert.IsType<VerifiedGoogleIdentity>(result.Identity);
        Assert.Equal("owned-subject", identity.Subject);
        Assert.Equal("employee@example.invalid", identity.Email);
        Assert.True(identity.EmailVerified);
        Assert.Equal("example.invalid", identity.HostedDomain);
        Assert.Equal("พนักงานทดสอบ", identity.FullName);
        Assert.Equal("https://synthetic.example.invalid/profile.png", identity.ProfileImageUrl);
        Assert.True(fixture.JwksRequests > 0);
    }

    /// <summary>
    /// Verifies invalid SDK or consumer boundaries reject the credential without an identity.
    /// </summary>
    /// <param name="failure">The injected authority or credential failure tested by the case.</param>
    /// <returns>A task that completes after the regression assertions finish.</returns>
    [Theory]
    [InlineData("issuer")]
    [InlineData("audience")]
    [InlineData("additional-audience")]
    [InlineData("array-wrong-audience")]
    [InlineData("missing-audience")]
    [InlineData("expired")]
    [InlineData("future-issued")]
    [InlineData("missing-issued")]
    [InlineData("missing-expiry")]
    [InlineData("signature")]
    [InlineData("trusted-array-signature")]
    [InlineData("algorithm")]
    [InlineData("nonce")]
    [InlineData("missing-nonce")]
    [InlineData("subject")]
    [InlineData("email")]
    [InlineData("unverified-email")]
    public async Task ActualSdkAndConsumer_InvalidBoundaryRejectsWithoutIdentity(string failure)
    {
        var claims = fixture.Claims();
        switch (failure)
        {
            case "issuer": claims["iss"] = "https://accounts.google.com.evil.invalid"; break;
            case "audience": claims["aud"] = "other-client"; break;
            case "additional-audience": claims["aud"] = new[] { "owned-client", "other-client" }; break;
            case "array-wrong-audience": claims["aud"] = new[] { "other-client" }; break;
            case "missing-audience": claims.Remove("aud"); break;
            case "expired": claims["exp"] = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds(); break;
            case "future-issued": claims["iat"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(); break;
            case "missing-issued": claims.Remove("iat"); break;
            case "missing-expiry": claims.Remove("exp"); break;
            case "nonce": claims["nonce"] = "different-nonce"; break;
            case "missing-nonce": claims.Remove("nonce"); break;
            case "subject": claims["sub"] = ""; break;
            case "email": claims["email"] = ""; break;
            case "unverified-email": claims["email_verified"] = false; break;
            case "trusted-array-signature": claims["aud"] = new[] { "owned-client" }; break;
        }

        var token = fixture.Sign(claims, wrongKey: failure is "signature" or "trusted-array-signature", algorithm: failure == "algorithm" ? "HS256" : "RS256");
        var result = await CreateValidator().ValidateAsync(token, "intranet", "owned-nonce", default);

        Assert.False(result.Succeeded);
        Assert.Null(result.Identity);
        Assert.Equal("invalid_google_credential", result.ErrorCode);
        Assert.DoesNotContain(token, result.ErrorDescription ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain("owned-subject", result.ErrorDescription ?? string.Empty, StringComparison.Ordinal);
    }

    /// <summary>
    /// Verifies even a single trusted array audience still requires a valid signature.
    /// </summary>
    /// <returns>A task that completes after the regression assertions finish.</returns>
    [Fact]
    public async Task ActualSdkAndProductionAudienceGuard_SingleTrustedArrayStillRequiresSignature()
    {
        var claims = fixture.Claims();
        claims["aud"] = new[] { "owned-client" };

        var result = await CreateValidator().ValidateAsync(fixture.Sign(claims), "intranet", "owned-nonce", default);

        Assert.True(result.Succeeded);
        Assert.Equal("owned-subject", result.Identity?.Subject);
        Assert.True(fixture.JwksRequests > 0);
    }

    /// <summary>
    /// Verifies ambiguous or untrusted audiences are rejected before invoking the provider.
    /// </summary>
    /// <param name="payload">The candidate JSON payload used to exercise audience admission.</param>
    /// <returns>A task that completes after the regression assertions finish.</returns>
    [Theory]
    [InlineData("{}")]
    [InlineData("{\"aud\":\"other-client\"}")]
    [InlineData("{\"aud\":[\"other-client\"]}")]
    [InlineData("{\"aud\":[\"owned-client\",\"other-client\"]}")]
    [InlineData("{\"aud\":\"\"}")]
    [InlineData("{\"aud\":\"OWNED-client\"}")]
    [InlineData("{\"aud\":\" owned-client \"}")]
    [InlineData("{\"aud\":null}")]
    [InlineData("{\"aud\":42}")]
    [InlineData("{\"aud\":true}")]
    [InlineData("{\"aud\":{\"client\":\"owned-client\"}}")]
    [InlineData("{\"aud\":[]}")]
    [InlineData("{\"aud\":[\"owned-client\",null]}")]
    [InlineData("{\"aud\":[\"owned-client\",42]}")]
    [InlineData("{\"aud\":[\"owned-client\",\"\"]}")]
    [InlineData("{\"aud\":\"other-client\",\"aud\":\"owned-client\"}")]
    [InlineData("{\"aud\":\"owned-client\",\"aud\":\"owned-client\"}")]
    [InlineData("{\"aud\":\"owned-client\",\"a\\u0075d\":\"owned-client\"}")]
    [InlineData("{\"aud\":\"owned-client\",}")]
    [InlineData("{\"aud\":\"owned-client\"} trailing")]
    [InlineData("[]")]
    public async Task ProductionAdapter_AmbiguousOrUntrustedAudienceFailsBeforeProvider(string payload)
    {
        var token = fixture.SignRawPayload(payload);

        var exception = await Assert.ThrowsAsync<InvalidJwtException>(() =>
            new GoogleIdentityTokenVerifier().VerifyAsync(token, "owned-client", default));

        Assert.Equal("JWT audience is invalid.", exception.Message);
        Assert.Null(exception.InnerException);
        Assert.DoesNotContain(token, exception.Message, StringComparison.Ordinal);
        var result = await CreateValidator(new GoogleIdentityTokenVerifier()).ValidateAsync(token, "intranet", "owned-nonce", default);
        Assert.False(result.Succeeded);
        Assert.Equal("invalid_google_credential", result.ErrorCode);
        Assert.Null(result.Identity);
    }

    /// <summary>
    /// Verifies bounded payload rejection remains opaque to the caller.
    /// </summary>
    /// <param name="boundary">The payload boundary that must be rejected opaquely.</param>
    /// <returns>A task that completes after the regression assertions finish.</returns>
    [Theory]
    [InlineData("size")]
    [InlineData("depth")]
    [InlineData("encoding")]
    public async Task ProductionAdapter_BoundedPayloadRejectionIsOpaque(string boundary)
    {
        var payload = boundary == "depth"
            ? "{\"aud\":\"owned-client\",\"nested\":" + new string('[', 17) + "0" + new string(']', 17) + "}"
            : "{\"aud\":\"owned-client\",\"padding\":\"" + new string('x', 10000) + "\"}";
        var token = boundary == "encoding" ? "header.invalid+payload.signature" : fixture.SignRawPayload(payload);

        var exception = await Assert.ThrowsAsync<InvalidJwtException>(() =>
            new GoogleIdentityTokenVerifier().VerifyAsync(token, "owned-client", default));

        Assert.Equal("JWT audience is invalid.", exception.Message);
        Assert.Null(exception.InnerException);
    }

    /// <summary>
    /// Verifies malformed credential segments are rejected without disclosing details.
    /// </summary>
    /// <param name="credential">The malformed credential whose segments must be rejected opaquely.</param>
    [Theory]
    [InlineData("")]
    [InlineData("header.payload")]
    [InlineData("header.payload.signature.extra")]
    [InlineData(".payload.signature")]
    [InlineData("header..signature")]
    [InlineData("header.payload.")]
    [InlineData("header.payload.signature")]
    public void AudienceGuard_MalformedSegmentsAreOpaque(string credential)
    {
        var exception = Assert.Throws<InvalidJwtException>(() =>
            GoogleIdentityTokenAudienceGuard.EnsureMatches(credential, "owned-client"));

        Assert.Equal("JWT audience is invalid.", exception.Message);
        Assert.Null(exception.InnerException);
    }

    /// <summary>
    /// Verifies noncanonical base64 is rejected even when it decodes to equivalent bytes.
    /// </summary>
    [Fact]
    public void AudienceGuard_NoncanonicalBase64WithEquivalentDecodedBytesIsRejected()
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        var segments = fixture.SignRawPayload("{\"aud\":\"owned-client\"}").Split('.');
        var canonical = segments[1];
        Assert.Equal(2, canonical.Length % 4);
        var finalIndex = alphabet.IndexOf(canonical[^1]);
        Assert.Equal(0, finalIndex & 15);
        var noncanonical = canonical[..^1] + alphabet[finalIndex | 1];
        Assert.Equal(Convert.FromBase64String(canonical + "=="),
            Convert.FromBase64String(noncanonical + "=="));

        var exception = Assert.Throws<InvalidJwtException>(() =>
            GoogleIdentityTokenAudienceGuard.EnsureMatches(segments[0] + "." + noncanonical + "." + segments[2], "owned-client"));

        Assert.Equal("JWT audience is invalid.", exception.Message);
        Assert.Null(exception.InnerException);
    }

    /// <summary>
    /// Verifies the sole audience property is recognized when its JSON name is escaped.
    /// </summary>
    [Fact]
    public void AudienceGuard_EscapedSoleAudienceNameIsRecognized()
    {
        var token = fixture.SignRawPayload("{\"a\\u0075d\":\"owned-client\"}");

        var exception = Record.Exception(() => GoogleIdentityTokenAudienceGuard.EnsureMatches(token, "owned-client"));

        Assert.Null(exception);
    }

    /// <summary>
    /// Verifies a hosted-domain suffix is not mistaken for an allowlisted domain.
    /// </summary>
    /// <returns>A task that completes after the regression assertions finish.</returns>
    [Fact]
    public async Task ActualSdkVerifiedClaims_HostedDomainSuffixIsNotAllowlisted()
    {
        var claims = fixture.Claims();
        claims["hd"] = "example.invalid.evil.invalid";
        claims["email"] = "employee@example.invalid.evil.invalid";

        var result = await CreateValidator().ValidateAsync(fixture.Sign(claims), "intranet", "owned-nonce", default);

        Assert.False(result.Succeeded);
        Assert.Null(result.Identity);
        Assert.Equal("invalid_domain", result.ErrorCode);
    }

    /// <summary>
    /// Verifies malformed credentials fail before fetching signing certificates.
    /// </summary>
    /// <returns>A task that completes after the regression assertions finish.</returns>
    [Fact]
    public async Task ProductionGoogleAdapter_MalformedCredentialFailsBeforeCertificateFetch()
    {
        var validator = CreateValidator(new GoogleIdentityTokenVerifier());

        var result = await validator.ValidateAsync("not-a-jwt", "intranet", "owned-nonce", default);

        Assert.False(result.Succeeded);
        Assert.Null(result.Identity);
        Assert.Equal("invalid_google_credential", result.ErrorCode);
        Assert.DoesNotContain("not-a-jwt", result.ErrorDescription ?? string.Empty, StringComparison.Ordinal);
    }

    private GoogleIdentityTokenValidator CreateValidator(IGoogleIdentityTokenVerifier? verifier = null)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["GoogleIdentity:Employee:Audiences:intranet"] = "owned-client",
            ["GoogleIdentity:Employee:HostedDomain"] = "example.invalid",
        }).Build();
        return new(configuration, NullLogger<GoogleIdentityTokenValidator>.Instance,
            verifier ?? new LocalSdkVerifier(fixture.CertificatesUri));
    }

    private sealed class LocalSdkVerifier(Uri certificatesUri) : IGoogleIdentityTokenVerifier
    {
        public async Task<GoogleIdentityTokenClaims> VerifyAsync(string credential, string audience, CancellationToken cancellationToken)
        {
            GoogleIdentityTokenAudienceGuard.EnsureMatches(credential, audience);
            var options = new SignedTokenVerificationOptions
            {
                CertificatesUrl = certificatesUri.AbsoluteUri,
            };
            options.TrustedIssuers.Add("https://accounts.google.com");
            options.TrustedIssuers.Add("accounts.google.com");
            options.TrustedAudiences.Add(audience);
            var payload = await JsonWebSignature.VerifySignedTokenAsync<GoogleJsonWebSignature.Payload>(
                credential, options, cancellationToken);
            return new(payload.Subject, payload.Email, payload.EmailVerified, payload.Nonce,
                payload.HostedDomain, payload.Name, payload.Picture);
        }
    }
}

/// <summary>
/// Provides a loopback signing-certificate endpoint and local keys for genuine SDK verification.
/// </summary>
public sealed class GoogleSdk177JwksFixture : IAsyncLifetime
{
    private readonly RSA rsa = RSA.Create(2048);
    private WebApplication application = null!;
    private int jwksRequests;

    /// <summary>
    /// Gets the loopback URI serving the fixture's signing certificates.
    /// </summary>
    public Uri CertificatesUri { get; private set; } = null!;
    /// <summary>
    /// Gets the number of certificate requests received by this fixture.
    /// </summary>
    public int JwksRequests => Volatile.Read(ref jwksRequests);

    /// <summary>
    /// Starts the loopback certificate endpoint using the fixture-owned signing key.
    /// </summary>
    /// <returns>A task that completes when fixture initialization is finished.</returns>
    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
        application = builder.Build();
        var parameters = rsa.ExportParameters(false);
        var jwks = JsonSerializer.Serialize(new
        {
            keys = new[] { new { kty = "RSA", alg = "RS256", kid = "owned-key", n = Encode(parameters.Modulus!), e = Encode(parameters.Exponent!) } },
        });
        application.MapGet("/owned-jwks", (HttpContext context) =>
        {
            Assert.Equal(0, context.Request.Headers.Authorization.Count);
            Interlocked.Increment(ref jwksRequests);
            return Results.Text(jwks, "application/json");
        });
        await application.StartAsync();
        var server = application.Services.GetRequiredService<IServer>();
        var address = Assert.Single(server.Features.Get<IServerAddressesFeature>()!.Addresses);
        CertificatesUri = new Uri(new Uri(address), "/owned-jwks");
        Assert.True(IPAddress.IsLoopback(IPAddress.Parse(CertificatesUri.Host)));
    }

    /// <summary>
    /// Creates the baseline signed-credential claims used by the acceptance cases.
    /// </summary>
    /// <returns>The baseline claim dictionary for a locally signed credential.</returns>
    public Dictionary<string, object> Claims() => new()
    {
        ["iss"] = "https://accounts.google.com",
        ["aud"] = "owned-client",
        ["iat"] = DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds(),
        ["exp"] = DateTimeOffset.UtcNow.AddHours(2).ToUnixTimeSeconds(),
        ["sub"] = "owned-subject",
        ["email"] = "employee@example.invalid",
        ["email_verified"] = true,
        ["nonce"] = "owned-nonce",
        ["hd"] = "example.invalid",
        ["name"] = "พนักงานทดสอบ",
        ["picture"] = "https://synthetic.example.invalid/profile.png",
    };

    /// <summary>
    /// Signs structured claims with the selected local key and algorithm.
    /// </summary>
    /// <param name="claims">The structured claims or raw JSON claim payload to sign.</param>
    /// <param name="wrongKey">Whether to sign with the key absent from the published certificate set.</param>
    /// <param name="algorithm">The JWT signing algorithm written into the locally signed credential.</param>
    /// <returns>The compact JWT signed with the selected fixture key.</returns>
    public string Sign(Dictionary<string, object> claims, bool wrongKey = false, string algorithm = "RS256")
        => SignRawPayload(JsonSerializer.Serialize(claims), wrongKey, algorithm);

    /// <summary>
    /// Signs a raw JSON claim payload with the selected local key and algorithm.
    /// </summary>
    /// <param name="claims">The structured claims or raw JSON claim payload to sign.</param>
    /// <param name="wrongKey">Whether to sign with the key absent from the published certificate set.</param>
    /// <param name="algorithm">The JWT signing algorithm written into the locally signed credential.</param>
    /// <returns>The compact JWT signed with the selected fixture key.</returns>
    public string SignRawPayload(string claims, bool wrongKey = false, string algorithm = "RS256")
    {
        var header = Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { alg = algorithm, typ = "JWT", kid = "owned-key" })));
        var payload = Encode(Encoding.UTF8.GetBytes(claims));
        var input = header + "." + payload;
        using var differentRsa = wrongKey ? RSA.Create(2048) : null;
        var signature = (differentRsa ?? rsa).SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return input + "." + Encode(signature);
    }

    /// <summary>
    /// Stops the loopback certificate host and releases the fixture-owned signing keys.
    /// </summary>
    /// <returns>A task that completes after fixture-owned resources are released.</returns>
    public async Task DisposeAsync()
    {
        await application.StopAsync();
        await application.DisposeAsync();
        rsa.Dispose();
    }

    private static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
