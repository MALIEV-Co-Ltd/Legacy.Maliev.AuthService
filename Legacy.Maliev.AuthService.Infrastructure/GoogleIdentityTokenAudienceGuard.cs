using System.Text.Json;
using Google.Apis.Auth;
using Microsoft.IdentityModel.Tokens;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>
/// Rejects ambiguous or untrusted audience claims before Google SDK verification.
/// Passing this guard never establishes identity or replaces cryptographic validation.
/// </summary>
public static class GoogleIdentityTokenAudienceGuard
{
    // Match the Google-specific SDK's existing maximum JWT length. The payload is
    // therefore at most 7,500 decoded bytes, with bounded JSON nesting/iteration.
    private const int MaximumCredentialLength = 10000;
    private const int MaximumPayloadBytes = 7500;
    private const int MaximumJsonDepth = 16;

    /// <summary>Requires one unambiguous audience claim containing only the exact configured client.</summary>
    /// <param name="credential">The untrusted serialized ID token, never logged or persisted.</param>
    /// <param name="audience">The sole trusted client for the current application.</param>
    /// <exception cref="InvalidJwtException">The token does not have a bounded, unambiguous, trusted audience.</exception>
    public static void EnsureMatches(string credential, string audience)
    {
        if (string.IsNullOrWhiteSpace(credential) || credential.Length > MaximumCredentialLength ||
            string.IsNullOrWhiteSpace(audience))
        {
            throw InvalidAudience();
        }

        var firstDot = credential.IndexOf('.');
        var secondDot = firstDot < 0 ? -1 : credential.IndexOf('.', firstDot + 1);
        if (firstDot <= 0 || secondDot <= firstDot + 1 || secondDot == credential.Length - 1 ||
            credential.IndexOf('.', secondDot + 1) >= 0)
        {
            throw InvalidAudience();
        }

        var encodedPayload = credential.AsSpan(firstDot + 1, secondDot - firstDot - 1);
        foreach (var character in encodedPayload)
        {
            if (!(character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_'))
            {
                throw InvalidAudience();
            }
        }

        try
        {
            var payload = Base64UrlEncoder.DecodeBytes(encodedPayload.ToString());
            if (payload.Length > MaximumPayloadBytes ||
                !encodedPayload.SequenceEqual(Base64UrlEncoder.Encode(payload).AsSpan()))
            {
                throw InvalidAudience();
            }

            using var document = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = MaximumJsonDepth });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw InvalidAudience();
            }

            var audienceClaims = 0;
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (!property.NameEquals("aud")) continue;
                audienceClaims++;
                if (audienceClaims > 1 || !IsTrusted(property.Value, audience)) throw InvalidAudience();
            }

            if (audienceClaims != 1) throw InvalidAudience();
        }
        catch (Exception exception) when (exception is JsonException or FormatException or ArgumentException)
        {
            // Parser diagnostics can contain token material. Emit only an opaque SDK failure.
            throw InvalidAudience();
        }
    }

    private static bool IsTrusted(JsonElement claim, string audience)
    {
        if (claim.ValueKind == JsonValueKind.String)
        {
            return string.Equals(claim.GetString(), audience, StringComparison.Ordinal);
        }

        if (claim.ValueKind != JsonValueKind.Array || claim.GetArrayLength() == 0) return false;
        foreach (var element in claim.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.String ||
                !string.Equals(element.GetString(), audience, StringComparison.Ordinal)) return false;
        }

        return true;
    }

    private static InvalidJwtException InvalidAudience() => new("JWT audience is invalid.");
}
