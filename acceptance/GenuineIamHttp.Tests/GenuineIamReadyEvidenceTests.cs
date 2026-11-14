using System.Text.Json;
using Xunit;

namespace Legacy.Maliev.AuthService.GenuineIamHttp.Tests;

/// <summary>Checks the genuine IAM ready protocol and loaded dependency evidence.</summary>
public sealed class GenuineIamReadyEvidenceTests
{
    private static JsonDocument Parse(string additional) => JsonDocument.Parse(
        "{\"baseAddress\":\"http://127.0.0.1:3210\",\"seeded\":true,\"jwtValidationPreserved\":true" + additional + "}");

    [Fact]
    public void OriginalReadyProtocolRemainsValidWithoutOverlay()
    {
        using var json = Parse("");
        var result = OwnedIamProcess.ValidateReady(json.RootElement, false);
        Assert.Equal("http://127.0.0.1:3210/", result.Address.AbsoluteUri);
        Assert.Null(result.Version);
        Assert.Null(result.Hash);
    }

    [Fact]
    public void PatchedReadyEvidenceIsAccepted()
    {
        using var json = Parse(",\"webUtilitiesFileVersion\":\"10.0.15.0\",\"webUtilitiesSha256\":\"" + new string('a', 64) + "\"");
        var result = OwnedIamProcess.ValidateReady(json.RootElement, true);
        Assert.Equal("10.0.15.0", result.Version);
        Assert.Equal(new string('a', 64), result.Hash);
    }

    [Theory]
    [InlineData(",\"webUtilitiesFileVersion\":\"10.0.14.0\",\"webUtilitiesSha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"")]
    [InlineData(",\"webUtilitiesFileVersion\":\"invalid\",\"webUtilitiesSha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"")]
    [InlineData(",\"webUtilitiesFileVersion\":\"10.0.15.0\",\"webUtilitiesSha256\":\"bad\"")]
    [InlineData("")]
    public void MissingOldOrMalformedOverlayEvidenceIsRejected(string additional)
    {
        using var json = Parse(additional);
        Assert.ThrowsAny<Exception>(() => OwnedIamProcess.ValidateReady(json.RootElement, true));
    }
}
