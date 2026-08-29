using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.Extensions.Options;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class ServiceClientOptionsValidationTests
{
    [Fact]
    public void Validate_AllowsEmptyClientSetForEnvironmentsWithoutMachineIdentities()
    {
        var result = new ServiceClientOptionsValidator().Validate(
            Options.DefaultName,
            new ServiceClientOptions());

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_AcceptsConfiguredHashAndExplicitPermissions()
    {
        var result = new ServiceClientOptionsValidator().Validate(
            Options.DefaultName,
            new ServiceClientOptions
            {
                Clients =
                {
                    ["legacy-web"] = new ServiceClientCredential
                    {
                        SecretSha256 = ServiceClientCredential.HashSecret("runtime-only-secret"),
                        Permissions = ["legacy-contact.messages.create"],
                    },
                },
            });

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_RejectsMalformedHashWithoutEchoingTheSecretValue()
    {
        const string malformed = "not-a-secret-hash";
        var result = new ServiceClientOptionsValidator().Validate(
            Options.DefaultName,
            new ServiceClientOptions
            {
                Clients =
                {
                    ["legacy-web"] = new ServiceClientCredential
                    {
                        SecretSha256 = malformed,
                        Permissions = ["legacy-contact.messages.create"],
                    },
                },
            });

        Assert.False(result.Succeeded);
        var message = string.Join(";", result.Failures!);
        Assert.Contains("legacy-web", message, StringComparison.Ordinal);
        Assert.DoesNotContain(malformed, message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("*")]
    [InlineData("legacy-contact.*")]
    public void Validate_RejectsEmptyOrWildcardPermissions(string permission)
    {
        var result = new ServiceClientOptionsValidator().Validate(
            Options.DefaultName,
            new ServiceClientOptions
            {
                Clients =
                {
                    ["legacy-web"] = new ServiceClientCredential
                    {
                        SecretSha256 = ServiceClientCredential.HashSecret("runtime-only-secret"),
                        Permissions = [permission],
                    },
                },
            });

        Assert.False(result.Succeeded);
    }
}
