using Maliev.Aspire.ServiceDefaults.IAM;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class NormalIamCompositionHttpTests
{
    [Theory]
    [InlineData("Services:IAMService:BaseUrl")]
    [InlineData("Services:IAM:BaseUrl")]
    public void NormalProgram_RegistersActualScopedIamClient(string originKey)
    {
        using var app = new Factory(originKey);
        using var first = app.Services.CreateScope();
        using var second = app.Services.CreateScope();
        var firstClient = Assert.IsType<IamServiceClient>(first.ServiceProvider.GetService<IIamServiceClient>());
        var secondClient = Assert.IsType<IamServiceClient>(second.ServiceProvider.GetService<IIamServiceClient>());
        Assert.NotSame(firstClient, secondClient);
        Assert.Same(firstClient, first.ServiceProvider.GetRequiredService<IIamServiceClient>());
    }

    private sealed class Factory(string originKey) : WebApplicationFactory<Program>
    {
        private readonly RSA signingKey = RSA.Create(2048);

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.UseSetting("CORS:AllowedOrigins", "https://localhost");
            builder.UseSetting(originKey, "https://normal-auth-iam.invalid");
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["ConnectionStrings:CustomerIdentity"] = "Host=localhost;Database=unused;Username=unused",
                    ["ConnectionStrings:EmployeeIdentity"] = "Host=localhost;Database=unused;Username=unused",
                    ["ConnectionStrings:RefreshSessions"] = "Host=localhost;Database=unused;Username=unused",
                    ["Jwt:Issuer"] = "https://normal-auth-iam.test",
                    ["Jwt:Audience"] = "normal-auth-iam-test",
                    ["Jwt:PrivateKeyPem"] = signingKey.ExportPkcs8PrivateKeyPem(),
                    ["Jwt:KeyId"] = "normal-auth-iam-test",
                }));
            // No authentication, authorization, IAM client or application replacements.
            // Merely configuring an origin must not be mistaken for normal registration.
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing) signingKey.Dispose();
        }
    }
}
