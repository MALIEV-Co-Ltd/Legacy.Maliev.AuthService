extern alias IamApi;
extern alias IamInfrastructure;
extern alias IamApplication;
extern alias IamDomain;

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using IamProgram = IamApi::Program;
using IamDb = IamInfrastructure::Maliev.IAMService.Infrastructure.Persistence.IAMDbContext;
using KeyProvider = IamApplication::Maliev.IAMService.Application.Services.IRsaKeyProvider;
using Principal = IamDomain::Maliev.IAMService.Domain.Entities.Principal;
using Permission = IamDomain::Maliev.IAMService.Domain.Entities.Permission;
using Binding = IamDomain::Maliev.IAMService.Domain.Entities.PrincipalPermissionBinding;

// Only fixed receipts leave stdout: injected configuration and key material must
// never enter public CI logs, including through framework startup exceptions.
var protocol = Console.Out;
Console.SetOut(TextWriter.Null);
Console.SetError(TextWriter.Null);
var failures = new List<string>();
var phase = "configuration";
IamFactory? factory = null;
RSA? signingKey = null;
RSA? validationKey = null;
var capabilityKeys = new List<RSA>();
NpgsqlConnection? ownedPool = null;
HttpClient? client = null;
using var signing = RSA.Create();
try
{
    signing.ImportFromPem(Required("GENUINE_IAM_PRIVATE_PEM"));
    var principalId = Guid.Parse(Required("GENUINE_IAM_PRINCIPAL_ID"));
    var permissionId = Required("GENUINE_IAM_PERMISSION_ID");
    factory = new IamFactory(signing, Required("GENUINE_IAM_CONNECTION"), Required("GENUINE_IAM_LIVE_KEY"));
    phase = "host-start";
    factory.UseKestrel(0);
    client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
    using var startupDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
    await using (var scope = factory.Services.CreateAsyncScope())
    {
        phase = "jwt-contract";
        var db = scope.ServiceProvider.GetRequiredService<IamDb>();
        signingKey = scope.ServiceProvider.GetRequiredService<KeyProvider>().GetRsa();
        var authentication = scope.ServiceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);
        var parameters = authentication.TokenValidationParameters;
        var capability = scope.ServiceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(IamApi::Maliev.IAMService.Api.Authorization.TokenIssuanceCapabilityAuthentication.Scheme);
        foreach (var candidate in capability.TokenValidationParameters.IssuerSigningKeyResolver!(
            string.Empty, null!, "genuine-join", capability.TokenValidationParameters))
        {
            if (candidate is RsaSecurityKey { Rsa: not null } rsaKey) capabilityKeys.Add(rsaKey.Rsa);
        }
        if (!parameters.ValidateIssuer || !parameters.ValidateAudience || !parameters.ValidateLifetime
            || !parameters.ValidateIssuerSigningKey || parameters.SignatureValidator is not null)
        {
            throw new InvalidOperationException("JWT validation contract failed.");
        }
        var key = parameters.IssuerSigningKey ?? parameters.IssuerSigningKeys?.Single();
        validationKey = (key as RsaSecurityKey)?.Rsa
            ?? throw new InvalidOperationException("RSA JWT validation is required.");
        phase = "authority-seed";
        ownedPool = new NpgsqlConnection(db.Database.GetDbConnection().ConnectionString);
        db.Principals.Add(new Principal { PrincipalId = principalId, PrincipalType = "user", IsActive = true });
        db.Permissions.Add(new Permission { PermissionId = permissionId, ServiceName = "join", ResourceType = "resource", Action = "read" });
        db.PrincipalPermissionBindings.Add(new Binding
        {
            BindingId = Guid.NewGuid(), PrincipalId = principalId, PermissionId = permissionId, ResourcePath = "join/owned"
        });
        await db.SaveChangesAsync(startupDeadline.Token);
        if (await db.PrincipalPermissionBindings.CountAsync(b => b.PrincipalId == principalId, startupDeadline.Token) != 1)
        {
            throw new InvalidOperationException("Synthetic authority seed failed.");
        }
    }
    phase = "listener-contract";
    var addresses = factory.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()
        ?? throw new InvalidOperationException("Kestrel address is unavailable.");
    var address = new Uri(addresses.Addresses.Single());
    if (address.Scheme != "http" || !address.IsLoopback || address.Port <= 0)
    {
        throw new InvalidOperationException("IAM listener must be HTTP loopback.");
    }
    await protocol.WriteLineAsync("GENUINE_IAM_READY=" + JsonSerializer.Serialize(new
    {
        baseAddress = address.AbsoluteUri.TrimEnd('/'), seeded = true, jwtValidationPreserved = true
    }));
    await protocol.FlushAsync();
    phase = "stop-protocol";
    using var lease = new CancellationTokenSource(TimeSpan.FromMinutes(10));
    if (await Console.In.ReadLineAsync(lease.Token) != "stop")
    {
        throw new InvalidOperationException("Owned host requires a stop command.");
    }
}
catch (Exception)
{
    // Exclude exception payloads, which may contain credentials.
    failures.Add(phase);
}
finally
{
    await CleanupAsync("client", () => { client?.Dispose(); return Task.CompletedTask; });
    await CleanupAsync("host", async () =>
    {
        if (factory is not null)
        {
            await factory.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(20));
        }
    });
    await CleanupAsync("signing-rsa", () => { signingKey?.Dispose(); return Task.CompletedTask; });
    await CleanupAsync("validation-rsa", () => { validationKey?.Dispose(); return Task.CompletedTask; });
    foreach (var capabilityKey in capabilityKeys)
    {
        await CleanupAsync("capability-rsa", () => { capabilityKey.Dispose(); return Task.CompletedTask; });
    }
    await CleanupAsync("fixture-rsa", () => { signing.Dispose(); return Task.CompletedTask; });
    await CleanupAsync("owned-pool", () =>
    {
        if (ownedPool is not null)
        {
            try { NpgsqlConnection.ClearPool(ownedPool); }
            finally { ownedPool.Dispose(); }
        }
        return Task.CompletedTask;
    });
    await protocol.WriteLineAsync("GENUINE_IAM_STOPPED=" + JsonSerializer.Serialize(new
    {
        disposed = failures.Count == 0, failedSteps = failures
    }));
    await protocol.FlushAsync();
}
return failures.Count == 0 ? 0 : 1;

async Task CleanupAsync(string name, Func<Task> action)
{
    try { await action(); }
    catch (Exception) { failures.Add(name); }
}

static string Required(string name) => Environment.GetEnvironmentVariable(name)
    ?? throw new InvalidOperationException("A synthetic acceptance setting is missing.");

internal sealed class IamFactory(RSA signing, string connection, string liveKey) : WebApplicationFactory<IamProgram>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseContentRoot(Path.Combine(FindRepositoryRoot(), ".genuine-iam-source", "Maliev.IAMService", "Maliev.IAMService.Api"));
        builder.UseEnvironment("Production");
        builder.ConfigureLogging(logging => logging.ClearProviders());
        foreach (var setting in new Dictionary<string, string?>
        {
            ["ASPNETCORE_ENVIRONMENT"] = "Production",
            ["ConnectionStrings:IamDbContext"] = connection,
            ["ConnectionStrings:rabbitmq"] = "amqp://unused:unused@127.0.0.1:1/",
            ["Cache:RedisEnabled"] = "false",
            ["Observability:RuntimeMetricsEnabled"] = "false",
            ["CORS:AllowedOrigins:0"] = "https://localhost",
            ["CORS:AllowedOrigins"] = "https://localhost",
            ["Jwt:Issuer"] = "https://auth.join.invalid",
            ["Jwt:Audience"] = "https://iam.join.invalid",
            ["Jwt:PublicKey"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(signing.ExportSubjectPublicKeyInfoPem())),
            ["Jwt:PrivateKey"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(signing.ExportPkcs8PrivateKeyPem())),
            ["IAM:TokenIssuanceCapability:PublicKeys:genuine-join"] = Convert.ToBase64String(signing.ExportSubjectPublicKeyInfo()),
            ["IAM:LivePermissionChecks:AllowedServices:0"] = "QuotationService",
            ["IAM:LivePermissionChecks:CredentialHashes:QuotationService"] = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(liveKey)))
        })
        {
            builder.UseSetting(setting.Key, setting.Value);
        }
        builder.ConfigureServices(services =>
        {
            string[] disabled = ["IAMInitializationHostedService", "IAMInfrastructureSeederHostedService", "BackgroundIAMRegistrationService", "MassTransitHostedService"];
            foreach (var descriptor in services.Where(d => d.ServiceType == typeof(IHostedService)
                && disabled.Contains(d.ImplementationType?.Name)).ToArray())
            {
                services.Remove(descriptor);
            }
        });
    }

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Legacy.Maliev.AuthService.slnx"))) return directory.FullName;
        }
        throw new InvalidOperationException("The owned acceptance source root was not found.");
    }
}
