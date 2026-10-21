using System.Net;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>
/// Verifies environment-specific CORS configuration without treating preflight permission as authentication.
/// </summary>
public sealed class CorsHttpContractTests
{
    /// <summary>
    /// Verifies registered development origins receive preflight permission without application authority.
    /// </summary>
    /// <param name="origin">The request origin tested against the configured CORS or IAM origin policy.</param>
    /// <returns>A task that completes after the regression assertions finish.</returns>
    [Theory]
    [InlineData("https://maliev.com")]
    [InlineData("https://www.maliev.com")]
    [InlineData("http://localhost:3000")]
    public async Task Development_RegisteredOriginsAllowPreflightWithoutGrantingAuthority(string origin)
    {
        await using var factory = new CorsFactory(Environments.Development);
        using var client = OpenClient(factory);
        foreach (var path in new[] { "/customers/v1/validate", "/Employees/v1/validate" })
        {
            using var request = Preflight(path, origin);
            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            AssertCors(response, origin, allowed: true);
            Assert.Contains("POST", response.Headers.GetValues("Access-Control-Allow-Methods"));
            Assert.Contains("content-type", response.Headers.GetValues("Access-Control-Allow-Headers"));
            Assert.Empty(await response.Content.ReadAsByteArrayAsync());
            AssertNoAuthority(response);
        }

        await AssertUnauthenticatedAsync(client, origin, allowed: true);
    }

    /// <summary>
    /// Verifies unlisted development origins receive neither CORS permission nor application authority.
    /// </summary>
    /// <param name="origin">The request origin tested against the configured CORS or IAM origin policy.</param>
    /// <returns>A task that completes after the regression assertions finish.</returns>
    [Theory]
    [InlineData("http://maliev.com")]
    [InlineData("http://www.maliev.com")]
    [InlineData("https://crm.maliev.com")]
    [InlineData("https://maliev.com.attacker.invalid")]
    [InlineData("https://www.maliev.com.attacker.invalid")]
    [InlineData("http://localhost:3001")]
    public async Task Development_UnlistedOriginsReceiveNoCorsPermissionOrAuthority(string origin)
    {
        await using var factory = new CorsFactory(Environments.Development);
        using var client = OpenClient(factory);
        using var request = Preflight("/customers/v1/validate", origin);
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        AssertCors(response, origin, allowed: false);
        AssertNoAuthority(response);

        await AssertUnauthenticatedAsync(client, origin, allowed: false);
    }

    /// <summary>
    /// Verifies explicit scalar or array configuration replaces development origin defaults.
    /// </summary>
    /// <param name="array">Whether explicit origins are supplied through indexed array configuration.</param>
    /// <returns>A task that completes after the regression assertions finish.</returns>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Development_ExplicitScalarOrArrayProviderReplacesDefaultOrigins(bool array)
    {
        await using var factory = new CorsFactory(Environments.Development, "https://maliev.com", array);
        using var client = OpenClient(factory);
        foreach (var (origin, allowed) in new[]
        {
            ("https://maliev.com", true),
            ("https://www.maliev.com", false),
            ("http://localhost:3000", false),
        })
        {
            using var request = Preflight("/Employees/v1/validate", origin);
            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            AssertCors(response, origin, allowed);
            AssertNoAuthority(response);
        }
    }

    /// <summary>
    /// Verifies production admits only explicitly configured origins rather than development defaults.
    /// </summary>
    /// <param name="origin">The request origin tested against the configured CORS or IAM origin policy.</param>
    /// <param name="allowed">Whether the configured origin is expected to receive CORS permission.</param>
    /// <returns>A task that completes after the regression assertions finish.</returns>
    [Theory]
    [InlineData("https://maliev.com", true)]
    [InlineData("https://www.maliev.com", false)]
    [InlineData("http://localhost:3000", false)]
    public async Task Production_LoadsOnlyExplicitOriginsWithoutDevelopmentDefaults(string origin, bool allowed)
    {
        await using var factory = new CorsFactory(Environments.Production, "https://maliev.com");
        using var client = OpenClient(factory);
        Assert.Equal(Environments.Production, factory.Services.GetRequiredService<IHostEnvironment>().EnvironmentName);
        using var request = Preflight("/customers/v1/validate", origin);
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        AssertCors(response, origin, allowed);
        AssertNoAuthority(response);

        await AssertUnauthenticatedAsync(client, origin, allowed);
    }

    /// <summary>
    /// Verifies missing origin configuration fails closed outside development.
    /// </summary>
    /// <param name="environment">The nondevelopment hosting environment whose missing configuration must fail closed.</param>
    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public void NonDevelopment_MissingOriginsStillFailClosed(string environment)
    {
        var builder = new HostApplicationBuilder(new HostApplicationBuilderSettings
        {
            DisableDefaults = true,
            EnvironmentName = environment,
        });
        AddOwnerJson(builder.Configuration, environment);
        Assert.Null(builder.Configuration["CORS:AllowedOrigins"]);
        Assert.Empty(builder.Configuration.GetSection("CORS:AllowedOrigins").GetChildren());

        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddStandardCors());

        Assert.Contains("CORS origins not configured.", exception.Message, StringComparison.Ordinal);
    }

    private static HttpClient OpenClient(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
        });
        client.Timeout = TimeSpan.FromSeconds(15);
        return client;
    }

    private static HttpRequestMessage Preflight(string path, string origin)
    {
        var request = new HttpRequestMessage(HttpMethod.Options, path);
        request.Headers.Add("Origin", origin);
        request.Headers.Add("Access-Control-Request-Method", "POST");
        request.Headers.Add("Access-Control-Request-Headers", "content-type");
        return request;
    }

    private static async Task AssertUnauthenticatedAsync(HttpClient client, string origin, bool allowed)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/auth/v1/employee-identities/1");
        request.Headers.Add("Origin", origin);
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate, header => header.Scheme == "Bearer");
        AssertCors(response, origin, allowed);
        AssertNoAuthority(response);
    }

    private static void AssertCors(HttpResponseMessage response, string origin, bool allowed)
    {
        if (allowed)
        {
            Assert.Equal(origin, Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
            Assert.Equal("true", Assert.Single(response.Headers.GetValues("Access-Control-Allow-Credentials")));
        }
        else
        {
            Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
            Assert.False(response.Headers.Contains("Access-Control-Allow-Credentials"));
        }
    }

    private static void AssertNoAuthority(HttpResponseMessage response)
    {
        Assert.False(response.Headers.Contains("Set-Cookie"));
        Assert.False(response.Headers.Contains("Authorization"));
    }

    private static void AddOwnerJson(IConfigurationBuilder configuration, string environment)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Legacy.Maliev.AuthService.slnx")))
            directory = directory.Parent;
        var root = directory?.FullName ?? throw new DirectoryNotFoundException("Auth repository root was not found.");
        var api = Path.Combine(root, "Legacy.Maliev.AuthService.Api");
        configuration.AddJsonFile(Path.Combine(api, "appsettings.json"), optional: false, reloadOnChange: false)
            .AddJsonFile(Path.Combine(api, $"appsettings.{environment}.json"), optional: true, reloadOnChange: false);
    }

    private sealed class CorsFactory(string environment, string? origins = null, bool array = false)
        : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment(environment);
            // Host settings become entry-point arguments before Program eagerly registers the CORS policy.
            if (origins is not null)
                builder.UseSetting(array ? "CORS:AllowedOrigins:0" : "CORS:AllowedOrigins", origins);
            builder.ConfigureLogging(logging => logging.ClearProviders());
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                // Isolate ambient runner configuration; consume the owner's real environment JSON and normal provider order.
                configuration.Sources.Clear();
                AddOwnerJson(configuration, environment);
                using var signing = RSA.Create(2048);
                var settings = new Dictionary<string, string?>
                {
                    ["ConnectionStrings:CustomerIdentity"] = "Host=127.0.0.1;Port=1;Database=unused;Username=fixture;Pooling=false",
                    ["ConnectionStrings:EmployeeIdentity"] = "Host=127.0.0.1;Port=1;Database=unused;Username=fixture;Pooling=false",
                    ["ConnectionStrings:RefreshSessions"] = "Host=127.0.0.1;Port=1;Database=unused;Username=fixture;Pooling=false",
                    ["Jwt:Issuer"] = "https://cors-fixture.invalid",
                    ["Jwt:Audience"] = "cors-fixture",
                    ["Jwt:PrivateKeyPem"] = signing.ExportPkcs8PrivateKeyPem(),
                    ["Jwt:KeyId"] = "cors-fixture",
                    ["EmployeeRecovery:Enabled"] = "false",
                    ["Observability:TracingEnabled"] = "false",
                    ["Observability:RuntimeMetricsEnabled"] = "false",
                    ["OTEL_EXPORTER_OTLP_ENDPOINT"] = "",
                };
                if (origins is not null)
                    settings[array ? "CORS:AllowedOrigins:0" : "CORS:AllowedOrigins"] = origins;
                configuration.AddInMemoryCollection(settings);
            });
            builder.ConfigureServices(services => services.Configure<HostOptions>(options =>
            {
                options.StartupTimeout = TimeSpan.FromSeconds(20);
                options.ShutdownTimeout = TimeSpan.FromSeconds(10);
            }));
        }
    }
}
