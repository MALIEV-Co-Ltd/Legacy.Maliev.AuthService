using System.Xml.Linq;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class RuntimeDependencyGraphContractTests
{
    private static readonly IReadOnlyDictionary<string, string> ExpectedRuntimeFloors =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Asp.Versioning.Mvc.ApiExplorer"] = "10.2.1",
            ["MassTransit.Abstractions"] = "9.2.1",
            ["MassTransit.RabbitMQ"] = "9.2.1",
            ["Microsoft.AspNetCore.Authentication.JwtBearer"] = "10.0.11",
            ["Microsoft.AspNetCore.OpenApi"] = "10.0.11",
            ["Microsoft.EntityFrameworkCore.Design"] = "10.0.11",
            ["Microsoft.Extensions.Caching.StackExchangeRedis"] = "10.0.11",
            ["Microsoft.Extensions.Diagnostics.HealthChecks.EntityFrameworkCore"] = "10.0.11",
            ["Microsoft.Extensions.Http.Resilience"] = "10.9.0",
            ["Microsoft.Extensions.ServiceDiscovery"] = "10.9.0",
            ["Microsoft.OpenApi"] = "2.12.2",
            ["Npgsql.EntityFrameworkCore.PostgreSQL"] = "10.0.3",
            ["OpenTelemetry.Exporter.OpenTelemetryProtocol"] = "1.18.0",
            ["OpenTelemetry.Extensions.Hosting"] = "1.18.0",
            ["OpenTelemetry.Instrumentation.AspNetCore"] = "1.18.0",
            ["OpenTelemetry.Instrumentation.Http"] = "1.18.0",
            ["OpenTelemetry.Instrumentation.Runtime"] = "1.18.0",
            ["Scalar.AspNetCore"] = "2.17.2",
            ["System.IdentityModel.Tokens.Jwt"] = "8.22.0",
        };

    [Fact]
    public void ApiProject_PinsTheValidatedServiceDefaultsRuntimeFloors()
    {
        var packageVersions = ReadPackageVersions(Path.Combine(
            FindRepositoryRoot(),
            "Legacy.Maliev.AuthService.Api",
            "Legacy.Maliev.AuthService.Api.csproj"));

        Assert.All(
            ExpectedRuntimeFloors,
            expected => Assert.Equal(expected.Value, packageVersions[expected.Key]));
    }

    [Fact]
    public void ApiProject_MatchesTheCheckedOutServiceDefaultsGraph()
    {
        var root = FindRepositoryRoot();
        var apiVersions = ReadPackageVersions(Path.Combine(
            root,
            "Legacy.Maliev.AuthService.Api",
            "Legacy.Maliev.AuthService.Api.csproj"));
        var serviceDefaultsVersions = ReadPackageVersions(FindServiceDefaultsProject(root));

        Assert.All(
            ExpectedRuntimeFloors.Where(expected => serviceDefaultsVersions.ContainsKey(expected.Key)),
            expected => Assert.Equal(serviceDefaultsVersions[expected.Key], apiVersions[expected.Key]));
    }

    private static IReadOnlyDictionary<string, string> ReadPackageVersions(string projectPath)
    {
        var project = XDocument.Load(projectPath);

        return project
            .Descendants("PackageReference")
            .Where(reference => reference.Attribute("Version") is not null)
            .ToDictionary(
                reference => reference.Attribute("Include")?.Value
                    ?? throw new InvalidDataException($"PackageReference in {projectPath} has no Include attribute."),
                reference => reference.Attribute("Version")!.Value,
                StringComparer.Ordinal);
    }

    private static string FindServiceDefaultsProject(string repositoryRoot)
    {
        const string relativeProjectPath =
            "Legacy.Maliev.ServiceDefaults/src/Legacy.Maliev.ServiceDefaults/Legacy.Maliev.ServiceDefaults.csproj";
        var workspaceRoot = Environment.GetEnvironmentVariable("MalievWorkspaceRoot");
        var candidates = new[]
        {
            workspaceRoot is null ? null : Path.Combine(workspaceRoot, relativeProjectPath),
            Path.Combine(repositoryRoot, ".dependencies", relativeProjectPath),
            Path.GetFullPath(Path.Combine(repositoryRoot, "..", relativeProjectPath)),
            Path.GetFullPath(Path.Combine(repositoryRoot, "..", "..", relativeProjectPath)),
        };

        return candidates.FirstOrDefault(candidate => candidate is not null && File.Exists(candidate))
            ?? throw new FileNotFoundException("The checked-out Legacy.Maliev.ServiceDefaults project was not found.");
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Legacy.Maliev.AuthService.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root was not found.");
    }
}
