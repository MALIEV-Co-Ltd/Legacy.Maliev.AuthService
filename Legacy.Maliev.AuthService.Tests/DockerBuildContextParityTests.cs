using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit.Abstractions;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>
/// Checks retained Docker context exclusions against real BuildKit while preserving actual Auth and pinned dependency input bytes.
/// </summary>
/// <param name="output">The test output sink for bounded tooling version and executable-digest provenance only.</param>
public sealed class DockerBuildContextParityTests(ITestOutputHelper output)
{
    /// <summary>
    /// Checks local Docker endpoint admission without launching a Docker client.
    /// </summary>
    /// <param name="endpoint">The candidate local socket, named pipe, remote endpoint, or malformed endpoint.</param>
    /// <param name="allowed">Whether the exact endpoint shape is admitted for the context regression.</param>
    [Theory]
    [InlineData("unix:///var/run/docker.sock", true)]
    [InlineData("unix:///run/docker.sock", true)]
    [InlineData("npipe:////./pipe/dockerDesktopLinuxEngine", true)]
    [InlineData("npipe:////./pipe/docker_engine", true)]
    [InlineData("tcp://127.0.0.1:2375", false)]
    [InlineData("tcp://remote.example:2376", false)]
    [InlineData("npipe:////remote/pipe/docker_engine", false)]
    [InlineData("npipe:////./pipe/docker_engine/extra", false)]
    [InlineData("npipe:////./pipe/docker_engine?query", false)]
    [InlineData(null, false)]
    public void RemoteOrMalformedEndpoints_AreRejectedBeforeBuild(string? endpoint, bool allowed)
    {
        Assert.Equal(allowed, IsLocalEndpoint(endpoint));
    }

    /// <summary>
    /// Admits only unambiguous default-builder Docker driver headers from supported buildx inspect output.
    /// </summary>
    /// <param name="inspection">The bounded synthetic inspect output, including header and node-section controls.</param>
    /// <param name="allowed">Whether the top-level builder identity and driver are admitted.</param>
    [Theory]
    [InlineData("Name:    default\nDriver:  docker\n\nNodes:\nName: another-node\nEndpoint: unix:///var/run/docker.sock\n", true)]
    [InlineData("Name:\tdefault\r\nDriver:\tdocker\r\nLast Activity: 2026-10-22 00:00:00 +0000 UTC\r\n\r\nNodes:\r\nName: default\r\n", true)]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("Name: other\nDriver: docker\nNodes:\n", false)]
    [InlineData("Name: default\nDriver: docker-container\nNodes:\n", false)]
    [InlineData("Name: default\nDriver: remote\nNodes:\n", false)]
    [InlineData("Name: default\nDriver: Docker\nNodes:\n", false)]
    [InlineData("Name: default *\nDriver: docker\nNodes:\n", false)]
    [InlineData("Name: default\nName: default\nDriver: docker\nNodes:\n", false)]
    [InlineData("Name: default\nDriver: docker\nDriver: docker\nNodes:\n", false)]
    [InlineData("Driver: docker\nNodes:\nName: default\n", false)]
    [InlineData("Name: default\nNodes:\nDriver: docker\n", false)]
    [InlineData("Nodes:\nName: default\nDriver: docker\n", false)]
    [InlineData("Name: default\nDriver: docker\n", false)]
    [InlineData("Name: default\nDriver: docker\nError: synthetic status failure\n", false)]
    [InlineData("Name: default\nDriver: docker\nError: synthetic status failure\nNodes:\n", false)]
    [InlineData(" Name: default\n Driver: docker\nNodes:\n", false)]
    [InlineData("Name: default\nDriver : docker\nNodes:\n", false)]
    [InlineData("Name: default\nDriver: docker\nNodes: not-a-section\n", false)]
    [InlineData("Name: default\nDriver: docker\u001b\nNodes:\n", false)]
    [InlineData("Name: default\nDriver: docker\nUnexpected: value\nNodes:\n", false)]
    public void BuildxInspection_RequiresUnambiguousTopLevelDefaultDocker(string? inspection, bool allowed)
    {
        Assert.Equal(allowed, IsDefaultDockerBuilderInspection(inspection));
    }

    /// <summary>
    /// Refuses an oversized inspect result even when its prefix contains otherwise valid builder headers.
    /// </summary>
    [Fact]
    public void BuildxInspection_RefusesOutputBeyondExistingCommandBudget()
    {
        var inspection = "Name: default\nDriver: docker\nNodes:\n" + new string('x', 16384);
        Assert.False(IsDefaultDockerBuilderInspection(inspection));
    }

    /// <summary>
    /// Checks every retained exclusion category with real Docker COPY and compares admitted build inputs byte for byte.
    /// </summary>
    /// <returns>A task that completes after Docker context assertions and owned scratch cleanup.</returns>
    [Fact]
    public async Task ActualDockerContext_ExcludesRetainedArtifactsAndPreservesBuildInputs()
    {
        var endpoint = await LocalEndpointAsync();
        var version = (await DockerAsync("--host", endpoint, "version", "--format", "{{.Client.Version}}")).Trim();
        var buildx = (await DockerAsync("--host", endpoint, "buildx", "version")).Trim();
        Assert.InRange(version.Length, 1, 128);
        Assert.InRange(buildx.Length, 1, 256);
        Assert.All(version.Concat(buildx), character => Assert.True(
            char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_' or '/' or '+' or ' ',
            "Docker tooling provenance contained non-version text; raw output withheld."));
        using (var executable = File.OpenRead(ResolveDockerExecutable()))
        {
            var digest = await SHA256.HashDataAsync(executable);
            output.WriteLine("Docker client version: " + version);
            output.WriteLine("Buildx version: " + buildx);
            output.WriteLine("Docker executable SHA256: " + Convert.ToHexString(digest));
        }
        var inspection = await DockerAsync("--host", endpoint, "buildx", "inspect", "default");
        Assert.True(IsDefaultDockerBuilderInspection(inspection),
            "Only the unambiguous default Docker builder is admitted; raw inspection withheld.");
        var root = FindRepositoryRoot();
        var owned = Path.Combine(Path.GetTempPath(), "auth-docker-context-" + Guid.NewGuid().ToString("N"));
        var input = Path.Combine(owned, "input");
        var exportDirectory = Path.Combine(owned, "output");
        Exception? primaryFailure = null;
        try
        {
            Directory.CreateDirectory(input);
            File.Copy(Path.Combine(root, ".dockerignore"), Path.Combine(input, ".dockerignore"));
            await File.WriteAllTextAsync(Path.Combine(input, "Dockerfile"), "FROM scratch\nCOPY . /context/\n");

            var dependencies = Environment.GetEnvironmentVariable("MalievWorkspaceRoot");
            if (string.IsNullOrEmpty(dependencies)) dependencies = Path.GetDirectoryName(root)!;
            string[] projects =
            [
                "Legacy.Maliev.AuthService.Api",
                "Legacy.Maliev.AuthService.Application",
                "Legacy.Maliev.AuthService.Domain",
                "Legacy.Maliev.AuthService.Infrastructure",
            ];
            var included = new List<(string Source, string Relative)>
            {
                (Path.Combine(root, "Directory.Build.props"), "Directory.Build.props"),
                (Path.Combine(root, "nuget.config"), "nuget.config"),
            };
            foreach (var project in projects)
            {
                foreach (var path in SourceFiles(Path.Combine(root, project)))
                    included.Add((path, Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/')));
            }
            // The production Dockerfile clones these pinned repositories outside its COPY context.
            // Their checked-out inputs are additional nested-context custody controls, not a substitute image build.
            foreach (var dependency in new[] { "Legacy.Maliev.ServiceDefaults", "Legacy.Maliev.CompatibilityContracts" })
            {
                var checkout = Path.Combine(dependencies, dependency);
                foreach (var name in new[] { "Directory.Build.props", "global.json", "nuget.config", "README.md" })
                    included.Add((Path.Combine(checkout, name), ".dependencies/" + dependency + "/" + name));
                foreach (var path in SourceFiles(Path.Combine(checkout, "src")))
                    included.Add((path, ".dependencies/" + dependency + "/" +
                        Path.GetRelativePath(checkout, path).Replace(Path.DirectorySeparatorChar, '/')));
            }
            Assert.Equal(included.Count, included.Select(file => file.Relative).Distinct(StringComparer.Ordinal).Count());
            foreach (var file in included)
            {
                var destination = Path.Combine(input, file.Relative);
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.Copy(file.Source, destination);
            }

            string[] categories =
            [
                ".git/config", ".gitignore", ".github/workflow.yml", ".vscode/settings.json",
                ".vs/state", ".idea/workspace.xml", "bin/output.dll", "obj/generated.cs",
                "out/output.txt", "node_modules/package/index.js", "dist/bundle.js",
                "coverage/data.xml", "TestResults/result.trx", "private.suo", "private.user",
                "private.csproj.user", "private.cache", "private.log", "private.tmp",
                "private.nupkg", "private.swp", "private.swo", "private.env", ".env",
                ".env.synthetic", "private.ps1", "private.cmd", "private.sh",
                "private.yml", "private.yaml",
            ];
            string[] excluded =
            [
                .. categories,
                .. categories.Select(path => "nested/" + path),
                // A root Dockerfile.dockerignore would override the actual policy under test.
                "nested/Dockerfile.dockerignore",
                "artifacts/report.json",
                "deploy/base/deployment.yaml",
            ];
            Assert.DoesNotContain(included, file => excluded.Contains(file.Relative, StringComparer.Ordinal));
            foreach (var path in excluded)
            {
                var destination = Path.Combine(input, path);
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                await File.WriteAllTextAsync(destination, "SYNTHETIC_CONTEXT_EXCLUSION_SENTINEL");
            }
            await DockerAsync("--host", endpoint, "build", "--builder", "default",
                "--network=none", "--no-cache", "--progress=quiet",
                "--output", "type=local,dest=" + exportDirectory, "--file", Path.Combine(input, "Dockerfile"), input);
            foreach (var file in included)
            {
                var expected = await File.ReadAllBytesAsync(file.Source);
                var copied = await File.ReadAllBytesAsync(Path.Combine(exportDirectory, "context", file.Relative));
                Assert.True(expected.SequenceEqual(copied), $"Required build input changed at COPY: {file.Relative}");
            }
            Assert.DoesNotContain(excluded, path => File.Exists(Path.Combine(exportDirectory, "context", path)));
        }
        catch (Exception exception)
        {
            primaryFailure = exception;
            throw;
        }
        finally
        {
            try
            {
                if (Directory.Exists(owned)) Directory.Delete(owned, recursive: true);
            }
            catch (Exception cleanupFailure) when (primaryFailure is not null)
            {
                throw new AggregateException("Owned Docker context scratch cleanup failed.", primaryFailure, cleanupFailure);
            }
        }
    }

    private static IEnumerable<string> SourceFiles(string directory) =>
        Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
            .Where(path => !Path.GetRelativePath(directory, path).Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                .Any(segment => segment is "bin" or "obj"))
            .Where(path => Path.GetExtension(path) is ".cs" or ".csproj" or ".json" or ".resx");

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Legacy.Maliev.AuthService.slnx")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException("Auth test repository root is unavailable.");
    }

    private static async Task<string> LocalEndpointAsync()
    {
        var configured = Environment.GetEnvironmentVariable("DOCKER_HOST");
        if (!string.IsNullOrEmpty(configured))
        {
            Assert.True(IsLocalEndpoint(configured), "Remote Docker endpoint refused before build.");
            return configured;
        }
        var context = (await DockerAsync("context", "show")).Trim();
        using var document = JsonDocument.Parse(await DockerAsync("context", "inspect", context));
        var endpoint = document.RootElement[0].GetProperty("Endpoints").GetProperty("docker").GetProperty("Host").GetString();
        Assert.True(IsLocalEndpoint(endpoint), "Non-local Docker context refused before build.");
        return endpoint!;
    }

    private static bool IsDefaultDockerBuilderInspection(string? inspection)
    {
        if (string.IsNullOrEmpty(inspection) || inspection.Length > 16384
            || inspection.Any(character => char.IsControl(character) && character is not ('\r' or '\n' or '\t')))
            return false;

        string? name = null;
        string? driver = null;
        foreach (var rawLine in inspection.Split('\n'))
        {
            var line = rawLine.EndsWith('\r') ? rawLine[..^1] : rawLine;
            if (line == "Nodes:") return name == "default" && driver == "docker";
            if (line.StartsWith("Name:", StringComparison.Ordinal))
            {
                if (name is not null) return false;
                name = line["Name:".Length..].Trim(' ', '\t');
            }
            else if (line.StartsWith("Driver:", StringComparison.Ordinal))
            {
                if (driver is not null) return false;
                driver = line["Driver:".Length..].Trim(' ', '\t');
            }
            else if (line.StartsWith("Error:", StringComparison.Ordinal)
                || line.Length != 0 && !line.StartsWith("Last Activity:", StringComparison.Ordinal))
            {
                return false;
            }
        }
        return false;
    }

    private static bool IsLocalEndpoint(string? endpoint)
    {
        const string prefix = "npipe:////./pipe/";
        return endpoint is not null && endpoint.StartsWith(prefix, StringComparison.Ordinal)
            && endpoint.Length > prefix.Length
            && endpoint[prefix.Length..].All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or '.')
            || endpoint is "unix:///var/run/docker.sock" or "unix:///run/docker.sock";
    }

    private static async Task<string> DockerAsync(params string[] arguments)
    {
        var executable = ResolveDockerExecutable();
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
        };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        if (arguments.Contains("--host", StringComparer.Ordinal))
        {
            foreach (var name in new[] { "DOCKER_HOST", "DOCKER_CONTEXT", "BUILDX_BUILDER", "BUILDKIT_HOST" })
                start.Environment.Remove(name);
        }
        var result = await OwnedDockerCommand.RunAsync(start, TimeSpan.FromSeconds(60));
        Assert.True(result.ExitCode == 0, $"Docker context prerequisite/build failed, exit {result.ExitCode}; raw output withheld.");
        return result.StandardOutput;
    }

    private static string ResolveDockerExecutable()
    {
        var name = OperatingSystem.IsWindows() ? "docker.exe" : "docker";
        foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(directory)) continue;
            var path = Path.GetFullPath(Path.Combine(directory, name));
            if (File.Exists(path)) return path;
        }
        throw new FileNotFoundException("The trusted Docker client is unavailable.");
    }
}
