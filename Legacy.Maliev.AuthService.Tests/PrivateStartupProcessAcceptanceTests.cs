using System.Diagnostics;
using System.Text.Json;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class PrivateStartupProcessAcceptanceTests(Xunit.Abstractions.ITestOutputHelper testOutput)
{
    [Fact]
    public async Task ProductionStartup_MissingRuntimeConfiguration_EmitsOnePrivateFailureAndExitsNonzero()
    {
        var start = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(typeof(Program).Assembly.Location)!,
        };
        start.ArgumentList.Add("exec");
        var testAssembly = typeof(PrivateStartupProcessAcceptanceTests).Assembly.Location;
        start.ArgumentList.Add("--runtimeconfig");
        start.ArgumentList.Add(Path.ChangeExtension(testAssembly, ".runtimeconfig.json"));
        start.ArgumentList.Add("--depsfile");
        start.ArgumentList.Add(Path.ChangeExtension(testAssembly, ".deps.json"));
        start.ArgumentList.Add(typeof(Program).Assembly.Location);
        // A minimal allowlist prevents inherited production configuration from reaching
        // this deliberately broken startup. No database or HTTP request is issued.
        start.Environment.Clear();
        foreach (var name in new[] { "PATH", "SystemRoot", "TEMP", "TMP", "DOTNET_ROOT" })
        {
            var value = Environment.GetEnvironmentVariable(name);
            if (value is not null) start.Environment[name] = value;
        }
        start.Environment["ASPNETCORE_ENVIRONMENT"] = "Production";
        start.Environment["DOTNET_ENVIRONMENT"] = "Production";
        start.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        start.Environment["OTEL_SDK_DISABLED"] = "true";
        using var process = new Process { StartInfo = start };
        Assert.True(process.Start());
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await process.WaitForExitAsync(timeout.Token);
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
        }
        var output = await stdout + "\n" + await stderr;
        testOutput.WriteLine($"Production child exit code: {process.ExitCode}");
        testOutput.WriteLine(output);
        Assert.NotEqual(0, process.ExitCode);
        var failures = new List<JsonDocument>();
        try
        {
            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                if (!line.TrimStart().StartsWith('{')) continue;
                var document = JsonDocument.Parse(line);
                if (document.RootElement.TryGetProperty("EventName", out var name)
                    && name.GetString() == "StartupFailure") failures.Add(document);
                else document.Dispose();
            }
            var failure = Assert.Single(failures);
            Assert.Equal("HostInitialization", failure.RootElement.GetProperty("Operation").GetString());
            Assert.Equal("CRITICAL", failure.RootElement.GetProperty("severity").GetString());
            Assert.Equal(5102, failure.RootElement.GetProperty("eventId").GetInt32());
            Assert.DoesNotContain("Unhandled exception", output, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(" at ", output, StringComparison.Ordinal);
            Assert.DoesNotContain("ConnectionStrings__", output, StringComparison.Ordinal);
            Assert.DoesNotContain("ConnectionStrings:", output, StringComparison.Ordinal);
            Assert.DoesNotContain("PrivateKeyPem", output, StringComparison.Ordinal);
        }
        finally
        {
            foreach (var failure in failures) failure.Dispose();
        }
    }
}
