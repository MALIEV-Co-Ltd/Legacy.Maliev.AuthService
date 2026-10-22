using System.Diagnostics;
using System.Text;

namespace Legacy.Maliev.AuthService.Tests;

/// <summary>
/// Exercises the owned Docker command launch boundary with synthetic local commands, including descendant cleanup failures.
/// </summary>
public sealed class OwnedDockerCommandTests
{
    /// <summary>
    /// Preserves the actual command exit status and bounded output rather than the Linux supervisor exit status.
    /// </summary>
    /// <returns>A task that completes after command and owned group or job cleanup.</returns>
    [Fact]
    public async Task CommandExit_PreservesStatusAndDrainsOutput()
    {
        var result = await OwnedDockerCommand.RunAsync(Command("printf owned-output; exit 7", "echo owned-output& exit /b 7"), TimeSpan.FromSeconds(10));
        Assert.Equal(7, result.ExitCode);
        Assert.Equal("owned-output", result.StandardOutput.Trim());
    }

    /// <summary>
    /// Keeps a command cancellation failure while requiring its deliberately long-running descendant to leave the owned boundary.
    /// </summary>
    /// <returns>A task that completes only after the cancellation path verifies an empty owned group or job.</returns>
    [Fact]
    public async Task CommandCancellation_ReleasesOwnedDescendantAndPreservesCancellation()
    {
        var scratch = Path.Combine(Path.GetTempPath(), "auth-docker-command-" + Guid.NewGuid().ToString("N"));
        var acknowledgment = Path.Combine(scratch, "child-started");
        using var cancellation = new CancellationTokenSource();
        Task<OwnedDockerCommand.Result>? command = null;
        Exception? primaryFailure = null;
        var createdScratch = false;
        try
        {
            Directory.CreateDirectory(scratch);
            createdScratch = true;
            var start = DescendantCommand();
            start.Environment["AUTH_DOCKER_CHILD_ACK"] = acknowledgment;
            command = OwnedDockerCommand.RunAsync(start, TimeSpan.FromSeconds(10), cancellation.Token);
            using var observation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (!File.Exists(acknowledgment) && !command.IsCompleted)
                await Task.Delay(20, observation.Token);
            Assert.True(File.Exists(acknowledgment), "The controlled child did not acknowledge startup before cancellation.");
            Assert.Equal("child-started", (await File.ReadAllTextAsync(acknowledgment)).Trim());
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => command!);
        }
        catch (Exception failure)
        {
            primaryFailure = failure;
            throw;
        }
        finally
        {
            var cleanupFailures = new List<Exception>();
            try { cancellation.Cancel(); }
            catch (Exception failure) { cleanupFailures.Add(failure); }
            if (command is not null)
            {
                try { await command; }
                catch (OperationCanceledException) when (cancellation.IsCancellationRequested && command.IsCanceled)
                {
                    // Only the command cancellation requested by this control is an expected cleanup outcome.
                }
                catch (Exception failure) { cleanupFailures.Add(failure); }
            }
            try
            {
                if (createdScratch) Directory.Delete(scratch, recursive: true);
            }
            catch (Exception failure) { cleanupFailures.Add(failure); }
            if (cleanupFailures.Count != 0)
            {
                if (primaryFailure is not null) cleanupFailures.Insert(0, primaryFailure);
                throw new AggregateException("Owned cancellation regression cleanup failed.", cleanupFailures);
            }
        }
    }

    /// <summary>
    /// Refuses oversized command output and releases its owned command boundary without returning raw diagnostics.
    /// </summary>
    /// <returns>A task that completes after output refusal and verified group or job cleanup.</returns>
    [Fact]
    public async Task OutputBudget_ReleasesOwnedCommandAndWithholdsRawDiagnostics()
    {
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => OwnedDockerCommand.RunAsync(
            Command("i=0; while [ \"$i\" -lt 20000 ]; do printf x; i=$((i + 1)); done; sleep 30",
                "for /l %i in (1,1,20000) do @echo x"),
            TimeSpan.FromSeconds(10)));
        Assert.Equal("Docker diagnostic output budget exceeded; raw output withheld.", failure.Message);
    }

    /// <summary>
    /// Escapes Windows argument boundaries without interpreting arguments as a shell command.
    /// </summary>
    /// <param name="value">The empty, spaced, quoted, or trailing-backslash argument.</param>
    /// <param name="quoted">The exact native command-line representation expected by the Windows argument parser.</param>
    [Theory]
    [InlineData("", "\"\"")]
    [InlineData("a b", "\"a b\"")]
    [InlineData("a\"b", "\"a\\\"b\"")]
    [InlineData("a\\", "\"a\\\\\"")]
    public void WindowsArguments_PreserveExactBoundaries(string value, string quoted)
    {
        Assert.Equal(quoted, OwnedDockerCommand.QuoteWindowsArgument(value));
    }

    private static ProcessStartInfo DescendantCommand()
    {
        if (!OperatingSystem.IsWindows())
            return Command("(printf child-started > \"$AUTH_DOCKER_CHILD_ACK.pending\" && /bin/mv -- \"$AUTH_DOCKER_CHILD_ACK.pending\" \"$AUTH_DOCKER_CHILD_ACK\"; sleep 30) & wait", "");
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell", "v1.0", "powershell.exe");
        const string script = """
            $ErrorActionPreference = 'Stop'
            $child = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\ping.exe') -ArgumentList '-n','30','127.0.0.1' -NoNewWindow -PassThru
            try {
                $child.Refresh()
                if ($child.HasExited) { throw 'Controlled child exited before acknowledgment.' }
                $pending = $env:AUTH_DOCKER_CHILD_ACK + '.pending'
                [System.IO.File]::WriteAllText($pending, 'child-started')
                [System.IO.File]::Move($pending, $env:AUTH_DOCKER_CHILD_ACK)
                $child.WaitForExit()
            } finally { $child.Dispose() }
            """;
        var start = new ProcessStartInfo(executable) { UseShellExecute = false };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
            Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) })
            start.ArgumentList.Add(argument);
        return start;
    }

    private static ProcessStartInfo Command(string linux, string windows)
    {
        var executable = OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe")
            : "/bin/sh";
        var start = new ProcessStartInfo(executable) { UseShellExecute = false };
        if (OperatingSystem.IsWindows())
        {
            start.ArgumentList.Add("/d");
            start.ArgumentList.Add("/s");
            start.ArgumentList.Add("/c");
            start.ArgumentList.Add(windows);
        }
        else
        {
            start.ArgumentList.Add("-c");
            start.ArgumentList.Add(linux);
        }
        return start;
    }
}
