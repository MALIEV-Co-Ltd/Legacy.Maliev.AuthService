using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.AuthService.GenuineIamHttp.Tests;

/// <summary>Owns the genuine IAM HTTP host with its independent dependency graph.</summary>
public sealed class OwnedIamProcess
{
    private Process? process;
    private readonly CancellationTokenSource readers = new();
    private readonly TaskCompletionSource<Uri> ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task output = Task.CompletedTask;
    private Task<string> error = Task.FromResult(string.Empty);
    private Func<object, CancellationToken, Task>? record;
    private DateTime startedAtUtc;
    private bool disposedByHost;
    /// <summary>Gets the actual loopback Kestrel address.</summary>
    public Uri BaseAddress { get; private set; } = null!;

    /// <summary>Starts only the prebuilt exact-source IAM graph; credentials travel through its private environment.</summary>
    public async Task StartAsync(string repository, string connection, string privatePem, Guid principal, string permission, string liveKey,
        Func<object, CancellationToken, Task> receipt, CancellationToken cancellationToken)
    {
        record = receipt;
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = repository,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add(Path.Combine(repository, "acceptance", "GenuineIamHost", "bin", "Release", "net10.0", "GenuineIamHost.dll"));
        start.Environment["GENUINE_IAM_CONNECTION"] = connection;
        start.Environment["GENUINE_IAM_PRIVATE_PEM"] = privatePem;
        start.Environment["GENUINE_IAM_PRINCIPAL_ID"] = principal.ToString("D");
        start.Environment["GENUINE_IAM_PERMISSION_ID"] = permission;
        start.Environment["GENUINE_IAM_LIVE_KEY"] = liveKey;
        process = Process.Start(start) ?? throw new InvalidOperationException("Owned IAM process failed to start.");
        startedAtUtc = process.StartTime.ToUniversalTime();
        output = ReadProtocolAsync(process.StandardOutput, readers.Token);
        error = BoundedProcessOutput.ReadAsync(process.StandardError, 65536, readers.Token);
        await receipt(new { processId = process.Id, startedAtUtc, executable = "dotnet", state = "started", leaseMinutes = 10 }, cancellationToken);
        var exit = process.WaitForExitAsync(cancellationToken);
        var completed = await Task.WhenAny(ready.Task, output, error, exit).WaitAsync(cancellationToken);
        if (completed != ready.Task)
        {
            if (completed.IsFaulted) await completed;
            throw new InvalidOperationException("Owned IAM host did not provide its validated ready receipt.");
        }
        BaseAddress = await ready.Task;
    }

    private async Task ReadProtocolAsync(TextReader stream, CancellationToken cancellationToken)
    {
        var line = new StringBuilder();
        var buffer = new char[1024];
        var total = 0;
        while (true)
        {
            var count = await stream.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (count == 0) return;
            total += count;
            if (total > 65536) throw new InvalidOperationException("Owned IAM output limit exceeded.");
            foreach (var character in buffer.AsSpan(0, count))
            {
                if (character != '\n') { line.Append(character); continue; }
                var value = line.ToString().TrimEnd('\r');
                line.Clear();
                if (value.StartsWith("GENUINE_IAM_READY=", StringComparison.Ordinal))
                {
                    using var json = JsonDocument.Parse(value[18..]);
                    var address = new Uri(json.RootElement.GetProperty("baseAddress").GetString()!);
                    if (address.Scheme != "http" || address.Host != "127.0.0.1" || address.Port <= 0
                        || !json.RootElement.GetProperty("seeded").GetBoolean()
                        || !json.RootElement.GetProperty("jwtValidationPreserved").GetBoolean())
                        throw new InvalidOperationException("Owned IAM ready receipt is invalid.");
                    ready.TrySetResult(address);
                }
                else if (value.StartsWith("GENUINE_IAM_STOPPED=", StringComparison.Ordinal))
                {
                    using var json = JsonDocument.Parse(value[20..]);
                    disposedByHost = json.RootElement.GetProperty("disposed").GetBoolean();
                }
            }
        }
    }

    /// <summary>Requests finite graceful disposal, then reaps the exact owned process and settles its readers.</summary>
    public async Task DisposeAsync(CancellationToken cancellationToken)
    {
        if (process is null) { readers.Dispose(); return; }
        List<Exception> failures = [];
        var graceful = false;
        try
        {
            if (!process.HasExited)
            {
                await process.StandardInput.WriteLineAsync("stop".AsMemory(), cancellationToken);
                await process.StandardInput.FlushAsync(cancellationToken);
                await process.WaitForExitAsync(cancellationToken).WaitAsync(TimeSpan.FromSeconds(20), cancellationToken);
            }
            graceful = process.ExitCode == 0;
        }
        catch (Exception) { /* Exact handle cleanup below always runs; arbitrary output is not retained. */ }
        finally
        {
            var exited = false;
            try
            {
                exited = await BoundedProcessOutput.TerminateAsync(() => process.HasExited, () => process.Kill(entireProcessTree: true),
                    () => process.WaitForExit(5000),
                    async (complete, failed) =>
                    {
                        using var receiptDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(1));
                        await record!(new { processId = process.Id, startedAtUtc, state = "reaped", exited = complete,
                            terminationFailed = failed, remainingOwnership = !complete, exitCode = complete ? (int?)process.ExitCode : null }, receiptDeadline.Token)
                            .WaitAsync(receiptDeadline.Token);
                    });
            }
            catch (Exception) { Fail("terminate-or-receipt"); }
            try { exited = process.HasExited; }
            catch (Exception) { Fail("process-absence"); }
            try { await Task.WhenAll(output, error).WaitAsync(TimeSpan.FromSeconds(1)); }
            catch (Exception) { Fail("readers-drain"); }
            finally
            {
                try { readers.Cancel(); }
                catch (Exception) { Fail("readers-cancel"); }
                try { await Task.WhenAll(output, error).WaitAsync(TimeSpan.FromSeconds(1)); }
                catch (OperationCanceledException) when (output.IsCompleted && error.IsCompleted) { }
                catch (Exception) { Fail("readers-settle"); }
                try
                {
                    using var receiptDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(1));
                    await record!(new { state = "disposed", exited, hostDisposed = disposedByHost,
                        readersSettled = output.IsCompleted && error.IsCompleted, remainingOwnership = !exited }, receiptDeadline.Token)
                        .WaitAsync(receiptDeadline.Token);
                }
                catch (Exception) { Fail("disposal-receipt"); }
                try { process.Dispose(); }
                catch (Exception) { Fail("process-handle"); }
                process = null;
                try { readers.Dispose(); }
                catch (Exception) { Fail("readers-handle"); }
            }
            if (!exited || !graceful || !disposedByHost)
                Fail("graceful-disposal-contract");
            if (!output.IsCompleted || !error.IsCompleted) Fail("readers-unsettled");
            if (failures.Count != 0) throw new AggregateException("Owned IAM cleanup failed; inspect fixed ownership receipts.", failures);
        }
        void Fail(string step) => failures.Add(new InvalidOperationException("Owned IAM cleanup incomplete: " + step));
    }
}
