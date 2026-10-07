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
    private StreamReader? outputReader;
    private StreamReader? errorReader;
    private StreamWriter? inputWriter;
    private Task? stopWrite;
    private Task? stopFlush;
    private Task? output;
    private Task<string>? error;
    private Func<object, CancellationToken, Task>? record;
    private DateTime? startedAtUtc;
    private int? processId;
    private bool startAttempted;
    private bool started;
    private bool exited;
    private int? exitCode;
    private bool graceful;
    private bool inputDisposed;
    private bool outputDisposed;
    private bool errorDisposed;
    private bool readersDisposed;
    private bool processDisposed;
    private bool handlesDisposed;
    private bool cleanupFailed;
    private bool ReadersSettled => (output is null || output.IsCompleted) && (error is null || error.IsCompleted);
    private bool InputOperationsSettled => (stopWrite is null || stopWrite.IsCompleted) && (stopFlush is null || stopFlush.IsCompleted);
    private bool disposedByHost;
    /// <summary>Gets whether the exact process exited, acquired readers settled, and every owned handle closed.</summary>
    public bool IsQuiescent => exited && ReadersSettled && InputOperationsSettled && handlesDisposed;

    /// <summary>Gets the actual loopback Kestrel address.</summary>
    public Uri BaseAddress { get; private set; } = null!;

    /// <summary>Starts only the prebuilt exact-source IAM graph; credentials travel through its private environment.</summary>
    public async Task StartAsync(string repository, string connection, string privatePem, Guid principal, string permission, string liveKey,
        Func<object, CancellationToken, Task> receipt, CancellationToken cancellationToken)
    {
        if (process is not null || startAttempted || readersDisposed)
            throw new InvalidOperationException("Owned IAM process cannot be started twice.");
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
        // Register the exact handle before launch or any fallible metadata/reader setup.
        process = new Process { StartInfo = start };
        cancellationToken.ThrowIfCancellationRequested();
        startAttempted = true;
        started = process.Start();
        if (!started) throw new InvalidOperationException("Owned IAM process failed to start.");
        processId = process.Id;
        startedAtUtc = process.StartTime.ToUniversalTime();
        inputWriter = process.StandardInput;
        outputReader = process.StandardOutput;
        output = ReadProtocolAsync(outputReader, readers.Token);
        errorReader = process.StandardError;
        error = BoundedProcessOutput.ReadAsync(errorReader, 65536, readers.Token);
        await receipt(new { processId, startedAtUtc, executable = "dotnet", state = "started", leaseMinutes = 10 }, cancellationToken);
        var exit = process.WaitForExitAsync(cancellationToken);
        var completed = await Task.WhenAny(ready.Task, output!, error!, exit).WaitAsync(cancellationToken);
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

    /// <summary>Requests finite graceful disposal and retains every unresolved process or stream handle.</summary>
    public async Task DisposeAsync(CancellationToken cancellationToken)
    {
        List<Exception> failures = [];
        if (!started && startAttempted && process is not null)
        {
            try { processId = process.Id; started = true; }
            catch (Exception) { Fail("launch-unverified"); }
        }
        if (!startAttempted) exited = true;
        if (started && !processDisposed)
        {
            try
            {
                using var gracefulDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                gracefulDeadline.CancelAfter(TimeSpan.FromSeconds(20));
                if (!process!.HasExited)
                {
                    inputWriter ??= process.StandardInput;
                    stopWrite = inputWriter.WriteLineAsync("stop".AsMemory(), gracefulDeadline.Token);
                    await stopWrite.WaitAsync(gracefulDeadline.Token);
                    stopFlush = inputWriter.FlushAsync(gracefulDeadline.Token);
                    await stopFlush.WaitAsync(gracefulDeadline.Token);
                    await process.WaitForExitAsync(gracefulDeadline.Token).WaitAsync(gracefulDeadline.Token);
                }
                graceful = process.ExitCode == 0;
            }
            catch (Exception) { /* Exact-handle reconciliation always proceeds independently. */ }
            try { if (!process!.HasExited) process.Kill(entireProcessTree: true); }
            catch (Exception) { Fail("terminate"); }
            try { if (!process!.WaitForExit(5000)) Fail("reap"); }
            catch (Exception) { Fail("reap"); }
            try { exited = process!.HasExited; }
            catch (Exception) { Fail("process-absence"); }
            if (exited)
            {
                try { exitCode = process!.ExitCode; }
                catch (Exception) { Fail("exit-code"); }
            }
        }
        else if (startAttempted && !started) exited = false;

        // Allow the stopped receipt to drain before cancelling unfinished reads.
        await Task.WhenAll(SettleAsync(output, "output-drain", false), SettleAsync(error, "error-drain", false));
        if (!readersDisposed)
        {
            try { readers.Cancel(); }
            catch (Exception) { Fail("readers-cancel"); }
        }
        await Task.WhenAll(SettleAsync(output, "output-settle", true), SettleAsync(error, "error-settle", true));
        await Task.WhenAll(SettleAsync(stopWrite, "input-write-settle", true), SettleAsync(stopFlush, "input-flush-settle", true));
        if (!InputOperationsSettled) Fail("input-unsettled");
        if (!exited) Fail("process-unreaped");
        if (!ReadersSettled) Fail("readers-unsettled");

        // Exposed streams belong to this caller; Process.Dispose does not close
        // its caller-exposed SyncMode readers. Never close a live/unsettled lease.
        if (exited && ReadersSettled && InputOperationsSettled)
        {
            Close("input-handle", () => inputWriter?.Dispose(), ref inputDisposed);
            Close("output-handle", () => outputReader?.Dispose(), ref outputDisposed);
            Close("error-handle", () => errorReader?.Dispose(), ref errorDisposed);
            Close("readers-handle", readers.Dispose, ref readersDisposed);
            Close("process-handle", () => process?.Dispose(), ref processDisposed);
            handlesDisposed = inputDisposed && outputDisposed && errorDisposed && readersDisposed && processDisposed;
        }
        if (startAttempted && (!graceful || !disposedByHost)) Fail("graceful-disposal-contract");
        if (!handlesDisposed) Fail("handles-retained");
        cleanupFailed |= failures.Count != 0;
        try
        {
            if (record is not null)
            {
                using var receiptDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(1));
                await record(new
                {
                    processId, startedAtUtc, executable = "dotnet", state = IsQuiescent ? "disposed" : "retained",
                    launchAttempted = startAttempted, started, exited, exitCode, graceful, hostDisposed = disposedByHost,
                    outputReaderStarted = outputReader is not null, errorReaderStarted = errorReader is not null,
                    readersSettled = ReadersSettled, inputOperationsSettled = InputOperationsSettled, inputHandleDisposed = inputDisposed,
                    outputHandleDisposed = outputDisposed, errorHandleDisposed = errorDisposed,
                    readersHandleDisposed = readersDisposed, processHandleDisposed = processDisposed,
                    handlesDisposed, originalCleanupFailure = cleanupFailed, remainingOwnership = !IsQuiescent,
                    leaseMinutes = IsQuiescent ? 0 : 10
                }, receiptDeadline.Token).WaitAsync(receiptDeadline.Token);
            }
        }
        catch (Exception) { Fail("disposition-receipt"); cleanupFailed = true; }
        if (failures.Count != 0 || cleanupFailed)
            throw new AggregateException("Owned IAM cleanup failed; inspect fixed ownership receipts.",
                failures.Count != 0 ? failures : [new InvalidOperationException("Owned IAM cleanup previously failed.")]);

        async Task SettleAsync(Task? task, string step, bool allowCancelled)
        {
            if (task is null) return;
            try { await task.WaitAsync(TimeSpan.FromSeconds(1)); }
            catch (OperationCanceledException) when (allowCancelled && task.IsCompleted) { }
            catch (Exception) { Fail(step); }
        }
        void Close(string step, Action close, ref bool complete)
        {
            if (complete) return;
            try { close(); complete = true; }
            catch (Exception) { Fail(step); }
        }
        void Fail(string step)
        {
            lock (failures) failures.Add(new InvalidOperationException("Owned IAM cleanup incomplete: " + step));
        }
    }
}
