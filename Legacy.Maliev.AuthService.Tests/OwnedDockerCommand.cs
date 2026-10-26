using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;

namespace Legacy.Maliev.AuthService.Tests;

internal static class OwnedDockerCommand
{
    private const int OutputLimit = 16384;
    private static readonly TimeSpan CleanupDeadline = TimeSpan.FromSeconds(5);

    internal sealed record Result(int ExitCode, string StandardOutput);

    internal static Task<Result> RunAsync(ProcessStartInfo start, TimeSpan deadline, CancellationToken cancellationToken = default) =>
        OperatingSystem.IsWindows() ? RunWindowsAsync(start, deadline, cancellationToken) : RunLinuxAsync(start, deadline, cancellationToken);

    // Keep the group leader alive after Docker exits: a dispatched buildx child can outlive the CLI.
    // This owns the trusted Docker launch path, not an adversarial executable that changes its session.
    private const string Supervisor = """
        nonce=$1
        shift
        trap '/bin/kill -KILL -- -$$' EXIT
        interrupted=0
        trap 'interrupted=1' TERM
        printf '%s:READY:%s\n' "$nonce" "$$"
        IFS= read -r go || exit 125
        [ "$go" = "$nonce:GO" ] || exit 125
        (trap '' TERM; sleep 70; /bin/kill -KILL -- -$$) </dev/null &
        "$@" </dev/null &
        command=$!
        wait "$command"
        status=$?
        printf '\n%s:DONE:%s\n' "$nonce" "$status"
        while :; do
            interrupted=0
            IFS= read -r release
            status=$?
            [ "$interrupted" -eq 1 ] && continue
            [ "$status" -eq 0 ] || break
        done
        """;

    private static async Task<Result> RunLinuxAsync(ProcessStartInfo command, TimeSpan deadline, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("The Docker context proof requires Linux or Windows.");
        var nonce = Guid.NewGuid().ToString("N");
        var start = new ProcessStartInfo("/usr/bin/setsid")
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var argument in new[] { "--wait", "/bin/sh", "-c", Supervisor, "--", nonce, command.FileName })
            start.ArgumentList.Add(argument);
        foreach (var argument in command.ArgumentList) start.ArgumentList.Add(argument);
        start.Environment.Clear();
        foreach (var pair in command.Environment) start.Environment[pair.Key] = pair.Value;
        using var process = new Process { StartInfo = start };
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(deadline);
        using var readers = new CancellationTokenSource();
        var ready = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        var done = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<string>? stdout = null;
        Task<string>? stderr = null;
        Exception? primary = null;
        var captured = false;
        var cleaned = false;
        DateTime started = default;
        process.Start();
        try
        {
            started = process.StartTime.ToUniversalTime();
            stdout = ReadSupervisorAsync(process.StandardOutput, nonce, ready, done, readers.Token);
            stderr = ReadBoundedAsync(process.StandardError, readers.Token);
            var leader = await AwaitProtocolAsync(ready.Task, stdout, stderr, timeout.Token);
            // setsid must not have forked: no command is released until the retained Process is the session leader.
            if (leader != process.Id || GetProcessGroup(leader) != leader)
                throw new InvalidOperationException("Owned Docker session identity was not established.");
            captured = true;
            await process.StandardInput.WriteLineAsync(nonce + ":GO");
            await process.StandardInput.FlushAsync();
            var exitCode = await AwaitProtocolAsync(done.Task, stdout, stderr, timeout.Token);
            await FinishLinuxAsync(process, started, stdout, stderr);
            cleaned = true;
            await stderr;
            return new Result(exitCode, await stdout);
        }
        catch (Exception failure)
        {
            primary = failure;
            throw;
        }
        finally
        {
            var failures = new List<Exception>();
            if (primary is not null) TryCleanup(failures, readers.Cancel);
            await TryCleanupAsync(failures, async () =>
            {
                if (captured && !cleaned)
                    await FinishLinuxAsync(process, started, stdout!, stderr!);
                else if (!captured && !process.HasExited)
                {
                    // Before GO the supervisor has no command child; EOF invokes its self-owned EXIT trap.
                    process.StandardInput.Close();
                    using var cleanup = new CancellationTokenSource(CleanupDeadline);
                    await process.WaitForExitAsync(cleanup.Token);
                }
            });
            TryCleanup(failures, readers.Cancel);
            TryCleanup(failures, process.StandardInput.Dispose);
            TryCleanup(failures, process.StandardOutput.Dispose);
            TryCleanup(failures, process.StandardError.Dispose);
            await TryCleanupAsync(failures, () => ObserveReadersAsync(stdout, stderr));
            ThrowCleanupFailures("Owned Docker session cleanup failed.", primary, failures);
        }
    }

    private static async Task FinishLinuxAsync(Process process, DateTime started, Task<string> stdout, Task<string> stderr)
    {
        if (!process.HasExited)
        {
            VerifyLeader(process, started);
            if (SendSignal(-process.Id, 15) != 0) throw NativeFailure("Owned Docker group TERM failed.");
            await Task.Delay(TimeSpan.FromMilliseconds(200));
            if (!process.HasExited)
            {
                VerifyLeader(process, started);
                if (SendSignal(-process.Id, 9) != 0) throw NativeFailure("Owned Docker group KILL failed.");
            }
        }
        using var cleanup = new CancellationTokenSource(CleanupDeadline);
        await process.WaitForExitAsync(cleanup.Token);
        // Probe only after the final signal. Never signal a potentially recycled process-group ID again.
        while (SendSignal(-process.Id, 0) == 0)
            await Task.Delay(20, cleanup.Token);
        if (Marshal.GetLastPInvokeError() != 3) throw NativeFailure("Owned Docker group absence was not verified.");
        await ObserveReadersAsync(stdout, stderr).WaitAsync(cleanup.Token);
    }

    private static void VerifyLeader(Process process, DateTime started)
    {
        process.Refresh();
        if (process.HasExited || process.StartTime.ToUniversalTime() != started || GetProcessGroup(process.Id) != process.Id)
            throw new InvalidOperationException("Owned Docker session identity changed before cleanup.");
    }

    private static async Task<int> AwaitProtocolAsync(Task<int> protocol, Task<string> stdout, Task<string> stderr, CancellationToken token)
    {
        var watchError = true;
        while (true)
        {
            var winner = await (watchError
                ? Task.WhenAny(protocol, stdout, stderr)
                : Task.WhenAny(protocol, stdout)).WaitAsync(token);
            if (winner == protocol) return await protocol;
            await winner;
            if (winner == stderr)
            {
                watchError = false;
                continue;
            }
            throw new InvalidOperationException("Owned Docker supervisor closed before its bounded protocol completed.");
        }
    }

    private static async Task<string> ReadSupervisorAsync(StreamReader reader, string nonce, TaskCompletionSource<int> ready, TaskCompletionSource<int> done, CancellationToken token)
    {
        var output = new StringBuilder();
        var buffer = new char[1024];
        var announced = false;
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), token)) != 0)
        {
            output.Append(buffer, 0, count);
            if (Encoding.UTF8.GetByteCount(output.ToString()) > OutputLimit + 256)
                throw new InvalidOperationException("Docker diagnostic output budget exceeded; raw output withheld.");
            var value = output.ToString();
            if (!announced)
            {
                var end = value.IndexOf('\n');
                if (end < 0) continue;
                var prefix = nonce + ":READY:";
                if (!value.StartsWith(prefix, StringComparison.Ordinal) ||
                    !int.TryParse(value.AsSpan(prefix.Length, end - prefix.Length), NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
                    throw new InvalidOperationException("Owned Docker supervisor identity protocol was invalid.");
                ready.TrySetResult(pid);
                output.Remove(0, end + 1);
                announced = true;
                value = output.ToString();
            }
            var marker = "\n" + nonce + ":DONE:";
            var at = value.LastIndexOf(marker, StringComparison.Ordinal);
            if (at >= 0)
            {
                var end = value.IndexOf('\n', at + marker.Length);
                if (end >= 0)
                {
                    if (!int.TryParse(value.AsSpan(at + marker.Length, end - at - marker.Length),
                            NumberStyles.None, CultureInfo.InvariantCulture, out var exitCode) || exitCode is < 0 or > 255)
                        throw new InvalidOperationException("Owned Docker supervisor exit protocol was invalid.");
                    output.Remove(at, end + 1 - at);
                    done.TrySetResult(exitCode);
                }
            }
            if (done.Task.IsCompleted && Encoding.UTF8.GetByteCount(output.ToString()) > OutputLimit)
                throw new InvalidOperationException("Docker diagnostic output budget exceeded; raw output withheld.");
        }
        if (Encoding.UTF8.GetByteCount(output.ToString()) > OutputLimit)
            throw new InvalidOperationException("Docker diagnostic output budget exceeded; raw output withheld.");
        return output.ToString();
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, CancellationToken token)
    {
        var output = new StringBuilder();
        var buffer = new char[1024];
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), token)) != 0)
        {
            if (Encoding.UTF8.GetByteCount(output.ToString()) + Encoding.UTF8.GetByteCount(buffer, 0, count) > OutputLimit)
                throw new InvalidOperationException("Docker diagnostic output budget exceeded; raw output withheld.");
            output.Append(buffer, 0, count);
        }
        return output.ToString();
    }

    private static async Task ObserveReadersAsync(Task<string>? stdout, Task<string>? stderr)
    {
        foreach (var reader in new[] { stdout, stderr })
        {
            if (reader is null) continue;
            try { await reader.WaitAsync(CleanupDeadline); }
            catch (Exception) when (reader.IsFaulted || reader.IsCanceled) { _ = reader.Exception; }
        }
    }

    private static async Task<Result> RunWindowsAsync(ProcessStartInfo command, TimeSpan deadline, CancellationToken cancellationToken)
    {
        using var job = CreateJobObject(IntPtr.Zero, null);
        if (job.IsInvalid) throw NativeFailure("Owned Docker job creation failed.");
        var limits = new ExtendedLimits { Basic = new BasicLimits { LimitFlags = 0x2000 } };
        if (!SetInformationJobObject(job, 9, ref limits, Marshal.SizeOf<ExtendedLimits>()))
            throw NativeFailure("Owned Docker job limits failed.");
        using var input = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.Inheritable);
        using var output = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
        using var error = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
        using var stdoutReader = new StreamReader(output, Encoding.UTF8, leaveOpen: true);
        using var stderrReader = new StreamReader(error, Encoding.UTF8, leaveOpen: true);
        IntPtr attributes = IntPtr.Zero;
        IntPtr handles = IntPtr.Zero;
        IntPtr jobs = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;
        IntPtr processHandle = IntPtr.Zero;
        var attributesInitialized = false;
        uint processGroup = 0;
        Task<string>? stdout = null;
        Task<string>? stderr = null;
        Exception? primary = null;
        using var readers = new CancellationTokenSource();
        try
        {
            nuint size = 0;
            _ = InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
            attributes = Marshal.AllocHGlobal(checked((int)size));
            if (!InitializeProcThreadAttributeList(attributes, 2, 0, ref size))
                throw NativeFailure("Owned Docker process attributes failed.");
            attributesInitialized = true;
            handles = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(handles, input.ClientSafePipeHandle.DangerousGetHandle());
            Marshal.WriteIntPtr(handles, IntPtr.Size, output.ClientSafePipeHandle.DangerousGetHandle());
            Marshal.WriteIntPtr(handles, IntPtr.Size * 2, error.ClientSafePipeHandle.DangerousGetHandle());
            jobs = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(jobs, job.DangerousGetHandle());
            if (!UpdateProcThreadAttribute(attributes, 0, 0x20002, handles, (nuint)(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero) ||
                !UpdateProcThreadAttribute(attributes, 0, 0x2000D, jobs, (nuint)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                throw NativeFailure("Owned Docker atomic job assignment failed.");
            var startup = new StartupInfoEx
            {
                Startup = new StartupInfo
                {
                    Size = Marshal.SizeOf<StartupInfoEx>(),
                    Flags = 0x100,
                    Input = input.ClientSafePipeHandle.DangerousGetHandle(),
                    Output = output.ClientSafePipeHandle.DangerousGetHandle(),
                    Error = error.ClientSafePipeHandle.DangerousGetHandle(),
                },
                Attributes = attributes,
            };
            var block = string.Join('\0', command.Environment.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                .Select(pair => pair.Key + "=" + pair.Value)) + "\0\0";
            environment = Marshal.StringToHGlobalUni(block);
            var line = new StringBuilder(QuoteWindowsArgument(command.FileName) + " " +
                string.Join(" ", command.ArgumentList.Select(QuoteWindowsArgument)));
            // Atomic JOB_LIST assignment precedes child code. Nested-job refusal fails closed; no breakaway is requested.
            if (!CreateProcess(command.FileName, line, IntPtr.Zero, IntPtr.Zero, true,
                    0x00080000 | 0x00000400 | 0x08000000 | 0x00000200,
                    environment, null, ref startup, out var created))
                throw NativeFailure("Owned Docker process creation failed.");
            processHandle = created.Process;
            processGroup = created.ProcessId;
            CloseHandle(created.Thread);
            input.DisposeLocalCopyOfClientHandle();
            output.DisposeLocalCopyOfClientHandle();
            error.DisposeLocalCopyOfClientHandle();
            stdout = ReadBoundedAsync(stdoutReader, readers.Token);
            stderr = ReadBoundedAsync(stderrReader, readers.Token);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(deadline);
            while (WaitForSingleObject(processHandle, 0) == 0x102)
            {
                if (stdout.IsFaulted) await stdout;
                if (stderr.IsFaulted) await stderr;
                await Task.Delay(20, timeout.Token);
            }
            if (!GetExitCodeProcess(processHandle, out var exitCode))
                throw NativeFailure("Owned Docker exit status was unavailable.");
            await FinishWindowsAsync(job, processHandle, processGroup);
            await Task.WhenAll(stdout, stderr).WaitAsync(CleanupDeadline);
            return new Result(checked((int)exitCode), await stdout);
        }
        catch (Exception failure)
        {
            primary = failure;
            throw;
        }
        finally
        {
            var failures = new List<Exception>();
            if (primary is not null) TryCleanup(failures, readers.Cancel);
            TryCleanup(failures, input.Dispose);
            await TryCleanupAsync(failures, () => FinishWindowsAsync(job, processHandle, processGroup));
            TryCleanup(failures, readers.Cancel);
            TryCleanup(failures, stdoutReader.Dispose);
            TryCleanup(failures, stderrReader.Dispose);
            if (processHandle != IntPtr.Zero) TryCleanup(failures, () =>
            {
                if (!CloseHandle(processHandle)) throw NativeFailure("Owned Docker process handle release failed.");
            });
            if (attributes != IntPtr.Zero)
            {
                if (attributesInitialized) TryCleanup(failures, () => DeleteProcThreadAttributeList(attributes));
                TryCleanup(failures, () => Marshal.FreeHGlobal(attributes));
            }
            if (handles != IntPtr.Zero) TryCleanup(failures, () => Marshal.FreeHGlobal(handles));
            if (jobs != IntPtr.Zero) TryCleanup(failures, () => Marshal.FreeHGlobal(jobs));
            if (environment != IntPtr.Zero) TryCleanup(failures, () => Marshal.FreeHGlobal(environment));
            await TryCleanupAsync(failures, () => ObserveReadersAsync(stdout, stderr));
            ThrowCleanupFailures("Owned Docker job cleanup failed.", primary, failures);
        }
    }

    private static async Task FinishWindowsAsync(Microsoft.Win32.SafeHandles.SafeFileHandle job, IntPtr process, uint group)
    {
        if (ActiveProcesses(job) == 0) return;
        // A no-window CLI may have no attached console: CTRL_BREAK is best effort, not a claimed graceful cancellation.
        if (group != 0 && process != IntPtr.Zero && WaitForSingleObject(process, 0) == 0x102)
            _ = GenerateConsoleCtrlEvent(1, group);
        await Task.Delay(200);
        if (ActiveProcesses(job) != 0 && !TerminateJobObject(job, 125))
            throw NativeFailure("Owned Docker job termination failed.");
        using var cleanup = new CancellationTokenSource(CleanupDeadline);
        while (ActiveProcesses(job) != 0) await Task.Delay(20, cleanup.Token);
    }

    private static uint ActiveProcesses(Microsoft.Win32.SafeHandles.SafeFileHandle job)
    {
        if (!QueryInformationJobObject(job, 1, out var accounting, Marshal.SizeOf<BasicAccounting>(), IntPtr.Zero))
            throw NativeFailure("Owned Docker job absence could not be verified.");
        return accounting.ActiveProcesses;
    }

    internal static string QuoteWindowsArgument(string value)
    {
        var quoted = new StringBuilder("\"");
        var slashes = 0;
        foreach (var character in value)
        {
            if (character == '\\') { slashes++; continue; }
            quoted.Append('\\', character == '"' ? slashes * 2 + 1 : slashes);
            quoted.Append(character);
            slashes = 0;
        }
        quoted.Append('\\', slashes * 2);
        return quoted.Append('"').ToString();
    }

    private static void TryCleanup(List<Exception> failures, Action cleanup)
    {
        try { cleanup(); }
        catch (Exception failure) { failures.Add(failure); }
    }

    private static async Task TryCleanupAsync(List<Exception> failures, Func<Task> cleanup)
    {
        try { await cleanup(); }
        catch (Exception failure) { failures.Add(failure); }
    }

    private static void ThrowCleanupFailures(string message, Exception? primary, List<Exception> failures)
    {
        if (failures.Count == 0) return;
        if (primary is not null) failures.Insert(0, primary);
        throw new AggregateException(message, failures);
    }

    private static Win32Exception NativeFailure(string message) => new(Marshal.GetLastPInvokeError(), message);

    [DllImport("libc", EntryPoint = "getpgid", SetLastError = true)]
    private static extern int GetProcessGroup(int process);
    [DllImport("libc", EntryPoint = "kill", SetLastError = true)]
    private static extern int SendSignal(int process, int signal);

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        internal int Size;
        internal IntPtr Reserved, Desktop, Title;
        internal int X, Y, XSize, YSize, XCount, YCount, Fill, Flags;
        internal short Show, ReservedSize;
        internal IntPtr ReservedData, Input, Output, Error;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx
    {
        internal StartupInfo Startup;
        internal IntPtr Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        internal IntPtr Process, Thread;
        internal uint ProcessId, ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimits
    {
        internal long ProcessTime, JobTime;
        internal uint LimitFlags;
        internal nuint MinWorkingSet, MaxWorkingSet;
        internal uint ActiveLimit;
        internal nuint Affinity;
        internal uint Priority, Scheduling;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimits
    {
        internal BasicLimits Basic;
        internal ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes;
        internal nuint ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicAccounting
    {
        internal long UserTime, KernelTime, PeriodUserTime, PeriodKernelTime;
        internal uint PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateJobObjectW", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateJobObject(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(Microsoft.Win32.SafeHandles.SafeFileHandle job, int type, ref ExtendedLimits information, int length);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(Microsoft.Win32.SafeHandles.SafeFileHandle job, int type, out BasicAccounting information, int length, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateJobObject(Microsoft.Win32.SafeHandles.SafeFileHandle job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref nuint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, nuint attribute, IntPtr value, nuint size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcess(string application, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inherit, uint flags, IntPtr environment, string? directory, ref StartupInfoEx startup, out ProcessInformation information);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GenerateConsoleCtrlEvent(uint signal, uint group);
    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
