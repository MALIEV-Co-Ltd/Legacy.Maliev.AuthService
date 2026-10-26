using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Text;

namespace Legacy.Maliev.AuthService.Tests;

internal enum CleanupFailurePhase
{
    Unknown,
    Stop,
    Remove,
    StopAndRemove,
}

internal static class CleanupFailureObserver
{
    internal static string Format(Exception exception, TimeSpan elapsed, int ownedState,
        CleanupFailurePhase phase = CleanupFailurePhase.Unknown)
    {
        var report = new StringBuilder("postgres_cleanup_failure elapsed_ms=");
        report.Append(Math.Clamp(elapsed.TotalMilliseconds, 0, int.MaxValue).ToString("0", CultureInfo.InvariantCulture));
        report.Append(" owned_state=").Append(ownedState.ToString(CultureInfo.InvariantCulture));
        report.Append(" cleanup_phase=").Append(phase switch
        {
            CleanupFailurePhase.Stop => "stop",
            CleanupFailurePhase.Remove => "remove",
            CleanupFailurePhase.StopAndRemove => "stop_and_remove",
            _ => "unknown",
        });
        var current = exception;
        for (var depth = 0; current is not null && depth < 8; depth++, current = current.InnerException)
        {
            report.Append(" type=").Append(SafeName(current.GetType().Name));
            var trace = new StackTrace(current, false);
            report.Append(" docker_api_frame=").Append(DockerApiFrame(trace));
            report.Append(" frames=");
            if (trace.FrameCount == 0) report.Append("none");
            for (var frame = 0; frame < Math.Min(trace.FrameCount, 4); frame++)
            {
                if (frame > 0) report.Append(',');
                var method = trace.GetFrame(frame)?.GetMethod();
                report.Append(SafeName(method?.DeclaringType?.Name ?? "unknown"));
                report.Append('.').Append(SafeName(method?.Name ?? "unknown"));
            }
        }
        return report.ToString(0, Math.Min(report.Length, 2048));
    }

    internal static void Observe(Exception exception, TimeSpan elapsed, Func<int> ownedState,
        Action<string> write, Action<string>? persist = null,
        CleanupFailurePhase phase = CleanupFailurePhase.Unknown)
    {
        string report;
        try { report = Format(exception, elapsed, ownedState(), phase); }
        catch { return; }
        try { write(report); }
        catch { /* Each diagnostic sink is independent of the original failure. */ }
        try { persist?.Invoke(report); }
        catch { /* Diagnostics must never replace the original cleanup exception. */ }
    }

    // Positive metadata witness only: a missing frame never proves which request failed.
    private static string DockerApiFrame(StackTrace trace)
    {
        for (var index = 0; index < Math.Min(trace.FrameCount, 64); index++)
        {
            var operation = ClassifyDockerApiFrame(trace.GetFrame(index)?.GetMethod());
            if (operation != "unavailable") return operation;
        }
        return "unavailable";
    }

    internal static string ClassifyDockerApiFrame(MethodBase? method)
    {
        var type = method?.DeclaringType;
        if (type is null || type.Assembly != typeof(Docker.DotNet.DockerClient).Assembly) return "unavailable";
        string? name;
        if (type.FullName == "Docker.DotNet.ContainerOperations") name = method!.Name;
        else if (type.DeclaringType?.FullName == "Docker.DotNet.ContainerOperations" && method!.Name == "MoveNext")
        {
            name = type.Name.StartsWith("<InspectContainerAsync>d__", StringComparison.Ordinal) ? "InspectContainerAsync"
                : type.Name.StartsWith("<StopContainerAsync>d__", StringComparison.Ordinal) ? "StopContainerAsync"
                : type.Name.StartsWith("<RemoveContainerAsync>d__", StringComparison.Ordinal) ? "RemoveContainerAsync" : null;
        }
        else return "unavailable";
        return name switch
        {
            "InspectContainerAsync" => "inspect",
            "StopContainerAsync" => "stop",
            "RemoveContainerAsync" => "remove",
            _ => "unavailable",
        };
    }

    internal static void WriteReceipt(string report, string containerId, Func<string, string?> environment)
    {
        // The test step deliberately sets GITHUB_ACTIONS=false for local project
        // references; use the unchanged hosted identity rather than that switch.
        if (environment("GITHUB_REPOSITORY") != "MALIEV-Co-Ltd/Legacy.Maliev.AuthService" ||
            environment("RUNNER_ENVIRONMENT") != "github-hosted")
            return;
        var run = environment("GITHUB_RUN_ID");
        var attempt = environment("GITHUB_RUN_ATTEMPT");
        var sha = environment("GITHUB_SHA");
        var workspace = environment("GITHUB_WORKSPACE");
        if (!IsRunIdentity(run) || !IsRunIdentity(attempt) || !IsLowerHex(sha, 40) ||
            !IsLowerHex(containerId, 64) || string.IsNullOrEmpty(workspace) ||
            !Path.IsPathFullyQualified(workspace) || !Directory.Exists(workspace))
            return;
        if (report.Length > 2048 || !report.StartsWith("postgres_cleanup_failure ", StringComparison.Ordinal) ||
            report.Any(character => character < ' ' || character > '~'))
            return;

        var directory = Path.Combine(Path.GetFullPath(workspace), "artifacts", "ordinary-postgres-cleanup");
        RejectLinkedAncestors(directory);
        Directory.CreateDirectory(directory);
        RejectLinkedAncestors(directory);
        var raw = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            run,
            attempt,
            sha,
            containerId,
            report
        }) + "\n");
        if (raw.Length > 8192) return;
        using var stream = new FileStream(Path.Combine(directory, $"cleanup-failure-{containerId}.json"),
            FileMode.CreateNew, FileAccess.Write, FileShare.None);
        stream.Write(raw);
    }

    private static void RejectLinkedAncestors(string directory)
    {
        for (DirectoryInfo? current = new(directory); current is not null; current = current.Parent)
        {
            if (current.LinkTarget is not null ||
                (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0))
                throw new IOException("Linked receipt destination rejected.");
        }
    }

    private static bool IsRunIdentity(string? value) =>
        value is { Length: > 0 and <= 20 } && value.All(char.IsAsciiDigit);

    private static bool IsLowerHex(string? value, int length) =>
        value is not null && value.Length == length && value.All(character => char.IsAsciiDigit(character) || character is >= 'a' and <= 'f');

    private static string SafeName(string value) =>
        new(value.Take(48).Select(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '.' ? character : '_').ToArray());
}
