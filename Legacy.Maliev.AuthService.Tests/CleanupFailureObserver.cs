using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.AuthService.Tests;

internal static class CleanupFailureObserver
{
    internal static string Format(Exception exception, TimeSpan elapsed, int? ownedState)
    {
        var report = new StringBuilder("postgres_cleanup_failure elapsed_ms=");
        report.Append(Math.Clamp(elapsed.TotalMilliseconds, 0, int.MaxValue).ToString("0", CultureInfo.InvariantCulture));
        report.Append(" owned_state=").Append(ownedState?.ToString(CultureInfo.InvariantCulture) ?? "unknown");
        var current = exception;
        for (var depth = 0; current is not null && depth < 8; depth++, current = current.InnerException)
        {
            report.Append(" type=").Append(SafeName(current.GetType().Name));
            var trace = new StackTrace(current, false);
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

    internal static void Observe(Exception exception, TimeSpan elapsed, Func<int> ownedState, Action<string> write)
    {
        try { write(Format(exception, elapsed, ownedState())); }
        catch { /* Diagnostics must never replace the original cleanup exception. */ }
    }

    internal static (string Id, DateTime StartedTime)? CaptureIdentity(Func<(string Id, DateTime StartedTime)> read)
    {
        try
        {
            var identity = read();
            return identity.Id.Length == 64 && identity.Id.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f')
                && identity.StartedTime != default ? identity : null;
        }
        catch { return null; }
    }

    internal static string? HostedDirectory(string? repository, string? runnerEnvironment, string? workspace)
    {
        try
        {
            if (repository != "MALIEV-Co-Ltd/Legacy.Maliev.AuthService" || runnerEnvironment != "github-hosted"
                || string.IsNullOrWhiteSpace(workspace) || !Path.IsPathFullyQualified(workspace)) return null;
            return Path.Combine(workspace, "artifacts", "ordinary-postgres-cleanup");
        }
        catch { return null; }
    }

    internal static void ObservePhase((string Id, DateTime StartedTime)? identity, string phase,
        TimeSpan elapsed, Func<int> ownedState, Exception? exception, string? directory)
    {
        try
        {
            if (identity is not { } captured || CaptureIdentity(() => captured) is null
                || directory is null || !Path.IsPathFullyQualified(directory)
                || phase is not ("dispose-entered" or "dispose-completed" or "dispose-faulted")) return;
            // Require the existing hosted receipt directory; never create or follow a linked destination.
            for (DirectoryInfo? current = new(directory); current is not null; current = current.Parent)
                if (!current.Exists || current.LinkTarget is not null
                    || (current.Attributes & FileAttributes.ReparsePoint) != 0) return;
            int? state = null;
            try { state = ownedState(); }
            catch { /* A failed state read must not hide the original failure's safe structure. */ }
            var report = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                containerId = captured.Id,
                fixtureStartedTime = captured.StartedTime.ToString("O", CultureInfo.InvariantCulture),
                phase,
                observedAtUtc = DateTime.UtcNow,
                elapsedMilliseconds = Math.Clamp(elapsed.TotalMilliseconds, 0, int.MaxValue),
                ownedState = state,
                failure = exception is null ? null : Format(exception, elapsed, state)
            });
            if (report.Length > 4096) return;
            using var stream = new FileStream(Path.Combine(directory, $"fixture-{captured.Id}-{phase}.json"),
                FileMode.CreateNew, FileAccess.Write, FileShare.None);
            stream.Write(report);
        }
        catch { /* Best-effort evidence must never change cleanup's result or exception. */ }
    }

    private static string SafeName(string value) =>
        new(value.Take(48).Select(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '.' ? character : '_').ToArray());
}
