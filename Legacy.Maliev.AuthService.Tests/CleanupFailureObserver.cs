using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace Legacy.Maliev.AuthService.Tests;

internal static class CleanupFailureObserver
{
    internal static string Format(Exception exception, TimeSpan elapsed, int ownedState)
    {
        var report = new StringBuilder("postgres_cleanup_failure elapsed_ms=");
        report.Append(Math.Clamp(elapsed.TotalMilliseconds, 0, int.MaxValue).ToString("0", CultureInfo.InvariantCulture));
        report.Append(" owned_state=").Append(ownedState.ToString(CultureInfo.InvariantCulture));
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

    private static string SafeName(string value) =>
        new(value.Take(48).Select(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '.' ? character : '_').ToArray());
}
