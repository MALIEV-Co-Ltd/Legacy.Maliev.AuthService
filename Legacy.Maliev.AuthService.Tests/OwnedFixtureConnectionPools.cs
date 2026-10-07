using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

// Capture configured pool identities even when runtime code opens a separate context.
internal sealed class OwnedFixtureConnectionPools : IAsyncDisposable
{
    private readonly Dictionary<string, NpgsqlConnection> pools = [];
    private readonly object gate = new();
    public void Configure(DbContextOptionsBuilder options)
    {
        // The production callback has already applied its connection and retry settings.
        var connection = options.Options.Extensions.OfType<RelationalOptionsExtension>().Single().ConnectionString
            ?? throw new InvalidOperationException("Fixture relational connection configuration is missing");
        lock (gate)
            if (!pools.ContainsKey(connection)) pools.Add(connection, new NpgsqlConnection(connection));
        // Keep the original options and data source behavior; these handles are never opened.
    }
    public ValueTask DisposeAsync()
    {
        var failures = new List<Exception>();
        foreach (var pool in pools.Values)
        {
            try { NpgsqlConnection.ClearPool(pool); } catch (Exception exception) { failures.Add(exception); }
            try { pool.Dispose(); } catch (Exception exception) { failures.Add(exception); }
        }
        if (failures.Count != 0) throw new AggregateException("Owned fixture pool cleanup failed", failures);
        return ValueTask.CompletedTask;
    }
}

internal sealed class FixtureResourceFailureLogger : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName) => new FailureLogger();
    public void Dispose() { }
    private sealed class FailureLogger : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => level >= LogLevel.Error;
        public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (exception is null) return;
            var depth = 0;
            for (var cause = exception; cause is not null && depth++ < 3; cause = cause.InnerException)
                Console.WriteLine("FixtureResourceFailure: " + cause.GetType().FullName + " at " + string.Join(" -> ", new System.Diagnostics.StackTrace(cause).GetFrames().Take(8).Select(frame => frame.GetMethod()?.DeclaringType?.FullName + "." + frame.GetMethod()?.Name)));
        }
    }
}
