using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Npgsql;
using Microsoft.Extensions.Logging;

namespace Legacy.Maliev.AuthService.Tests;

// Own the actual EF data sources; ClearPool only targets Npgsql's connection-string registry.
internal sealed class OwnedFixtureDataSources : IAsyncDisposable
{
    private readonly Dictionary<string, NpgsqlDataSource> sources = [];
    private readonly object gate = new();
    public void Configure(DbContextOptionsBuilder options)
    {
        // The production callback has already applied its connection and retry settings.
        var connection = options.Options.Extensions.OfType<RelationalOptionsExtension>().Single().ConnectionString
            ?? throw new InvalidOperationException("Fixture relational connection configuration is missing");
        lock (gate)
        {
            if (!sources.TryGetValue(connection, out var source))
                sources.Add(connection, source = new NpgsqlDataSourceBuilder(connection).Build());
            options.UseNpgsql(source);
        }
    }
    public async ValueTask DisposeAsync()
    {
        var failures = new List<Exception>();
        foreach (var source in sources.Values)
            try { await source.DisposeAsync(); } catch (Exception exception) { failures.Add(exception); }
        if (failures.Count != 0) throw new AggregateException("Owned fixture data source cleanup failed", failures);
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
