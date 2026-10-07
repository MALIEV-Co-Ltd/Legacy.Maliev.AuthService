using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Npgsql;

namespace Legacy.Maliev.AuthService.Tests;

// Capture actual runtime pools without resolving services or opening connections at teardown.
internal sealed class OwnedFixtureConnectionPools : DbConnectionInterceptor
{
    private readonly HashSet<NpgsqlConnection> pools = [];
    private readonly object gate = new();
    public override InterceptionResult ConnectionOpening(DbConnection connection, ConnectionEventData eventData, InterceptionResult result)
    {
        lock (gate) pools.Add((NpgsqlConnection)connection);
        return result;
    }
    public override ValueTask<InterceptionResult> ConnectionOpeningAsync(DbConnection connection, ConnectionEventData eventData, InterceptionResult result, CancellationToken cancellationToken = default)
    {
        lock (gate) pools.Add((NpgsqlConnection)connection);
        return ValueTask.FromResult(result);
    }
    public void Clear()
    {
        var failures = new List<Exception>();
        lock (gate)
            foreach (var pool in pools)
                try { NpgsqlConnection.ClearPool(pool); } catch (Exception exception) { failures.Add(exception); }
        if (failures.Count != 0) throw new AggregateException("Owned fixture pool cleanup failed", failures);
    }
}
