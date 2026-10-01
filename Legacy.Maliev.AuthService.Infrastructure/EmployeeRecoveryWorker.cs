using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Delivers committed receipts only; never holds an employee identity lock while acquiring Auth state.</summary>
public sealed class EmployeeRecoveryWorker(IServiceScopeFactory scopes, EmployeeRecoveryOptions options, ILogger<EmployeeRecoveryWorker> logger) : BackgroundService
{
    private readonly SemaphoreSlim batchGate = new(1, 1);
    private readonly EmployeeRecoveryScanCursor cursor = new();

    /// <summary>Runs one cancellation-aware serialized delivery batch using a fresh dependency scope.</summary>
    public async Task<int> ReconcileBatchAsync(CancellationToken cancellationToken)
    {
        await batchGate.WaitAsync(cancellationToken);
        try
        {
            await using var scope = scopes.CreateAsyncScope();
            var result = await scope.ServiceProvider.GetRequiredService<EmployeeSelfService>().ReconcileWorkerBatchAsync(cursor, cancellationToken);
            if (result.Failed != 0) logger.LogWarning("Employee recovery finalization is unavailable; committed receipts remain pending.");
            return result.Completed;
        }
        finally { batchGate.Release(); }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Enabled) return;
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        do
        {
            try
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                deadline.CancelAfter(TimeSpan.FromSeconds(30));
                await ReconcileBatchAsync(deadline.Token);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch { logger.LogWarning("Employee recovery finalization is unavailable; committed receipts remain pending."); }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
