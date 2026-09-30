using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Delivers committed receipts only; never holds an employee identity lock while acquiring Auth state.</summary>
public sealed class EmployeeRecoveryWorker(IServiceScopeFactory scopes, EmployeeRecoveryOptions options, ILogger<EmployeeRecoveryWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Enabled) return;
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        do
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                deadline.CancelAfter(TimeSpan.FromSeconds(30));
                await scope.ServiceProvider.GetRequiredService<EmployeeSelfService>().ReconcileOutstandingAsync(deadline.Token);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            catch { logger.LogWarning("Employee recovery finalization is unavailable; committed receipts remain pending."); }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
