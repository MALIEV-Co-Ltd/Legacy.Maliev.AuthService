namespace Legacy.Maliev.AuthService.Infrastructure;

// Process-local scheduling only. The worker gate protects this state across fresh DI scopes;
// none of these positions authorize a credential effect or acknowledge a receipt.
internal sealed class EmployeeRecoveryScanCursor
{
    internal EmployeeRecoveryScanPosition? After { get; set; }
    internal EmployeeRecoveryScanPosition? Upper { get; set; }
    internal void Reset() { After = null; Upper = null; }
}

internal readonly record struct EmployeeRecoveryScanPosition(DateTimeOffset AppliedAt, Guid ActionId);
internal readonly record struct EmployeeRecoveryBatchResult(int Completed, int Failed);
