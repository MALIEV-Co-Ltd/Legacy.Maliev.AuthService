using Legacy.Maliev.AuthService.Application;

namespace Legacy.Maliev.AuthService.Tests;

// Only permission-isolation tests replace profile authority. Normal-host tests use the real HTTP reader.
internal sealed class AuthorizationEmployeeProfileStub : IEmployeeProfileBindingClient
{
    public Task<EmployeeProfileBindingResult> ReadAsync(int databaseId, CancellationToken cancellationToken) =>
        Task.FromResult(new EmployeeProfileBindingResult(EmployeeProfileBindingStatus.Verified,
            new(databaseId, "employee@example.com", null)));
}
