using Legacy.Maliev.AuthService.Application;

namespace Legacy.Maliev.AuthService.Tests;

// Explicit stored-profile fixture for isolated infrastructure tests only.
// Normal HTTP boundary tests retain the real reader and separately signed transport.
internal sealed class FixedCustomerProfileBinding(params CustomerProfileBinding[] profiles) : ICustomerProfileBindingClient
{
    public Task<CustomerProfileBindingResult> ReadAsync(int databaseId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var profile = profiles.SingleOrDefault(value => value.Id == databaseId);
        return Task.FromResult(profile is null ? new CustomerProfileBindingResult(CustomerProfileBindingStatus.Missing)
            : new CustomerProfileBindingResult(CustomerProfileBindingStatus.Verified, profile));
    }
}
