using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.Extensions.Time.Testing;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class CustomerRefreshAdmissionTests
{
    [Theory]
    [InlineData(IdentityKind.Customer, true, false)]
    [InlineData(IdentityKind.Customer, false, true)]
    [InlineData(IdentityKind.Employee, true, true)]
    [InlineData(IdentityKind.Employee, false, true)]
    public async Task Refresh_RechecksInitialPasswordStateBeforeIssuance(
        IdentityKind kind, bool setupRequired, bool expectedSuccess)
    {
        var identity = new LegacyIdentity("refresh-state-id", "state@example.com", "state@example.com", kind, 42, "unchanged-stamp")
        {
            RequiresInitialPassword = setupRequired,
        };
        var issuer = new RecordingIssuer();
        var store = new SuccessfulRotation(identity);
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 10, 9, 0, 0, 0, TimeSpan.Zero));
        var service = new AuthenticationService(new UnusedValidator(), new CurrentIdentity(identity), issuer, store, clock);

        var result = await service.RefreshAsync(new RefreshRequest(new string('r', 64)), default);

        Assert.Equal(expectedSuccess, result.Succeeded);
        Assert.Equal(expectedSuccess ? 1 : 0, issuer.Calls);
        Assert.Null(result.RequiredAction);
        Assert.NotNull(store.Replacement);
        if (expectedSuccess)
        {
            Assert.NotNull(result.Tokens);
            Assert.Null(store.RevokedHash);
        }
        else
        {
            Assert.Null(result.Tokens);
            Assert.Equal(store.Replacement.TokenHash, store.RevokedHash);
            Assert.Equal(clock.GetUtcNow(), store.RevokedAt);
        }
    }

    private sealed class UnusedValidator : ILegacyCredentialValidator
    {
        public Task<LegacyIdentity?> ValidateAsync(string userName, string password, IdentityKind kind, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Refresh must not invoke password validation.");
    }

    private sealed class CurrentIdentity(LegacyIdentity identity) : ILegacyIdentityReader
    {
        public Task<LegacyIdentity?> FindActiveAsync(string identityId, IdentityKind kind, CancellationToken cancellationToken) =>
            Task.FromResult<LegacyIdentity?>(identity);
    }

    private sealed class RecordingIssuer : IAccessTokenIssuer
    {
        public int Calls { get; private set; }
        public IssuedAccessToken Issue(LegacyIdentity identity, DateTimeOffset now, Guid? employeeSessionId)
        {
            Calls++;
            return new("controlled-access-token", 900);
        }
    }

    private sealed class SuccessfulRotation(LegacyIdentity identity) : IRefreshSessionStore
    {
        public RefreshSession? Replacement { get; private set; }
        public string? RevokedHash { get; private set; }
        public DateTimeOffset? RevokedAt { get; private set; }
        public Task CreateAsync(RefreshSession session, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Refresh must use the rotation boundary.");
        public Task<RefreshRotationResult> RotateAsync(string presentedHash, RefreshSession replacement, CancellationToken cancellationToken)
        {
            Replacement = replacement;
            return Task.FromResult(new RefreshRotationResult(RefreshRotationStatus.Succeeded, identity.Id, identity.Kind, identity.SecurityStamp));
        }
        public Task RevokeFamilyAsync(string tokenHash, DateTimeOffset now, CancellationToken cancellationToken)
        {
            RevokedHash = tokenHash;
            RevokedAt = now;
            return Task.CompletedTask;
        }
    }
}
