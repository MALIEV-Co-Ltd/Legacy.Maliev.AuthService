using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.Extensions.Time.Testing;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class GoogleAuthenticationServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 27, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Exchange_ConsumesNonceBeforeValidation_AndStoresOnlyRefreshHash()
    {
        var nonce = new RecordingNonceService { ConsumeResult = true };
        var events = nonce.Events;
        var validator = new RecordingGoogleValidator(new(
            true,
            new VerifiedGoogleIdentity("subject", "employee@maliev.com", true, "maliev.com", null, null),
            null,
            null), events);
        var store = new RecordingStore();
        var service = CreateService(nonce, validator, new StubEmployeeReader(Employee(), events), store);
        store.Events = events;

        var result = await service.ExchangeAsync(
            new GoogleExchangeRequest(new string('c', 128), "intranet", new string('n', 64)),
            "legacy-intranet",
            default);

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Tokens);
        Assert.True(nonce.Consumed);
        Assert.Equal(["consume", "validate", "lookup", "store", "issue"], nonce.Events);
        Assert.NotNull(store.Created);
        Assert.NotEqual(result.Tokens.RefreshToken, store.Created.TokenHash);
        Assert.DoesNotContain(result.Tokens.RefreshToken, store.Created.TokenHash, StringComparison.Ordinal);
        Assert.Equal(IdentityKind.Employee, store.Created.IdentityKind);
        Assert.Equal(Employee().Id, store.Created.IdentityId);
    }

    [Fact]
    public async Task Exchange_ReplayedOrExpiredNonce_FailsBeforeCredentialValidation()
    {
        var nonce = new RecordingNonceService { ConsumeResult = false };
        var validator = new RecordingGoogleValidator(new(
            true,
            new VerifiedGoogleIdentity("subject", "employee@maliev.com", true, "maliev.com", null, null),
            null,
            null));
        var store = new RecordingStore();
        var service = CreateService(nonce, validator, new StubEmployeeReader(Employee()), store);

        var result = await service.ExchangeAsync(
            new GoogleExchangeRequest(new string('c', 128), "intranet", new string('n', 64)),
            "legacy-intranet",
            default);

        Assert.False(result.Succeeded);
        Assert.Equal("invalid_nonce", result.ErrorCode);
        Assert.False(validator.Called);
        Assert.Null(store.Created);
    }

    [Fact]
    public async Task Exchange_UnknownOrInactiveEmployee_FailsWithoutCreatingSession()
    {
        var nonce = new RecordingNonceService { ConsumeResult = true };
        var validator = new RecordingGoogleValidator(new(
            true,
            new VerifiedGoogleIdentity("subject", "unknown@maliev.com", true, "maliev.com", null, null),
            null,
            null));
        var store = new RecordingStore();
        var service = CreateService(nonce, validator, new StubEmployeeReader(null), store);

        var result = await service.ExchangeAsync(
            new GoogleExchangeRequest(new string('c', 128), "intranet", new string('n', 64)),
            "legacy-intranet",
            default);

        Assert.False(result.Succeeded);
        Assert.Equal("employee_not_found", result.ErrorCode);
        Assert.Null(store.Created);
    }

    [Fact]
    public async Task Exchange_InvalidGoogleIdentity_DoesNotCreateSession()
    {
        var nonce = new RecordingNonceService { ConsumeResult = true };
        var validator = new RecordingGoogleValidator(GoogleIdentityValidationResult.Invalid());
        var store = new RecordingStore();
        var service = CreateService(nonce, validator, new StubEmployeeReader(Employee()), store);

        var result = await service.ExchangeAsync(
            new GoogleExchangeRequest(new string('c', 128), "intranet", new string('n', 64)),
            "legacy-intranet",
            default);

        Assert.False(result.Succeeded);
        Assert.Equal("invalid_google_credential", result.ErrorCode);
        Assert.Null(store.Created);
    }

    private static GoogleAuthenticationService CreateService(
        RecordingNonceService nonce,
        RecordingGoogleValidator validator,
        StubEmployeeReader reader,
        RecordingStore store) =>
        new(nonce, validator, reader, new RecordingIssuer(nonce), store, new FakeTimeProvider(Now));

    private static LegacyIdentity Employee() =>
        new("employee-id", "employee@maliev.com", "employee@maliev.com", IdentityKind.Employee, 7, "stamp");

    private sealed class RecordingNonceService : IGoogleIdentityNonceService
    {
        public bool ConsumeResult { get; init; }
        public bool Consumed { get; private set; }
        public List<string> Events { get; } = [];

        public Task<(string Nonce, DateTimeOffset ExpiresAtUtc)> IssueAsync(
            string serviceName, string application, CancellationToken cancellationToken)
        {
            Events.Add("issue");
            return Task.FromResult(("nonce", Now.AddMinutes(10)));
        }

        public Task<bool> ConsumeAsync(
            string nonce, string serviceName, string application, CancellationToken cancellationToken)
        {
            Events.Add("consume");
            Consumed = true;
            return Task.FromResult(ConsumeResult);
        }
    }

    private sealed class RecordingGoogleValidator(
        GoogleIdentityValidationResult result,
        List<string>? events = null) : IGoogleIdentityTokenValidator
    {
        public bool Called { get; private set; }

        public Task<GoogleIdentityValidationResult> ValidateAsync(
            string credential, string application, string expectedNonce, CancellationToken cancellationToken)
        {
            Called = true;
            events?.Add("validate");
            return Task.FromResult(result);
        }
    }

    private sealed class StubEmployeeReader(LegacyIdentity? result, List<string>? events = null) : IGoogleEmployeeIdentityReader
    {
        public Task<LegacyIdentity?> FindActiveEmployeeByEmailAsync(
            string email, CancellationToken cancellationToken)
        {
            events?.Add("lookup");
            return Task.FromResult(result);
        }
    }

    private sealed class RecordingIssuer(RecordingNonceService nonce) : IAccessTokenIssuer
    {
        public IssuedAccessToken Issue(LegacyIdentity identity, DateTimeOffset now)
        {
            nonce.Events.Add("issue");
            return new("access-token", 900);
        }
    }

    private sealed class RecordingStore : IRefreshSessionStore
    {
        public List<string>? Events { get; set; }
        public RefreshSession? Created { get; private set; }

        public Task CreateAsync(RefreshSession session, CancellationToken cancellationToken)
        {
            Events?.Add("store");
            Created = session;
            return Task.CompletedTask;
        }

        public Task<RefreshRotationResult> RotateAsync(
            string presentedHash, RefreshSession replacement, CancellationToken cancellationToken) =>
            Task.FromResult(new RefreshRotationResult(RefreshRotationStatus.Invalid, null, null, null));

        public Task RevokeFamilyAsync(string tokenHash, DateTimeOffset now, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }
}
