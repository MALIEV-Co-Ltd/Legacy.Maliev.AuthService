using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.Extensions.Time.Testing;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class AuthenticationServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 15, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Login_ValidLegacyPassword_IssuesShortLivedAccessAndHashedRefreshSession()
    {
        var identity = Identity();
        var validator = new StubValidator(identity);
        var store = new RecordingStore();
        var service = CreateService(validator, store);

        var result = await service.LoginAsync(
            new LoginRequest(" user@maliev.com ", "correct password", IdentityKind.Customer), default);

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Tokens);
        Assert.Equal("Bearer", result.Tokens.TokenType);
        Assert.Equal(900, result.Tokens.ExpiresIn);
        Assert.Equal(Now.AddDays(14), result.Tokens.RefreshExpiresAt);
        Assert.Equal("user@maliev.com", validator.UserName);
        Assert.Equal("correct password", validator.Password);
        Assert.NotNull(store.Created);
        Assert.NotEqual(result.Tokens.RefreshToken, store.Created.TokenHash);
        Assert.DoesNotContain(result.Tokens.RefreshToken, store.Created.TokenHash, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Login_InvalidCredentials_ReturnsGenericFailureAndCreatesNoSession()
    {
        var store = new RecordingStore();
        var service = CreateService(new StubValidator(null), store);

        var result = await service.LoginAsync(
            new LoginRequest("missing@maliev.com", "wrong", IdentityKind.Employee), default);

        Assert.False(result.Succeeded);
        Assert.Null(result.Tokens);
        Assert.Null(store.Created);
    }

    [Fact]
    public async Task Refresh_ActiveToken_RotatesTokenAndNeverStoresRawValue()
    {
        var store = new RecordingStore
        {
            RotationResult = new RefreshRotationResult(RefreshRotationStatus.Succeeded, Identity()),
        };
        var service = CreateService(new StubValidator(null), store);

        var result = await service.RefreshAsync(new RefreshRequest(new string('r', 64)), default);

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Tokens);
        Assert.NotNull(store.Replacement);
        Assert.NotEqual(result.Tokens.RefreshToken, store.Replacement.TokenHash);
        Assert.Equal(Now.AddDays(14), store.Replacement.ExpiresAt);
    }

    [Theory]
    [InlineData(RefreshRotationStatus.Invalid)]
    [InlineData(RefreshRotationStatus.Reused)]
    public async Task Refresh_InvalidOrReusedToken_ReturnsSamePublicFailure(RefreshRotationStatus status)
    {
        var store = new RecordingStore { RotationResult = new RefreshRotationResult(status, null) };
        var service = CreateService(new StubValidator(null), store);

        var result = await service.RefreshAsync(new RefreshRequest(new string('r', 64)), default);

        Assert.False(result.Succeeded);
        Assert.Null(result.Tokens);
    }

    [Fact]
    public async Task Revoke_HashesTokenBeforeStoreBoundary()
    {
        var store = new RecordingStore();
        var service = CreateService(new StubValidator(null), store);
        var raw = new string('x', 64);

        await service.RevokeAsync(new RevokeRequest(raw), default);

        Assert.NotNull(store.RevokedHash);
        Assert.NotEqual(raw, store.RevokedHash);
        Assert.Equal(Now, store.RevokedAt);
    }

    private static AuthenticationService CreateService(StubValidator validator, RecordingStore store) =>
        new(validator, new StubTokenIssuer(), store, new FakeTimeProvider(Now));

    private static LegacyIdentity Identity() =>
        new("legacy-user-id", "user@maliev.com", "user@maliev.com", IdentityKind.Customer, 42, "stamp");

    private sealed class StubValidator(LegacyIdentity? result) : ILegacyCredentialValidator
    {
        public string? UserName { get; private set; }

        public string? Password { get; private set; }

        public Task<LegacyIdentity?> ValidateAsync(
            string userName,
            string password,
            IdentityKind kind,
            CancellationToken cancellationToken)
        {
            UserName = userName;
            Password = password;
            return Task.FromResult(result);
        }
    }

    private sealed class StubTokenIssuer : IAccessTokenIssuer
    {
        public IssuedAccessToken Issue(LegacyIdentity identity, DateTimeOffset now) => new("signed.jwt", 900);
    }

    private sealed class RecordingStore : IRefreshSessionStore
    {
        public RefreshSession? Created { get; private set; }

        public RefreshSession? Replacement { get; private set; }

        public string? RevokedHash { get; private set; }

        public DateTimeOffset? RevokedAt { get; private set; }

        public RefreshRotationResult RotationResult { get; init; } =
            new(RefreshRotationStatus.Invalid, null);

        public Task CreateAsync(RefreshSession session, CancellationToken cancellationToken)
        {
            Created = session;
            return Task.CompletedTask;
        }

        public Task<RefreshRotationResult> RotateAsync(
            string presentedHash,
            RefreshSession replacement,
            CancellationToken cancellationToken)
        {
            Replacement = replacement;
            return Task.FromResult(RotationResult);
        }

        public Task RevokeFamilyAsync(string tokenHash, DateTimeOffset now, CancellationToken cancellationToken)
        {
            RevokedHash = tokenHash;
            RevokedAt = now;
            return Task.CompletedTask;
        }
    }
}