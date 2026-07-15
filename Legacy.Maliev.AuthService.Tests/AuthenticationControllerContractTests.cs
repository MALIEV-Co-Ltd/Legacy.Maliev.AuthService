using Legacy.Maliev.AuthService.Api.Controllers;
using Legacy.Maliev.AuthService.Application;
using Legacy.Maliev.AuthService.Domain;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Time.Testing;
using System.Reflection;

namespace Legacy.Maliev.AuthService.Tests;

public sealed class AuthenticationControllerContractTests
{
    [Fact]
    public void AuthenticationBoundary_ExposesOnlyPostEndpointsAndNoLongLivedTokenRoute()
    {
        var methods = typeof(AuthenticationController).GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .Where(method => method.DeclaringType == typeof(AuthenticationController))
            .ToArray();

        Assert.NotEmpty(methods);
        Assert.All(methods, method => Assert.NotEmpty(method.GetCustomAttributes<HttpPostAttribute>()));
        Assert.DoesNotContain(methods, method =>
            method.GetCustomAttributes<HttpPostAttribute>()
                .Any(attribute => attribute.Template?.Contains("longlived", StringComparison.OrdinalIgnoreCase) == true));
    }

    [Fact]
    public async Task Login_InvalidCredentials_ReturnsGenericProblemWithoutAccountEnumeration()
    {
        var service = new AuthenticationService(
            new RejectingValidator(),
            new MissingIdentityReader(),
            new NoopIssuer(),
            new NoopStore(),
            new FakeTimeProvider(new DateTimeOffset(2026, 7, 15, 0, 0, 0, TimeSpan.Zero)));
        var controller = new AuthenticationController(service);

        var result = await controller.Login(
            new LoginRequest("missing@maliev.com", "incorrect", IdentityKind.Customer), default);

        var unauthorized = Assert.IsType<UnauthorizedObjectResult>(result.Result);
        var problem = Assert.IsType<ProblemDetails>(unauthorized.Value);
        Assert.Equal("The supplied credentials or session are invalid.", problem.Detail);
        Assert.DoesNotContain("missing@maliev.com", problem.Detail, StringComparison.Ordinal);
    }

    private sealed class RejectingValidator : ILegacyCredentialValidator
    {
        public Task<LegacyIdentity?> ValidateAsync(
            string userName,
            string password,
            IdentityKind kind,
            CancellationToken cancellationToken) => Task.FromResult<LegacyIdentity?>(null);
    }

    private sealed class MissingIdentityReader : ILegacyIdentityReader
    {
        public Task<LegacyIdentity?> FindActiveAsync(
            string identityId,
            IdentityKind kind,
            CancellationToken cancellationToken) => Task.FromResult<LegacyIdentity?>(null);
    }

    private sealed class NoopIssuer : IAccessTokenIssuer
    {
        public IssuedAccessToken Issue(LegacyIdentity identity, DateTimeOffset now) => new("unused", 900);
    }

    private sealed class NoopStore : IRefreshSessionStore
    {
        public Task CreateAsync(RefreshSession session, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<RefreshRotationResult> RotateAsync(
            string presentedHash,
            RefreshSession replacement,
            CancellationToken cancellationToken) => Task.FromResult(
                new RefreshRotationResult(RefreshRotationStatus.Invalid, null, null, null));

        public Task RevokeFamilyAsync(
            string tokenHash,
            DateTimeOffset now,
            CancellationToken cancellationToken) => Task.CompletedTask;
    }
}