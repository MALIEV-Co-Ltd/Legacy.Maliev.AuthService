using Legacy.Maliev.AuthService.Domain;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.AuthService.Application;

/// <summary>Coordinates nonce-bound Google employee exchange and server-side refresh sessions.</summary>
public sealed class GoogleAuthenticationService(
    IGoogleIdentityNonceService nonceService,
    IGoogleIdentityTokenValidator tokenValidator,
    IGoogleEmployeeIdentityReader employeeIdentityReader,
    IAccessTokenIssuer accessTokenIssuer,
    IRefreshSessionStore refreshSessionStore,
    TimeProvider timeProvider)
{
    private static readonly TimeSpan RefreshLifetime = TimeSpan.FromDays(14);

    /// <summary>Issues a nonce that is safe to return to the browser.</summary>
    public Task<(string Nonce, DateTimeOffset ExpiresAtUtc)> IssueNonceAsync(
        string serviceName,
        string application,
        CancellationToken cancellationToken) =>
        nonceService.IssueAsync(serviceName, application, cancellationToken);

    /// <summary>Consumes the nonce before validating the credential to prevent replay.</summary>
    public async Task<GoogleExchangeResult> ExchangeAsync(
        GoogleExchangeRequest request,
        string serviceName,
        CancellationToken cancellationToken)
    {
        if (!await nonceService.ConsumeAsync(
                request.Nonce,
                serviceName,
                request.Application,
                cancellationToken))
        {
            return GoogleExchangeResult.Failed("invalid_nonce");
        }

        var validation = await tokenValidator.ValidateAsync(
            request.Credential,
            request.Application,
            request.Nonce,
            cancellationToken);
        if (!validation.Succeeded || validation.Identity is null)
        {
            return GoogleExchangeResult.Failed(validation.ErrorCode ?? "invalid_google_credential");
        }

        var identity = await employeeIdentityReader.FindActiveEmployeeByEmailAsync(
            validation.Identity.Email,
            cancellationToken);
        if (identity is null)
        {
            return GoogleExchangeResult.Failed("employee_not_found");
        }

        var now = timeProvider.GetUtcNow();
        var refreshToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var session = new RefreshSession
        {
            Id = Guid.NewGuid(),
            FamilyId = Guid.NewGuid(),
            IdentityId = identity.Id,
            IdentityKind = IdentityKind.Employee,
            SecurityStamp = identity.SecurityStamp,
            TokenHash = Hash(refreshToken),
            CreatedAt = now,
            ExpiresAt = now.Add(RefreshLifetime),
        };
        await refreshSessionStore.CreateAsync(session, cancellationToken);

        var access = accessTokenIssuer.Issue(identity, now);
        return new GoogleExchangeResult(
            true,
            new TokenResponse(access.Value, refreshToken, "Bearer", access.ExpiresInSeconds, session.ExpiresAt),
            null);
    }

    private static string Hash(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}
