using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Legacy.Maliev.Web.Application;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.WebUtilities;
using System.Globalization;
using System.Text.Json;

namespace Legacy.Maliev.Web.Infrastructure;

internal sealed class CustomerAuthenticationClient(
    IHttpClientFactory clientFactory,
    IServiceAccessTokenProvider serviceTokenProvider,
    ILogger<CustomerAuthenticationClient> logger) : ICustomerAuthenticationClient
{
    public async Task<CustomerSelfIdentityResult> GetSelfIdentityAsync(string accessToken, int expectedCustomerId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(expectedCustomerId);
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            return new(CustomerSelfIdentityStatus.NotAuthorized);
        }

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "auth/v1/customer-self-service/identity");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            using var response = await clientFactory.CreateClient("auth").SendAsync(request, cancellationToken);
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                return new(CustomerSelfIdentityStatus.NotAuthorized);
            }
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return new(CustomerSelfIdentityStatus.NotFound);
            }
            if (response.StatusCode == HttpStatusCode.TooManyRequests || (int)response.StatusCode >= 500)
            {
                return new(CustomerSelfIdentityStatus.Unavailable);
            }
            if (response.StatusCode != HttpStatusCode.OK)
            {
                return new(CustomerSelfIdentityStatus.InvalidResponse);
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || root.EnumerateObject().Count(value => value.NameEquals("customerId")) != 1
                || root.EnumerateObject().Count(value => value.NameEquals("email")) != 1
                || root.EnumerateObject().Count(value => value.NameEquals("mobile")) != 1
                || root.GetProperty("customerId").ValueKind != JsonValueKind.Number
                || !root.GetProperty("customerId").TryGetInt32(out var customerId)
                || customerId <= 0
                || root.GetProperty("email").ValueKind is not (JsonValueKind.String or JsonValueKind.Null)
                || root.GetProperty("mobile").ValueKind is not (JsonValueKind.String or JsonValueKind.Null))
            {
                return new(CustomerSelfIdentityStatus.InvalidResponse);
            }
            if (customerId != expectedCustomerId)
            {
                return new(CustomerSelfIdentityStatus.IdentityMismatch);
            }

            return new(CustomerSelfIdentityStatus.Succeeded,
                new(customerId, root.GetProperty("email").GetString(), root.GetProperty("mobile").GetString()));
        }
        catch (JsonException)
        {
            return new(CustomerSelfIdentityStatus.InvalidResponse);
        }
        catch (Exception exception) when (exception is HttpRequestException or TimeoutException
            or Polly.Timeout.TimeoutRejectedException or Polly.CircuitBreaker.BrokenCircuitException
            || (exception is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            // Do not log tokens, response bodies, contact fields, or exception text.
            return new(CustomerSelfIdentityStatus.Unavailable);
        }
    }

    public async Task<CustomerAuthenticationResult> LoginAsync(
        string email,
        string password,
        CancellationToken cancellationToken)
    {
        try
        {
            using var response = await clientFactory.CreateClient("auth").PostAsJsonAsync(
                "auth/v1/login",
                new LoginRequest(email, password, 0),
                cancellationToken);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                return new(null, true);
            }

            if (response.StatusCode == HttpStatusCode.Conflict)
            {
                var action = await ReadJsonOrNullAsync<LoginActionResponse>(
                    response.Content,
                    "customer login required action",
                    cancellationToken);
                return action is null
                    || string.IsNullOrWhiteSpace(action.Token)
                    || action.Action is not ("confirm_email" or "set_initial_password")
                    ? new(null, true)
                    : new(
                        null,
                        true,
                        null,
                        new CustomerLoginRequiredAction(action.Action, action.Token));
            }

            if (!response.IsSuccessStatusCode)
            {
                return new(null, (int)response.StatusCode < 500);
            }

            var tokens = await ReadJsonOrNullAsync<CustomerTokenSet>(
                response.Content,
                "customer login",
                cancellationToken);
            return IsValid(tokens)
                ? new(
                    tokens,
                    true,
                    ExtractDatabaseId(tokens!.AccessToken),
                    HasPassword: ExtractHasPassword(tokens.AccessToken))
                : new(null, false);
        }
        catch (Exception exception) when (IsTransient(exception, cancellationToken))
        {
            logger.LogWarning(exception, "Auth service was unavailable during customer login.");
            return new(null, false);
        }
    }

    public async Task<CustomerAuthenticationResult> RefreshAsync(
        string refreshToken,
        CancellationToken cancellationToken)
    {
        try
        {
            using var response = await clientFactory.CreateClient("auth").PostAsJsonAsync(
                "auth/v1/refresh",
                new RefreshRequest(refreshToken),
                cancellationToken);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                return new(null, true);
            }

            if (!response.IsSuccessStatusCode)
            {
                return new(null, (int)response.StatusCode < 500);
            }

            var tokens = await ReadJsonOrNullAsync<CustomerTokenSet>(
                response.Content,
                "customer session refresh",
                cancellationToken);
            return IsValid(tokens)
                ? new(
                    tokens,
                    true,
                    ExtractDatabaseId(tokens!.AccessToken),
                    HasPassword: ExtractHasPassword(tokens.AccessToken))
                : new(null, false);
        }
        catch (Exception exception) when (IsTransient(exception, cancellationToken))
        {
            logger.LogWarning(exception, "Auth service was unavailable during customer session refresh.");
            return new(null, false);
        }
    }

    public async Task RevokeAsync(string refreshToken, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await clientFactory.CreateClient("auth").PostAsJsonAsync(
                "auth/v1/revoke",
                new RefreshRequest(refreshToken),
                cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Auth service rejected customer session revocation with status {StatusCode}.", response.StatusCode);
            }
        }
        catch (Exception exception) when (IsTransient(exception, cancellationToken))
        {
            logger.LogWarning(exception, "Auth service was unavailable during customer session revocation.");
        }
    }

    public async Task<CustomerIdentityRegistration> RegisterAsync(
        int databaseId,
        string email,
        string password,
        CancellationToken cancellationToken)
    {
        using var response = await SendServiceRequestAsync(
            HttpMethod.Post,
            "auth/v1/customer-self-service/register",
            new RegisterRequest(databaseId, email, password),
            cancellationToken);
        if (response is null)
        {
            return new(false, null, null, null, ServiceAvailable: false);
        }

        if (!response.IsSuccessStatusCode)
        {
            if (response.StatusCode != HttpStatusCode.Conflict)
            {
                logger.LogWarning(
                    "Auth service rejected customer identity registration with status {StatusCode}.",
                    response.StatusCode);
            }

            return new(
                false,
                null,
                null,
                null,
                ServiceAvailable: (int)response.StatusCode < 500,
                Authorized: response.StatusCode is not (HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden),
                Conflict: response.StatusCode == HttpStatusCode.Conflict);
        }

        return await ReadJsonOrNullAsync<CustomerIdentityRegistration>(
                response.Content,
                "customer identity registration",
                cancellationToken)
            ?? new(false, null, null, null);
    }

    public async Task<CustomerIdentityRegistration> ResolveRegistrationAsync(
        int databaseId,
        string email,
        string password,
        CancellationToken cancellationToken)
    {
        using var response = await SendServiceRequestAsync(
            HttpMethod.Post,
            "auth/v1/customer-self-service/register/resolve",
            new ResolveRegistrationRequest(databaseId, email, password),
            cancellationToken);
        if (response is null)
        {
            return new(false, null, null, null, ServiceAvailable: false);
        }

        if (!response.IsSuccessStatusCode)
        {
            return new(
                false,
                null,
                null,
                null,
                ServiceAvailable: (int)response.StatusCode < 500,
                Authorized: response.StatusCode is not (HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden));
        }

        return await ReadJsonOrNullAsync<CustomerIdentityRegistration>(
                response.Content,
                "customer identity registration resolution",
                cancellationToken)
            ?? new(false, null, null, null, ServiceAvailable: false);
    }

    public Task<CustomerActionChallenge> RequestEmailConfirmationAsync(
        string email,
        CancellationToken cancellationToken) =>
        RequestChallengeAsync("email-confirmation/request", email, cancellationToken);

    public Task<bool> CompleteEmailConfirmationAsync(
        string email,
        string token,
        CancellationToken cancellationToken) =>
        CompleteActionAsync(
            "email-confirmation/complete",
            new CompleteActionRequest(email, token),
            cancellationToken);

    public Task<CustomerActionChallenge> RecoverEmailConfirmationAsync(
        string email,
        string recoveryToken,
        CancellationToken cancellationToken) =>
        CompleteChallengeAsync(
            "email-confirmation/recover",
            new CompleteActionRequest(email, recoveryToken),
            cancellationToken);

    public async Task<CustomerEmailChangeValidationResult> ValidateEmailChangeAsync(
        string email,
        string token,
        CancellationToken cancellationToken)
    {
        using var response = await SendServiceRequestAsync(
            HttpMethod.Post,
            "auth/v1/customer-self-service/email-change/validate",
            new CompleteActionRequest(email, token),
            cancellationToken);
        if (response is null)
        {
            return new(false, false, false);
        }

        var authorized = response.StatusCode is not (HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden);
        if (!authorized || !response.IsSuccessStatusCode)
        {
            return new(false, (int)response.StatusCode < 500, authorized);
        }

        var validation = await ReadJsonOrNullAsync<EmailChangeValidationResponse>(
            response.Content,
            "customer email-change validation",
            cancellationToken);
        return validation is null
            ? new(false, false, true)
            : new(
                true,
                true,
                true,
                validation.DatabaseId,
                validation.CurrentEmail,
                validation.NewEmail,
                validation.Completed);
    }

    public async Task<CustomerEmailChangeCompletionResult> CompleteEmailChangeAsync(
        string email,
        string token,
        CancellationToken cancellationToken)
    {
        using var response = await SendServiceRequestAsync(
            HttpMethod.Post,
            "auth/v1/customer-self-service/email-change/complete",
            new CompleteActionRequest(email, token),
            cancellationToken);
        if (response is null)
        {
            return new(false, false, false);
        }

        var authorized = response.StatusCode is not (HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden);
        return new(response.IsSuccessStatusCode, (int)response.StatusCode < 500, authorized);
    }

    public Task<CustomerActionChallenge> RequestPasswordResetAsync(
        string email,
        CancellationToken cancellationToken) =>
        RequestChallengeAsync("password-reset/request", email, cancellationToken);

    public Task<bool> CompletePasswordResetAsync(
        string email,
        string token,
        string password,
        CancellationToken cancellationToken) =>
        CompleteActionAsync(
            "password-reset/complete",
            new CompletePasswordResetRequest(email, token, password),
            cancellationToken);

    public Task<bool> CompleteInitialPasswordAsync(
        string email,
        string token,
        string password,
        CancellationToken cancellationToken) =>
        CompleteActionAsync(
            "initial-password/complete",
            new CompletePasswordResetRequest(email, token, password),
            cancellationToken);

    public Task<CustomerCredentialOperationResult> ChangeEmailAsync(
        string accessToken,
        string currentPassword,
        string newEmail,
        CancellationToken cancellationToken) =>
        ChangeCredentialAsync(
            "email/change",
            accessToken,
            new ChangeEmailRequest(currentPassword, newEmail),
            expectsChallenge: true,
            cancellationToken);

    public Task<CustomerCredentialOperationResult> ChangePasswordAsync(
        string accessToken,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken) =>
        ChangeCredentialAsync(
            "password/change",
            accessToken,
            new ChangePasswordRequest(currentPassword, newPassword),
            expectsChallenge: false,
            cancellationToken);

    public async Task<CustomerPasswordCreationResult> CreatePasswordAsync(
        string accessToken,
        string newPassword,
        CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Post,
                "auth/v1/customer-self-service/password/create")
            {
                Content = JsonContent.Create(new CreatePasswordRequest(newPassword)),
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            using var response = await clientFactory.CreateClient("auth").SendAsync(request, cancellationToken);
            var authorized = response.StatusCode is not (HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden);
            return response.StatusCode switch
            {
                HttpStatusCode.NoContent => new(true, true, true, false),
                HttpStatusCode.Conflict => new(false, true, true, true),
                HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => new(false, true, false, false),
                _ when (int)response.StatusCode >= 500 => new(false, false, authorized, false),
                _ => new(false, true, authorized, false),
            };
        }
        catch (Exception exception) when (IsTransient(exception, cancellationToken))
        {
            logger.LogWarning(exception, "Auth service was unavailable while creating a customer password.");
            return new(false, false, true, false);
        }
    }

    private async Task<CustomerCredentialOperationResult> ChangeCredentialAsync(
        string action,
        string accessToken,
        object content,
        bool expectsChallenge,
        CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Post,
                $"auth/v1/customer-self-service/{action}")
            {
                Content = JsonContent.Create(content),
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            using var response = await clientFactory.CreateClient("auth").SendAsync(
                request,
                cancellationToken);
            var authorized = response.StatusCode is not (HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden);
            if (!response.IsSuccessStatusCode)
            {
                return new(false, (int)response.StatusCode < 500, authorized);
            }

            if (!expectsChallenge)
            {
                return new(true, true, true);
            }

            var challenge = await ReadJsonOrNullAsync<ChallengeResponse>(
                response.Content,
                "customer credential challenge",
                cancellationToken);
            return challenge is null
                ? new(false, false, true)
                : new(challenge.Accepted && challenge.Token is not null, true, true, challenge.Token);
        }
        catch (Exception exception) when (IsTransient(exception, cancellationToken))
        {
            logger.LogWarning(exception, "Auth service was unavailable during a customer credential change.");
            return new(false, false, true);
        }
    }

    private async Task<CustomerActionChallenge> RequestChallengeAsync(
        string action,
        string email,
        CancellationToken cancellationToken)
    {
        using var response = await SendServiceRequestAsync(
            HttpMethod.Post,
            $"auth/v1/customer-self-service/{action}",
            new ActionRequest(email),
            cancellationToken);
        if (response is null)
        {
            return new(false, null, false, false);
        }

        var authorized = response.StatusCode is not HttpStatusCode.Unauthorized and not HttpStatusCode.Forbidden;
        if (!authorized)
        {
            return new(false, null, true, false);
        }

        if (!response.IsSuccessStatusCode)
        {
            logger.LogWarning(
                "Auth service rejected customer challenge creation with status {StatusCode}.",
                response.StatusCode);
            return new(false, null, (int)response.StatusCode < 500, true);
        }

        var challenge = await ReadJsonOrNullAsync<ChallengeResponse>(
            response.Content,
            "customer action challenge",
            cancellationToken);
        return challenge is null
            ? new(false, null, false, true)
            : new(challenge.Accepted, challenge.Token, true, true);
    }

    private async Task<CustomerActionChallenge> CompleteChallengeAsync(
        string action,
        object content,
        CancellationToken cancellationToken)
    {
        using var response = await SendServiceRequestAsync(
            HttpMethod.Post,
            $"auth/v1/customer-self-service/{action}",
            content,
            cancellationToken);
        if (response is null)
        {
            return new(false, null, false, false);
        }

        var authorized = response.StatusCode is not HttpStatusCode.Unauthorized and not HttpStatusCode.Forbidden;
        if (!authorized || !response.IsSuccessStatusCode)
        {
            return new(false, null, (int)response.StatusCode < 500, authorized);
        }

        var challenge = await ReadJsonOrNullAsync<ChallengeResponse>(
            response.Content,
            "customer recovery challenge",
            cancellationToken);
        return challenge is null
            ? new(false, null, false, true)
            : new(challenge.Accepted, challenge.Token, true, true);
    }

    private async Task<bool> CompleteActionAsync(
        string action,
        object content,
        CancellationToken cancellationToken)
    {
        using var response = await SendServiceRequestAsync(
            HttpMethod.Post,
            $"auth/v1/customer-self-service/{action}",
            content,
            cancellationToken);
        return response?.IsSuccessStatusCode == true;
    }

    private async Task<HttpResponseMessage?> SendServiceRequestAsync(
        HttpMethod method,
        string path,
        object content,
        CancellationToken cancellationToken)
    {
        var token = await serviceTokenProvider.GetAccessTokenAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(token))
        {
            logger.LogWarning("Customer identity request was rejected because service authentication was unavailable.");
            return null;
        }

        try
        {
            using var request = new HttpRequestMessage(method, path)
            {
                Content = JsonContent.Create(content),
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var response = await clientFactory.CreateClient("auth").SendAsync(request, cancellationToken);
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                serviceTokenProvider.Invalidate(token);
            }

            return response;
        }
        catch (Exception exception) when (IsTransient(exception, cancellationToken))
        {
            logger.LogWarning(exception, "Auth service was unavailable during customer self-service.");
            return null;
        }
    }

    private static bool IsTransient(Exception exception, CancellationToken cancellationToken) =>
        exception is HttpRequestException
        || (exception is TaskCanceledException && !cancellationToken.IsCancellationRequested);

    private async Task<T?> ReadJsonOrNullAsync<T>(
        HttpContent content,
        string operation,
        CancellationToken cancellationToken)
    {
        try
        {
            return await content.ReadFromJsonAsync<T>(cancellationToken);
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException)
        {
            logger.LogWarning(exception, "Auth service returned an invalid response during {Operation}.", operation);
            return default;
        }
    }

    private static bool IsValid(CustomerTokenSet? tokens) =>
        tokens is not null
        && !string.IsNullOrWhiteSpace(tokens.AccessToken)
        && !string.IsNullOrWhiteSpace(tokens.RefreshToken)
        && string.Equals(tokens.TokenType, "Bearer", StringComparison.OrdinalIgnoreCase)
        && tokens.ExpiresIn > 0
        && tokens.RefreshExpiresAt > DateTimeOffset.UnixEpoch;

    private static int? ExtractDatabaseId(string? accessToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            return null;
        }

        var segments = accessToken.Split('.');
        if (segments.Length != 3)
        {
            return null;
        }

        try
        {
            using var payload = JsonDocument.Parse(WebEncoders.Base64UrlDecode(segments[1]));
            if (!payload.RootElement.TryGetProperty("legacy_database_id", out var claim))
            {
                return null;
            }

            return claim.ValueKind switch
            {
                JsonValueKind.Number when claim.TryGetInt32(out var number) && number > 0 => number,
                JsonValueKind.String when int.TryParse(
                    claim.GetString(),
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out var number) && number > 0 => number,
                _ => null,
            };
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            return null;
        }
    }

    private static bool ExtractHasPassword(string accessToken)
    {
        try
        {
            var segments = accessToken.Split('.');
            if (segments.Length != 3)
            {
                return true;
            }

            using var payload = JsonDocument.Parse(WebEncoders.Base64UrlDecode(segments[1]));
            return !payload.RootElement.TryGetProperty("has_password", out var claim)
                || claim.ValueKind is not JsonValueKind.False;
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            return true;
        }
    }

    private sealed record LoginRequest(string UserName, string Password, int IdentityKind);
    private sealed record LoginActionResponse(string Action, string Token);
    private sealed record RefreshRequest(string RefreshToken);
    private sealed record RegisterRequest(int DatabaseId, string Email, string Password);
    private sealed record ResolveRegistrationRequest(int DatabaseId, string Email, string Password);
    private sealed record ActionRequest(string Email);
    private sealed record CompleteActionRequest(string Email, string Token);
    private sealed record CompletePasswordResetRequest(string Email, string Token, string Password);
    private sealed record EmailChangeValidationResponse(
        int DatabaseId,
        string CurrentEmail,
        string NewEmail,
        bool Completed = false);
    private sealed record ChangeEmailRequest(string CurrentPassword, string NewEmail);
    private sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);
    private sealed record CreatePasswordRequest(string NewPassword);
    private sealed record ChallengeResponse(bool Accepted, string? Token);
}
