using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Legacy.Maliev.AuthService.Infrastructure;

/// <summary>Resolves original default providers and authenticated remembered-client trust at password issuance only.</summary>
public sealed class EmployeePasswordTwoFactorPolicy(
    IServiceProvider services,
    IHttpContextAccessor contextAccessor,
    IAuthenticationSchemeProvider schemes,
    TimeProvider? clock = null)
{
    /// <summary>Reads provider eligibility from the same locked employee row and original token store.</summary>
    public async Task<EmployeePasswordTwoFactorDecision> EvaluateAsync(
        LegacyIdentityRow row, LegacyIdentityDbContext context, CancellationToken cancellationToken)
    {
        if (!row.TwoFactorEnabled) return new(false, false, []);
        // The original Identity UserStore uses this exact key, provider and token name.
        // A missing/unmigrated token table is a runtime error, not proof that no provider exists.
        var keys = await context.Database.SqlQuery<string?>($"""
            SELECT "Value" FROM "AspNetUserTokens"
            WHERE "UserId" = {row.Id} AND "LoginProvider" = '[AspNetUserStore]' AND "Name" = 'AuthenticatorKey'
            """).ToListAsync(cancellationToken);
        var user = new IdentityUser
        {
            Id = row.Id, UserName = row.UserName, Email = row.Email, EmailConfirmed = row.EmailConfirmed,
            PhoneNumber = row.PhoneNumber, PhoneNumberConfirmed = row.PhoneNumberConfirmed,
            TwoFactorEnabled = row.TwoFactorEnabled, SecurityStamp = row.SecurityStamp,
        };
        using var store = new ProviderReadStore(user, keys.SingleOrDefault());
        using var manager = new UserManager<IdentityUser>(store, Options.Create(new IdentityOptions()),
            new PasswordHasher<IdentityUser>(), [], [], new UpperInvariantLookupNormalizer(),
            new IdentityErrorDescriber(), services, NullLogger<UserManager<IdentityUser>>.Instance);
        manager.RegisterTokenProvider(TokenOptions.DefaultEmailProvider, new EmailTokenProvider<IdentityUser>());
        manager.RegisterTokenProvider(TokenOptions.DefaultPhoneProvider, new PhoneNumberTokenProvider<IdentityUser>());
        manager.RegisterTokenProvider(TokenOptions.DefaultAuthenticatorProvider, new AuthenticatorTokenProvider<IdentityUser>());
        var providers = await manager.GetValidTwoFactorProvidersAsync(user);
        var enabled = manager.SupportsUserTwoFactor && await manager.GetTwoFactorEnabledAsync(user) && providers.Count > 0;
        var remembered = enabled && await IsRememberedAsync(row);
        return new(enabled, remembered, providers.ToArray());
    }

    private async Task<bool> IsRememberedAsync(LegacyIdentityRow row)
    {
        var context = contextAccessor.HttpContext;
        if (context is null || await schemes.GetSchemeAsync(IdentityConstants.TwoFactorRememberMeScheme) is null)
            return false;
        // This is authenticated server evidence, never a login JSON boolean or arbitrary header.
        var remembered = await context.AuthenticateAsync(IdentityConstants.TwoFactorRememberMeScheme);
        var valid = remembered.Succeeded && remembered.Principal?.Identity?.IsAuthenticated == true
            && remembered.Ticket?.AuthenticationScheme == IdentityConstants.TwoFactorRememberMeScheme
            && remembered.Principal.FindFirstValue(ClaimTypes.Name) == row.Id
            && !string.IsNullOrWhiteSpace(row.SecurityStamp)
            && remembered.Principal.FindFirstValue(new IdentityOptions().ClaimsIdentity.SecurityStampClaimType) == row.SecurityStamp;
        if (valid && remembered.Properties?.AllowRefresh != false && remembered.Properties?.IssuedUtc is { } issued && remembered.Properties.ExpiresUtc is { } expires)
        {
            var now = (clock ?? TimeProvider.System).GetUtcNow();
            // Preserve original CookieAuthenticationHandler midpoint and duration semantics.
            // No renewal is possible before the locked row's subject/stamp/password checks.
            if (expires > now && now - issued > expires - now)
            {
                var renewal = new AuthenticationProperties(new Dictionary<string, string?>(remembered.Properties.Items))
                { IssuedUtc = now, ExpiresUtc = now + (expires - issued) };
                await context.SignInAsync(IdentityConstants.TwoFactorRememberMeScheme, remembered.Principal!, renewal);
            }
        }
        return valid;
    }

    private sealed class ProviderReadStore(IdentityUser user, string? key) :
        IUserStore<IdentityUser>, IUserEmailStore<IdentityUser>, IUserPhoneNumberStore<IdentityUser>,
        IUserTwoFactorStore<IdentityUser>, IUserAuthenticatorKeyStore<IdentityUser>
    {
        public void Dispose() { }
        public Task<string> GetUserIdAsync(IdentityUser value, CancellationToken token) => Task.FromResult(value.Id);
        public Task<string?> GetUserNameAsync(IdentityUser value, CancellationToken token) => Task.FromResult(value.UserName);
        public Task<string?> GetNormalizedUserNameAsync(IdentityUser value, CancellationToken token) => Task.FromResult(value.NormalizedUserName);
        public Task<IdentityUser?> FindByIdAsync(string id, CancellationToken token) => Task.FromResult(id == user.Id ? user : null);
        public Task<IdentityUser?> FindByNameAsync(string name, CancellationToken token) => Task.FromResult<IdentityUser?>(null);
        public Task<string?> GetEmailAsync(IdentityUser value, CancellationToken token) => Task.FromResult(value.Email);
        public Task<bool> GetEmailConfirmedAsync(IdentityUser value, CancellationToken token) => Task.FromResult(value.EmailConfirmed);
        public Task<string?> GetNormalizedEmailAsync(IdentityUser value, CancellationToken token) => Task.FromResult(value.NormalizedEmail);
        public Task<IdentityUser?> FindByEmailAsync(string email, CancellationToken token) => Task.FromResult<IdentityUser?>(null);
        public Task<string?> GetPhoneNumberAsync(IdentityUser value, CancellationToken token) => Task.FromResult(value.PhoneNumber);
        public Task<bool> GetPhoneNumberConfirmedAsync(IdentityUser value, CancellationToken token) => Task.FromResult(value.PhoneNumberConfirmed);
        public Task<bool> GetTwoFactorEnabledAsync(IdentityUser value, CancellationToken token) => Task.FromResult(value.TwoFactorEnabled);
        public Task<string?> GetAuthenticatorKeyAsync(IdentityUser value, CancellationToken token) => Task.FromResult(key);
        public Task SetUserNameAsync(IdentityUser value, string? name, CancellationToken token) => throw ReadOnly();
        public Task SetNormalizedUserNameAsync(IdentityUser value, string? name, CancellationToken token) => throw ReadOnly();
        public Task<IdentityResult> CreateAsync(IdentityUser value, CancellationToken token) => throw ReadOnly();
        public Task<IdentityResult> UpdateAsync(IdentityUser value, CancellationToken token) => throw ReadOnly();
        public Task<IdentityResult> DeleteAsync(IdentityUser value, CancellationToken token) => throw ReadOnly();
        public Task SetEmailAsync(IdentityUser value, string? email, CancellationToken token) => throw ReadOnly();
        public Task SetEmailConfirmedAsync(IdentityUser value, bool confirmed, CancellationToken token) => throw ReadOnly();
        public Task SetNormalizedEmailAsync(IdentityUser value, string? email, CancellationToken token) => throw ReadOnly();
        public Task SetPhoneNumberAsync(IdentityUser value, string? number, CancellationToken token) => throw ReadOnly();
        public Task SetPhoneNumberConfirmedAsync(IdentityUser value, bool confirmed, CancellationToken token) => throw ReadOnly();
        public Task SetTwoFactorEnabledAsync(IdentityUser value, bool enabled, CancellationToken token) => throw ReadOnly();
        public Task SetAuthenticatorKeyAsync(IdentityUser value, string valueKey, CancellationToken token) => throw ReadOnly();
        private static NotSupportedException ReadOnly() => new("Provider resolution cannot mutate identity state.");
    }
}

/// <summary>Original issuance predicate; active identity and refresh eligibility are separate contracts.</summary>
public sealed record EmployeePasswordTwoFactorDecision(bool EnabledWithProvider, bool RememberedClient, string[] Providers)
{
    /// <summary>Whether a correct password must return the original unresolved second-factor result.</summary>
    public bool RequiresTwoFactor => EnabledWithProvider && !RememberedClient;
}
