// <copyright file="InitialPasswordSetupTests.cs" company="Maliev Company Limited">
// Copyright (c) Maliev Company Limited. All rights reserved.
// </copyright>

namespace Maliev.Web.Tests
{
    using Maliev.Identities;
    using Maliev.Service.WebApi;
    using Maliev.Service.WebApi.Model;
    using Maliev.Web.Pages.Account;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.DataProtection;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using Microsoft.AspNetCore.Mvc.Routing;
    using Microsoft.AspNetCore.Routing;
    using Microsoft.AspNetCore.WebUtilities;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Localization;
    using Microsoft.Extensions.Logging;
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Security.Claims;
    using System.Threading;
    using System.Threading.Tasks;
    using Xunit;

    public class InitialPasswordSetupTests
    {
        [Fact]
        public async Task SetPassword_ValidOneTimeToken_ReplacesTemporaryPasswordSendsEmailAndStartsMemberSession()
        {
            await using PasswordSetupFixture fixture = await PasswordSetupFixture.CreateAsync();
            SetInitialPassword page = await fixture.CreatePageAsync("Customer-owned-password-456!");

            IActionResult result = await page.OnPostSetPasswordAsync();

            RedirectToPageResult redirect = Assert.IsType<RedirectToPageResult>(result);
            Assert.Equal("/Index", redirect.PageName);
            Assert.Equal("Member", redirect.RouteValues!["area"]);
            Assert.True(await fixture.UserManager.CheckPasswordAsync(fixture.User, "Customer-owned-password-456!"));
            Assert.False(await fixture.UserManager.CheckPasswordAsync(fixture.User, PasswordSetupFixture.TemporaryPassword));
            Assert.DoesNotContain(
                fixture.Store.Claims,
                claim => claim.Type == "maliev:credential_state" && claim.Value == "temporary_password");
            Assert.Contains("/emails/noreply-plaintext/", fixture.WebApi.PostedRequestUri, StringComparison.Ordinal);
            Assert.Contains(
                page.Response.Headers.SetCookie,
                value => value.Contains(IdentityConstants.ApplicationScheme, StringComparison.Ordinal));
        }

        [Fact]
        public async Task SetPassword_InvalidToken_DoesNotChangeCredentialOrCreateSession()
        {
            await using PasswordSetupFixture fixture = await PasswordSetupFixture.CreateAsync();
            SetInitialPassword page = await fixture.CreatePageAsync("Customer-owned-password-456!", token: "not-a-token");

            IActionResult result = await page.OnPostSetPasswordAsync();

            Assert.IsType<PageResult>(result);
            Assert.True(await fixture.UserManager.CheckPasswordAsync(fixture.User, PasswordSetupFixture.TemporaryPassword));
            Assert.Contains(
                fixture.Store.Claims,
                claim => claim.Type == "maliev:credential_state" && claim.Value == "temporary_password");
            Assert.Contains(
                page.ModelState[string.Empty]!.Errors,
                error => error.ErrorMessage == "The password setup link is invalid or has expired. Please sign in again.");
            Assert.Null(fixture.WebApi.PostedRequestUri);
            Assert.Equal(0, page.Response.Headers.SetCookie.Count);
        }

        [Fact]
        public async Task SetPassword_WeakNewPassword_ReturnsPasswordGuidanceWithoutConsumingSetup()
        {
            await using PasswordSetupFixture fixture = await PasswordSetupFixture.CreateAsync();
            SetInitialPassword page = await fixture.CreatePageAsync("weak");

            IActionResult result = await page.OnPostSetPasswordAsync();

            Assert.IsType<PageResult>(result);
            Assert.Contains(
                page.ModelState[string.Empty]!.Errors,
                error => error.ErrorMessage == "Choose a stronger password that meets all password requirements.");
            Assert.DoesNotContain(
                page.ModelState[string.Empty]!.Errors,
                error => error.ErrorMessage.Contains("link is invalid", StringComparison.OrdinalIgnoreCase));
            Assert.True(await fixture.UserManager.CheckPasswordAsync(fixture.User, PasswordSetupFixture.TemporaryPassword));
            Assert.Contains(
                fixture.Store.Claims,
                claim => claim.Type == "maliev:credential_state" && claim.Value == "temporary_password");
            Assert.Null(fixture.WebApi.PostedRequestUri);
        }

        [Fact]
        public async Task SetPassword_UserWithoutTemporaryMarker_RejectsPasswordResetToken()
        {
            await using PasswordSetupFixture fixture = await PasswordSetupFixture.CreateAsync(includeTemporaryMarker: false);
            SetInitialPassword page = await fixture.CreatePageAsync("Customer-owned-password-456!");

            IActionResult result = await page.OnPostSetPasswordAsync();

            Assert.IsType<BadRequestResult>(result);
            Assert.True(await fixture.UserManager.CheckPasswordAsync(fixture.User, PasswordSetupFixture.TemporaryPassword));
            Assert.Null(fixture.WebApi.PostedRequestUri);
        }

        [Fact]
        public async Task SetPassword_MismatchedConfirmation_DoesNotChangeCredential()
        {
            await using PasswordSetupFixture fixture = await PasswordSetupFixture.CreateAsync();
            SetInitialPassword page = await fixture.CreatePageAsync("Customer-owned-password-456!");
            page.ConfirmPassword = "different-password";

            IActionResult result = await page.OnPostSetPasswordAsync();

            Assert.IsType<PageResult>(result);
            Assert.True(await fixture.UserManager.CheckPasswordAsync(fixture.User, PasswordSetupFixture.TemporaryPassword));
            Assert.Contains(
                page.ModelState[nameof(SetInitialPassword.ConfirmPassword)]!.Errors,
                error => error.ErrorMessage == "Password confirmation does not match.");
            Assert.Null(fixture.WebApi.PostedRequestUri);
        }

        [Theory]
        [InlineData(null, "token")]
        [InlineData("customer@example.com", null)]
        public async Task Load_MissingBootstrapCredential_ReturnsBadRequest(string email, string token)
        {
            await using PasswordSetupFixture fixture = await PasswordSetupFixture.CreateAsync();
            SetInitialPassword page = await fixture.CreatePageAsync("Customer-owned-password-456!");

            IActionResult result = page.OnGet(email, token, null, false);

            Assert.IsType<BadRequestResult>(result);
        }

        [Fact]
        public async Task SetPassword_ExternalReturnUrl_IsIgnored()
        {
            await using PasswordSetupFixture fixture = await PasswordSetupFixture.CreateAsync();
            SetInitialPassword page = await fixture.CreatePageAsync(
                "Customer-owned-password-456!",
                returnUrl: "https://attacker.invalid/steal");

            IActionResult result = await page.OnPostSetPasswordAsync();

            RedirectToPageResult redirect = Assert.IsType<RedirectToPageResult>(result);
            Assert.Equal("/Index", redirect.PageName);
            Assert.Equal("Member", redirect.RouteValues!["area"]);
        }

        [Fact]
        public async Task SetPassword_ThaiUi_SendsOnlyThaiPasswordChangedEmail()
        {
            using CultureScope culture = new CultureScope("th");
            await using PasswordSetupFixture fixture = await PasswordSetupFixture.CreateAsync();
            SetInitialPassword page = await fixture.CreatePageAsync("Customer-owned-password-456!");

            await page.OnPostSetPasswordAsync();

            Dictionary<string, Microsoft.Extensions.Primitives.StringValues> query =
                QueryHelpers.ParseQuery(new Uri("https://email-api.invalid" + fixture.WebApi.PostedRequestUri).Query);
            Assert.Equal("รหัสผ่าน MALIEV ของคุณได้รับการเปลี่ยนแล้ว", query["subject"].ToString());
            string decodedBody = WebUtility.HtmlDecode(fixture.WebApi.PostedContent);
            Assert.Contains("รหัสผ่านของคุณได้รับการเปลี่ยนเรียบร้อยแล้ว", decodedBody, StringComparison.Ordinal);
            Assert.DoesNotContain("Your password was changed", decodedBody, StringComparison.Ordinal);
        }

        [Fact]
        public void PasswordSetupResource_ThaiUi_ResolvesSingleLanguageMessages()
        {
            using CultureScope culture = new CultureScope("th");
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddLocalization(options => options.ResourcesPath = "Resources");
            using ServiceProvider provider = services.BuildServiceProvider();
            IStringLocalizer<SetInitialPassword> localizer = provider.GetRequiredService<IStringLocalizer<SetInitialPassword>>();

            Assert.Equal("ตั้งรหัสผ่านใหม่", localizer["Set your new password"].Value);
            Assert.Equal(
                "รหัสผ่าน MALIEV ของคุณได้รับการเปลี่ยนแล้ว",
                localizer["Your MALIEV password was changed"].Value);
        }

        private sealed class PasswordSetupFixture : IAsyncDisposable
        {
            public const string TemporaryPassword = "Temporary-password-123!";
            private readonly ServiceProvider services;

            private PasswordSetupFixture(
                ServiceProvider services,
                ApplicationUser user,
                PasswordSetupUserStore store,
                RecordingWebApiService webApi)
            {
                this.services = services;
                this.User = user;
                this.Store = store;
                this.WebApi = webApi;
                this.UserManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            }

            public ApplicationUser User { get; }

            public UserManager<ApplicationUser> UserManager { get; }

            public PasswordSetupUserStore Store { get; }

            public RecordingWebApiService WebApi { get; }

            public static Task<PasswordSetupFixture> CreateAsync(bool includeTemporaryMarker = true)
            {
                var user = new ApplicationUser
                {
                    Id = Guid.NewGuid().ToString(),
                    UserName = "customer@example.com",
                    NormalizedUserName = "CUSTOMER@EXAMPLE.COM",
                    Email = "customer@example.com",
                    NormalizedEmail = "CUSTOMER@EXAMPLE.COM",
                    EmailConfirmed = true,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    LockoutEnabled = true,
                };
                var store = new PasswordSetupUserStore(user);
                if (includeTemporaryMarker)
                {
                    store.Claims.Add(new Claim("maliev:credential_state", "temporary_password"));
                }

                var services = new ServiceCollection();
                services.AddLogging();
                services.AddDataProtection().UseEphemeralDataProtectionProvider();
                services.AddSingleton<IUserStore<ApplicationUser>>(store);
                services.AddAuthentication(IdentityConstants.ApplicationScheme).AddCookie(IdentityConstants.ApplicationScheme);
                services
                    .AddIdentityCore<ApplicationUser>()
                    .AddSignInManager()
                    .AddTokenProvider<DataProtectorTokenProvider<ApplicationUser>>(TokenOptions.DefaultProvider);
                ServiceProvider provider = services.BuildServiceProvider();
                UserManager<ApplicationUser> manager = provider.GetRequiredService<UserManager<ApplicationUser>>();
                user.PasswordHash = manager.PasswordHasher.HashPassword(user, TemporaryPassword);
                return Task.FromResult(new PasswordSetupFixture(provider, user, store, new RecordingWebApiService()));
            }

            public async Task<SetInitialPassword> CreatePageAsync(
                string newPassword,
                string token = null,
                string returnUrl = null)
            {
                var httpContext = new DefaultHttpContext
                {
                    RequestServices = this.services,
                    User = new ClaimsPrincipal(new ClaimsIdentity()),
                };
                httpContext.Request.Scheme = "https";
                httpContext.Request.Host = new HostString("www.maliev.com");
                SignInManager<ApplicationUser> signInManager = this.services.GetRequiredService<SignInManager<ApplicationUser>>();
                signInManager.Context = httpContext;
                string passwordToken = token ?? IdentityEmailTokenCodec.Encode(await this.UserManager.GeneratePasswordResetTokenAsync(this.User));
                var page = new SetInitialPassword(
                    this.UserManager,
                    signInManager,
                    null,
                    this.WebApi,
                    new PasswordSetupStringLocalizer(),
                    this.services.GetRequiredService<ILogger<SetInitialPassword>>())
                {
                    Email = this.User.Email,
                    Token = passwordToken,
                    Password = newPassword,
                    ConfirmPassword = newPassword,
                    ReturnUrl = returnUrl,
                    PageContext = new Microsoft.AspNetCore.Mvc.RazorPages.PageContext { HttpContext = httpContext },
                };
                page.Url = new PasswordSetupUrlHelper(httpContext);
                return page;
            }

            public ValueTask DisposeAsync() => this.services.DisposeAsync();
        }

        private sealed class PasswordSetupUrlHelper : IUrlHelper
        {
            public PasswordSetupUrlHelper(HttpContext context) =>
                this.ActionContext = new ActionContext(context, new RouteData(), new Microsoft.AspNetCore.Mvc.Abstractions.ActionDescriptor());

            public ActionContext ActionContext { get; }

            public string Action(UrlActionContext actionContext) => throw new NotSupportedException();

            public string Content(string contentPath) => contentPath;

            public bool IsLocalUrl(string url) => !string.IsNullOrEmpty(url) && url.StartsWith('/') && !url.StartsWith("//", StringComparison.Ordinal);

            public string Link(string routeName, object values) => throw new NotSupportedException();

            public string RouteUrl(UrlRouteContext routeContext) => throw new NotSupportedException();
        }

        private sealed class RecordingWebApiService : IWebApiService
        {
            public string PostedRequestUri { get; private set; }

            public string PostedContent { get; private set; }

            public async Task<HttpResponseMessage> Post(string requestUri, HttpContent content, string bearerToken = null)
            {
                this.PostedRequestUri = requestUri;
                this.PostedContent = content == null ? null : await content.ReadAsStringAsync();
                return new HttpResponseMessage(HttpStatusCode.OK);
            }

            public Task<string> RequestJwtTokenAsync(string username, string password, string currentToken = null) => Task.FromResult("service-token");

            public void SetClientFactory(IHttpClientFactory clientFactory)
            {
            }

            public Task<HttpResponseMessage> Delete(string requestUri, string bearerToken = null) => throw new NotSupportedException();
            public Task<HttpResponseMessage> Get(string requestUri, string bearerToken = null) => throw new NotSupportedException();
            public Task<ApiResponse<T>> GetAs<T>(string requestUri, string bearerToken = null) => throw new NotSupportedException();
            public Task<string> GetAsString(string requestUri, string bearerToken = null) => throw new NotSupportedException();
            public Task<HttpResponseMessage> GetExternal(string requestUri, string bearerToken = null) => throw new NotSupportedException();
            public Task<ApiResponse<T>> GetExternalAs<T>(string requestUri, string bearerToken = null) => throw new NotSupportedException();
            public Task<ApiResponse<T>> Post<T>(string requestUri, HttpContent content, string bearerToken = null) => throw new NotSupportedException();
            public Task<HttpResponseMessage> PostByteArray(string requestUri, byte[] content, string bearerToken = null) => throw new NotSupportedException();
            public Task<HttpResponseMessage> Put(string requestUri, HttpContent content, string bearerToken = null) => throw new NotSupportedException();
        }

        private sealed class PasswordSetupStringLocalizer : IStringLocalizer<SetInitialPassword>
        {
            private static readonly IReadOnlyDictionary<string, string> Thai = new Dictionary<string, string>
            {
                ["Your MALIEV password was changed"] = "รหัสผ่าน MALIEV ของคุณได้รับการเปลี่ยนแล้ว",
                ["Your password was changed successfully."] = "รหัสผ่านของคุณได้รับการเปลี่ยนเรียบร้อยแล้ว",
                ["If you did not make this change, contact MALIEV support immediately."] = "หากคุณไม่ได้ดำเนินการนี้ โปรดติดต่อฝ่ายสนับสนุนของ MALIEV ทันที",
                ["The password setup link is invalid or has expired. Please sign in again."] = "ลิงก์ตั้งรหัสผ่านไม่ถูกต้องหรือหมดอายุ โปรดเข้าสู่ระบบอีกครั้ง",
                ["Password confirmation does not match."] = "การยืนยันรหัสผ่านไม่ตรงกัน",
                ["Choose a stronger password that meets all password requirements."] = "โปรดเลือกรหัสผ่านที่ปลอดภัยและตรงตามข้อกำหนดทั้งหมด",
            };

            public LocalizedString this[string name] => new LocalizedString(
                name,
                CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "th" && Thai.TryGetValue(name, out string value) ? value : name);

            public LocalizedString this[string name, params object[] arguments] =>
                new LocalizedString(name, string.Format(CultureInfo.CurrentUICulture, this[name].Value, arguments));

            public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures) =>
                Thai.Select(item => new LocalizedString(item.Key, item.Value));
        }

        private sealed class CultureScope : IDisposable
        {
            private readonly CultureInfo originalCulture = CultureInfo.CurrentCulture;
            private readonly CultureInfo originalUiCulture = CultureInfo.CurrentUICulture;

            public CultureScope(string culture)
            {
                CultureInfo selected = CultureInfo.GetCultureInfo(culture);
                CultureInfo.CurrentCulture = selected;
                CultureInfo.CurrentUICulture = selected;
            }

            public void Dispose()
            {
                CultureInfo.CurrentCulture = this.originalCulture;
                CultureInfo.CurrentUICulture = this.originalUiCulture;
            }
        }

        private sealed class PasswordSetupUserStore :
            IUserStore<ApplicationUser>,
            IUserEmailStore<ApplicationUser>,
            IUserPasswordStore<ApplicationUser>,
            IUserSecurityStampStore<ApplicationUser>,
            IUserLockoutStore<ApplicationUser>,
            IUserClaimStore<ApplicationUser>
        {
            private readonly ApplicationUser user;

            public PasswordSetupUserStore(ApplicationUser user) => this.user = user;

            public List<Claim> Claims { get; } = new List<Claim>();

            public void Dispose()
            {
            }

            public Task AddClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
            {
                this.Claims.AddRange(claims);
                return Task.CompletedTask;
            }

            public Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken cancellationToken) => Task.FromResult(IdentityResult.Success);
            public Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken cancellationToken) => Task.FromResult(IdentityResult.Success);
            public Task<ApplicationUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken) => Task.FromResult(normalizedEmail == this.user.NormalizedEmail ? this.user : null);
            public Task<ApplicationUser> FindByIdAsync(string userId, CancellationToken cancellationToken) => Task.FromResult(userId == this.user.Id ? this.user : null);
            public Task<ApplicationUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken) => Task.FromResult(normalizedUserName == this.user.NormalizedUserName ? this.user : null);
            public Task<int> GetAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken) => Task.FromResult(user.AccessFailedCount);
            public Task<IList<Claim>> GetClaimsAsync(ApplicationUser user, CancellationToken cancellationToken) => Task.FromResult<IList<Claim>>(this.Claims.ToList());
            public Task<string> GetEmailAsync(ApplicationUser user, CancellationToken cancellationToken) => Task.FromResult(user.Email);
            public Task<bool> GetEmailConfirmedAsync(ApplicationUser user, CancellationToken cancellationToken) => Task.FromResult(user.EmailConfirmed);
            public Task<bool> GetLockoutEnabledAsync(ApplicationUser user, CancellationToken cancellationToken) => Task.FromResult(user.LockoutEnabled);
            public Task<DateTimeOffset?> GetLockoutEndDateAsync(ApplicationUser user, CancellationToken cancellationToken) => Task.FromResult(user.LockoutEnd);
            public Task<string> GetNormalizedEmailAsync(ApplicationUser user, CancellationToken cancellationToken) => Task.FromResult(user.NormalizedEmail);
            public Task<string> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken cancellationToken) => Task.FromResult(user.NormalizedUserName);
            public Task<string> GetPasswordHashAsync(ApplicationUser user, CancellationToken cancellationToken) => Task.FromResult(user.PasswordHash);
            public Task<string> GetSecurityStampAsync(ApplicationUser user, CancellationToken cancellationToken) => Task.FromResult(user.SecurityStamp);
            public Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken cancellationToken) => Task.FromResult(user.Id);
            public Task<string> GetUserNameAsync(ApplicationUser user, CancellationToken cancellationToken) => Task.FromResult(user.UserName);
            public Task<IList<ApplicationUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken) => Task.FromResult<IList<ApplicationUser>>(new List<ApplicationUser>());
            public Task<bool> HasPasswordAsync(ApplicationUser user, CancellationToken cancellationToken) => Task.FromResult(!string.IsNullOrEmpty(user.PasswordHash));
            public Task<int> IncrementAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken) => Task.FromResult(++user.AccessFailedCount);

            public Task RemoveClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
            {
                foreach (Claim claim in claims)
                {
                    this.Claims.RemoveAll(existing => existing.Type == claim.Type && existing.Value == claim.Value);
                }

                return Task.CompletedTask;
            }

            public Task ReplaceClaimAsync(ApplicationUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
            {
                this.Claims.RemoveAll(existing => existing.Type == claim.Type && existing.Value == claim.Value);
                this.Claims.Add(newClaim);
                return Task.CompletedTask;
            }

            public Task ResetAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken) => SetAsync(() => user.AccessFailedCount = 0);
            public Task SetEmailAsync(ApplicationUser user, string email, CancellationToken cancellationToken) => SetAsync(() => user.Email = email);
            public Task SetEmailConfirmedAsync(ApplicationUser user, bool confirmed, CancellationToken cancellationToken) => SetAsync(() => user.EmailConfirmed = confirmed);
            public Task SetLockoutEnabledAsync(ApplicationUser user, bool enabled, CancellationToken cancellationToken) => SetAsync(() => user.LockoutEnabled = enabled);
            public Task SetLockoutEndDateAsync(ApplicationUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken) => SetAsync(() => user.LockoutEnd = lockoutEnd);
            public Task SetNormalizedEmailAsync(ApplicationUser user, string normalizedEmail, CancellationToken cancellationToken) => SetAsync(() => user.NormalizedEmail = normalizedEmail);
            public Task SetNormalizedUserNameAsync(ApplicationUser user, string normalizedName, CancellationToken cancellationToken) => SetAsync(() => user.NormalizedUserName = normalizedName);
            public Task SetPasswordHashAsync(ApplicationUser user, string passwordHash, CancellationToken cancellationToken) => SetAsync(() => user.PasswordHash = passwordHash);
            public Task SetSecurityStampAsync(ApplicationUser user, string stamp, CancellationToken cancellationToken) => SetAsync(() => user.SecurityStamp = stamp);
            public Task SetUserNameAsync(ApplicationUser user, string userName, CancellationToken cancellationToken) => SetAsync(() => user.UserName = userName);
            public Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken cancellationToken) => Task.FromResult(IdentityResult.Success);

            private static Task SetAsync(Action action)
            {
                action();
                return Task.CompletedTask;
            }
        }
    }
}