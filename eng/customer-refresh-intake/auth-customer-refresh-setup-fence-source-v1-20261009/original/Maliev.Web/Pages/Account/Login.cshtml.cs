// <copyright file="Login.cshtml.cs" company="Maliev Company Limited">
// Copyright (c) Maliev Company Limited. All rights reserved.
// </copyright>

namespace Maliev.Web.Pages.Account
{
    using Maliev.Identities;
    using Maliev.Service.WebApi;
    using Maliev.Web.Security;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using Microsoft.AspNetCore.WebUtilities;
    using Microsoft.Extensions.Localization;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.Net.Http;
    using System.Text;
    using System.Text.Encodings.Web;
    using System.Threading.Tasks;
    using System.Web;

    /// <summary>
    /// LogInModel.
    /// </summary>
    /// <seealso cref="Microsoft.AspNetCore.Mvc.RazorPages.PageModel" />
    public class Login : PageModel
    {
        private const string EmailConfirmationRecoveryPurpose = "EmailConfirmationRecovery";

        /// <summary>
        /// The sign in manager.
        /// </summary>
        private readonly SignInManager<ApplicationUser> signInManager;

        /// <summary>
        /// The user manager.
        /// </summary>
        private readonly UserManager<ApplicationUser> userManager;

        private readonly IStringLocalizer<Login> localizer;

        /// <summary>
        /// The web API service.
        /// </summary>
        private readonly IWebApiService webApiService;

        /// <summary>
        /// Initializes a new instance of the <see cref="Login" /> class.
        /// </summary>
        /// <param name="signinManager"><see cref="SignInManager{ApplicationUser}" />.</param>
        /// <param name="userManager"><see cref="UserManager{ApplicationUser}" />.</param>
        /// <param name="clientFactory">The HTTP client factory.</param>
        /// <param name="webApiService">The web API service.</param>
        /// <param name="localizer">The localized account messages.</param>
        public Login(
            SignInManager<ApplicationUser> signinManager,
            UserManager<ApplicationUser> userManager,
            IHttpClientFactory clientFactory,
            IWebApiService webApiService,
            IStringLocalizer<Login> localizer)
        {
            this.signInManager = signinManager;
            this.userManager = userManager;
            this.webApiService = webApiService;
            this.localizer = localizer;

            if (this.webApiService != null)
            {
                this.webApiService.SetClientFactory(clientFactory);
            }
        }

        /// <summary>
        /// Gets or sets email.
        /// </summary>
        /// <value>
        /// The email.
        /// </value>
        [BindProperty]
        [Required(ErrorMessage = "Email address is required")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        /// <summary>
        /// Gets or sets the notification.
        /// </summary>
        /// <value>
        /// The notification.
        /// </value>
        [TempData]
        public string Notification { get; set; }

        /// <summary>
        /// Gets or sets password.
        /// </summary>
        /// <value>
        /// The password.
        /// </value>
        [BindProperty]
        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether login is presistent or not.
        /// </summary>
        /// <value>
        ///   <c>true</c> if [remember me]; otherwise, <c>false</c>.
        /// </value>
        [BindProperty]
        public bool RememberMe { get; set; }

        /// <summary>
        /// Gets a value indicating whether email-confirmation recovery should be offered.
        /// </summary>
        public bool ShowEmailConfirmationRecovery { get; private set; }

        /// <summary>
        /// Gets the localized contextual email-confirmation recovery message.
        /// </summary>
        public string EmailConfirmationRecoveryMessage { get; private set; }

        /// <summary>
        /// Gets or sets the short-lived grant used by the contextual resend action.
        /// </summary>
        [BindProperty]
        public string EmailConfirmationRecoveryToken { get; set; }

        /// <summary>
        /// Gets or sets return URL.
        /// </summary>
        /// <value>
        /// The return URL.
        /// </value>
        [BindProperty]
        public string ReturnUrl { get; set; }

        /// <summary>
        /// GET.
        /// </summary>
        /// <param name="email">email address.</param>
        /// <param name="returnUrl">return URL.</param>
        /// <param name="message">The message.</param>
        /// <returns>
        ///   <see cref="IActionResult" />.
        /// </returns>
        public IActionResult OnGet(string email, string returnUrl, string message)
        {
            if (this.signInManager.IsSignedIn(this.User))
            {
                return this.RedirectToPage("/Index", new { area = "Member" });
            }

            if (!string.IsNullOrEmpty(message))
            {
                this.Notification = message;
                return this.RedirectToPage();
            }

            if (!string.IsNullOrEmpty(email))
            {
                this.Email = email;
            }

            this.ReturnUrl = HttpUtility.UrlDecode(returnUrl, Encoding.UTF8);

            return null;
        }

        /// <summary>
        /// POST Login using email and password.
        /// </summary>
        /// <returns>
        ///   <see cref="IActionResult" />.
        /// </returns>
        public async Task<IActionResult> OnPostLoginAsync()
        {
            if (!this.ModelState.IsValid)
            {
                this.ModelState.AddModelError(string.Empty, this.localizer["Please verify your input again."]);
                return this.Page();
            }
            else
            {
                ApplicationUser user = await this.userManager.FindByEmailAsync(this.Email);
                Microsoft.AspNetCore.Identity.SignInResult result = user == null
                    ? Microsoft.AspNetCore.Identity.SignInResult.Failed
                    : await this.signInManager.CheckPasswordSignInAsync(user, this.Password, lockoutOnFailure: true);

                if (result.Succeeded)
                {
                    bool markedTemporary = await TemporaryPasswordCredential.IsMarkedAsync(this.userManager, user);
                    if (!markedTemporary && TemporaryPasswordCredential.MatchesLegacyIssuedFormat(this.Password))
                    {
                        IdentityResult markerResult = await TemporaryPasswordCredential.MarkAsync(this.userManager, user);
                        if (!markerResult.Succeeded)
                        {
                            this.ModelState.AddModelError(string.Empty, this.localizer["Login failed"]);
                            return this.Page();
                        }

                        markedTemporary = true;
                    }

                    if (markedTemporary)
                    {
                        string passwordToken = await this.userManager.GeneratePasswordResetTokenAsync(user);
                        return this.RedirectToPage(
                            "/Account/SetInitialPassword",
                            new
                            {
                                email = user.Email,
                                token = IdentityEmailTokenCodec.Encode(passwordToken),
                                returnUrl = this.GetSafeReturnUrl(),
                                rememberMe = this.RememberMe,
                            });
                    }

                    await this.signInManager.SignInAsync(user, this.RememberMe);
                    string safeReturnUrl = this.GetSafeReturnUrl();
                    if (!string.IsNullOrEmpty(safeReturnUrl))
                    {
                        return this.LocalRedirect(safeReturnUrl);
                    }

                    return this.RedirectToPage("/Index", new { area = "Member" });
                }
                else
                {
                    if (result.IsLockedOut)
                    {
                        this.ModelState.AddModelError(string.Empty, this.localizer["Too many failed attempts. This account has been locked out, please try again later."]);
                        return this.Page();
                    }
                    else if (result.IsNotAllowed)
                    {
                        ApplicationUser unconfirmedUser = await this.FindUnconfirmedUserWithValidPasswordAsync();
                        if (unconfirmedUser != null)
                        {
                            await this.OfferEmailConfirmationRecoveryAsync(
                                unconfirmedUser,
                                "Please verify your email before signing in.");
                            return this.Page();
                        }

                        this.ModelState.AddModelError(string.Empty, this.localizer["Login failed"]);
                        return this.Page();
                    }
                    else if (result.RequiresTwoFactor)
                    {
                        this.ModelState.AddModelError(string.Empty, this.localizer["Log in required Two-Factor Authentication"]);
                        return this.Page();
                    }

                    this.ModelState.AddModelError(string.Empty, this.localizer["Login failed"]);
                    return this.Page();
                }
            }
        }

        /// <summary>
        /// Sends a fresh email-confirmation link when the submitted credentials are valid.
        /// </summary>
        /// <returns>The redirect or page result.</returns>
        public async Task<IActionResult> OnPostResendEmailConfirmationAsync()
        {
            ApplicationUser user = await this.FindUnconfirmedUserWithRecoveryGrantAsync();
            if (user != null)
            {
                string code = await this.userManager.GenerateEmailConfirmationTokenAsync(user);
                string emailToken = IdentityEmailTokenCodec.Encode(code);
                string callbackUrl = this.Url.Page(
                    "/Account/EmailConfirmation",
                    pageHandler: null,
                    values: new { area = string.Empty, email = user.Email, token = emailToken },
                    protocol: this.Request.Scheme);
                string serviceToken = await this.webApiService.RequestJwtTokenAsync(user.UserName, user.Id);
                var queryString = new Dictionary<string, string>
                {
                    { "to", user.Email },
                    { "bcc", "mail-tracking@maliev.com" },
                    { "subject", this.localizer["Email Confirmation"] },
                    { "body", this.CreateEmailConfirmationMailBody(callbackUrl) },
                };
                string requestUri = QueryHelpers.AddQueryString("/emails/noreply/", queryString);
                using HttpResponseMessage response = await this.webApiService.Post(requestUri, null, serviceToken);
                if (!response.IsSuccessStatusCode)
                {
                    await this.OfferEmailConfirmationRecoveryAsync(
                        user,
                        "We could not send the verification email. Please try again later.");
                    return this.Page();
                }
            }

            this.Notification = this.localizer["If the account requires verification, a new verification link has been sent."];
            return this.RedirectToPage(new { email = this.Email, returnUrl = this.ReturnUrl });
        }

        private string GetSafeReturnUrl()
        {
            string returnUrl = HttpUtility.UrlDecode(this.ReturnUrl, Encoding.UTF8);
            return !string.IsNullOrEmpty(returnUrl) && this.Url.IsLocalUrl(returnUrl) ? returnUrl : null;
        }

        private async Task OfferEmailConfirmationRecoveryAsync(ApplicationUser user, string messageKey)
        {
            this.ShowEmailConfirmationRecovery = true;
            this.EmailConfirmationRecoveryMessage = this.localizer[messageKey];
            string token = await this.userManager.GenerateUserTokenAsync(
                user,
                TokenOptions.DefaultProvider,
                EmailConfirmationRecoveryPurpose);
            this.EmailConfirmationRecoveryToken = IdentityEmailTokenCodec.Encode(token);
        }

        private string CreateEmailConfirmationMailBody(string callbackUrl)
        {
            string safeCallbackUrl = HtmlEncoder.Default.Encode(callbackUrl);
            string greeting = HtmlEncoder.Default.Encode(this.localizer["Hello,"]);
            string confirmationMessage = HtmlEncoder.Default.Encode(
                this.localizer["Please confirm your MALIEV customer email address by selecting the link below."]);
            string confirmationLinkText = HtmlEncoder.Default.Encode(this.localizer["Confirm email"]);
            string ignoreMessage = HtmlEncoder.Default.Encode(
                this.localizer["If you did not request this email, you can ignore it."]);
            StringBuilder content = new StringBuilder();
            content.AppendLine($"<div>{greeting}</div>");
            content.AppendLine("<div>&nbsp;</div>");
            content.AppendLine($"<div>{confirmationMessage}</div>");
            content.AppendLine("<div>&nbsp;</div>");
            content.AppendLine($"<div><a href='{safeCallbackUrl}' target='_blank'>{confirmationLinkText}</a></div>");
            content.AppendLine("<div>&nbsp;</div>");
            content.AppendLine($"<div>{ignoreMessage}</div>");
            return content.ToString();
        }

        private async Task<ApplicationUser> FindUnconfirmedUserWithValidPasswordAsync()
        {
            ApplicationUser user = await this.userManager.FindByEmailAsync(this.Email);
            if (user == null)
            {
                return null;
            }

            if (this.userManager.SupportsUserLockout && await this.userManager.IsLockedOutAsync(user))
            {
                return null;
            }

            if (!await this.userManager.CheckPasswordAsync(user, this.Password))
            {
                if (this.userManager.SupportsUserLockout)
                {
                    await this.userManager.AccessFailedAsync(user);
                }

                return null;
            }

            if (this.userManager.SupportsUserLockout)
            {
                await this.userManager.ResetAccessFailedCountAsync(user);
            }

            return await this.userManager.IsEmailConfirmedAsync(user) ? null : user;
        }

        private async Task<ApplicationUser> FindUnconfirmedUserWithRecoveryGrantAsync()
        {
            if (string.IsNullOrWhiteSpace(this.Email) || string.IsNullOrWhiteSpace(this.EmailConfirmationRecoveryToken))
            {
                return null;
            }

            ApplicationUser user = await this.userManager.FindByEmailAsync(this.Email);
            if (user == null
                || await this.userManager.IsEmailConfirmedAsync(user)
                || (this.userManager.SupportsUserLockout && await this.userManager.IsLockedOutAsync(user)))
            {
                return null;
            }

            foreach (string candidate in IdentityEmailTokenCodec.DecodeCandidates(this.EmailConfirmationRecoveryToken))
            {
                if (await this.userManager.VerifyUserTokenAsync(
                    user,
                    TokenOptions.DefaultProvider,
                    EmailConfirmationRecoveryPurpose,
                    candidate))
                {
                    return user;
                }
            }

            return null;
        }
    }
}