// <copyright file="TemporaryPasswordCredential.cs" company="Maliev Company Limited">
// Copyright (c) Maliev Company Limited. All rights reserved.
// </copyright>

namespace Maliev.Web.Security
{
    using Maliev.Identities;
    using Microsoft.AspNetCore.Identity;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;

    /// <summary>
    /// Identifies customer accounts that must replace an issued temporary password.
    /// </summary>
    internal static class TemporaryPasswordCredential
    {
        internal const string ClaimType = "maliev:credential_state";
        internal const string ClaimValue = "temporary_password";
        private const string IssuedPasswordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@$%";

        /// <summary>
        /// Determines whether the user has a persisted temporary-password marker.
        /// </summary>
        /// <param name="userManager">The user manager.</param>
        /// <param name="user">The customer identity.</param>
        /// <returns><see langword="true" /> when the marker exists.</returns>
        internal static async Task<bool> IsMarkedAsync(UserManager<ApplicationUser> userManager, ApplicationUser user)
        {
            IList<Claim> claims = await userManager.GetClaimsAsync(user);
            return claims.Any(IsMarker);
        }

        /// <summary>
        /// Persists the temporary-password marker when it is not already present.
        /// </summary>
        /// <param name="userManager">The user manager.</param>
        /// <param name="user">The customer identity.</param>
        /// <returns>The Identity operation result.</returns>
        internal static async Task<IdentityResult> MarkAsync(UserManager<ApplicationUser> userManager, ApplicationUser user)
        {
            if (await IsMarkedAsync(userManager, user))
            {
                return IdentityResult.Success;
            }

            return await userManager.AddClaimAsync(user, CreateMarker());
        }

        /// <summary>
        /// Creates a password identity and persists its temporary-password marker as one provisioning operation.
        /// </summary>
        /// <param name="userManager">The user manager.</param>
        /// <param name="user">The customer identity.</param>
        /// <param name="password">The issued temporary password.</param>
        /// <returns>The Identity operation result.</returns>
        internal static Task<IdentityResult> CreateMarkedUserAsync(
            UserManager<ApplicationUser> userManager,
            ApplicationUser user,
            string password)
        {
            return CreateMarkedUserCoreAsync(userManager, user, password);
        }

        private static async Task<IdentityResult> CreateMarkedUserCoreAsync(
            UserManager<ApplicationUser> userManager,
            ApplicationUser user,
            string password)
        {
            IdentityResult createResult = await userManager.CreateAsync(user, password);
            if (!createResult.Succeeded)
            {
                return createResult;
            }

            IdentityResult markerResult;
            try
            {
                markerResult = await MarkAsync(userManager, user);
            }
            catch (System.Exception)
            {
                await userManager.DeleteAsync(user);
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "TemporaryPasswordMarkerFailed",
                    Description = "The temporary-password marker could not be persisted.",
                });
            }

            if (markerResult.Succeeded)
            {
                return IdentityResult.Success;
            }

            await userManager.DeleteAsync(user);
            return markerResult;
        }

        /// <summary>
        /// Removes all persisted temporary-password markers.
        /// </summary>
        /// <param name="userManager">The user manager.</param>
        /// <param name="user">The customer identity.</param>
        /// <returns>The Identity operation result.</returns>
        internal static async Task<IdentityResult> ClearAsync(UserManager<ApplicationUser> userManager, ApplicationUser user)
        {
            IList<Claim> claims = await userManager.GetClaimsAsync(user);
            Claim[] markers = claims.Where(IsMarker).ToArray();
            return markers.Length == 0
                ? IdentityResult.Success
                : await userManager.RemoveClaimsAsync(user, markers);
        }

        /// <summary>
        /// Recognizes the exact format used by the legacy temporary-password generator.
        /// </summary>
        /// <param name="password">The successfully validated password.</param>
        /// <returns><see langword="true" /> only for the issued legacy format.</returns>
        internal static bool MatchesLegacyIssuedFormat(string password)
        {
            return password?.Length == 20
                && password.All(IssuedPasswordAlphabet.Contains)
                && password.Any(char.IsUpper)
                && password.Any(char.IsLower)
                && password.Any(char.IsDigit)
                && password.Any(character => !char.IsLetterOrDigit(character))
                && password.Distinct().Count() >= 6;
        }

        private static Claim CreateMarker() => new Claim(ClaimType, ClaimValue);

        private static bool IsMarker(Claim claim) =>
            claim.Type == ClaimType && claim.Value == ClaimValue;
    }
}