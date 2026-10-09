// <copyright file="AuthController.cs" company="Maliev Company Limited">
// Copyright (c) Maliev Company Limited. All rights reserved.
// </copyright>

using System;
using System.Text;
using System.Threading.Tasks;
using Maliev.AuthService.JwtToken;
using Maliev.Identities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Maliev.AuthService.Controllers
{
    /// <summary>
    /// Authorization Controller.
    /// </summary>
    /// <seealso cref="Microsoft.AspNetCore.Mvc.ControllerBase" />
    [ApiController]
    [ApiConventionType(typeof(DefaultApiConventions))]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        /// <summary>
        /// The application user manager.
        /// </summary>
        private readonly UserManager<ApplicationUser> appUserManager;

        /// <summary>
        /// The emp user manager.
        /// </summary>
        private readonly UserManager<ApplicationEmployee> empUserManager;

        /// <summary>
        /// The token generator.
        /// </summary>
        private readonly ITokenGenerator tokenGenerator;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthController" /> class.
        /// </summary>
        /// <param name="appUserManager">The application user manager.</param>
        /// <param name="empUserManager">The emp user manager.</param>
        /// <param name="tokenGenerator">The token generator.</param>
        public AuthController(UserManager<ApplicationUser> appUserManager, UserManager<ApplicationEmployee> empUserManager, ITokenGenerator tokenGenerator)
        {
            this.appUserManager = appUserManager;
            this.empUserManager = empUserManager;
            this.tokenGenerator = tokenGenerator;
        }

        /// <summary>
        /// Validate employee existence. Use to secure SwaggerUI.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns>
        ///   <see cref="ActionResult" />.
        /// </returns>
        [HttpGet("validate", Name = "ValidateEmployee")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesDefaultResponseType]
        public async Task<ActionResult> GetValidatedEmployeeAsync(string username, string password)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                return this.BadRequest();
            }

            if (await this.GetValidatedUserRoleAsync(username, password) != null)
            {
                return new OkResult();
            }
            else
            {
                return this.Unauthorized();
            }
        }

        /// <summary>
        /// Posts the token.
        /// POST /auth/token.
        /// </summary>
        /// <returns>
        ///   <see cref="ActionResult" />.
        /// </returns>
        [HttpPost("token")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesDefaultResponseType]
        public async Task<ActionResult> PostTokenAsync()
        {
            if (this.Request == null)
            {
                return this.BadRequest();
            }

            var header = this.Request.Headers["Authorization"].ToString();

            // Basic Auth
            if (header.StartsWith("Basic"))
            {
                var rawCredentialBase64 = header.Substring("Basic".Length).Trim();
                var rawCredentialString = Encoding.UTF8.GetString(Convert.FromBase64String(rawCredentialBase64));
                var credential = rawCredentialString.Split(":");

                var username = credential[0];
                var password = credential[1];

                string role = await this.GetValidatedUserRoleAsync(username, password);
                if (role != null)
                {
                    string token = this.tokenGenerator.GenerateJwtToken(username, role);
                    return new OkObjectResult(token);
                }
                else
                {
                    return this.Unauthorized();
                }
            }
            else
            {
                return this.BadRequest();
            }
        }

        /// <summary>
        /// Posts the long-lived token.
        /// POST /auth/token/longlived.
        /// </summary>
        /// <returns>
        ///   <see cref="ActionResult" />.
        /// </returns>
        [HttpPost("token/longlived")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesDefaultResponseType]
        public async Task<ActionResult> PostLongLivedTokenAsync()
        {
            if (this.Request == null)
            {
                return this.BadRequest();
            }

            var header = this.Request.Headers["Authorization"].ToString();

            // Basic Auth
            if (header.StartsWith("Basic"))
            {
                var rawCredentialBase64 = header.Substring("Basic".Length).Trim();
                var rawCredentialString = Encoding.UTF8.GetString(Convert.FromBase64String(rawCredentialBase64));
                var credential = rawCredentialString.Split(":");

                var username = credential[0];
                var password = credential[1];

                string role = await this.GetValidatedUserRoleAsync(username, password);
                if (role != null)
                {
                    string token = this.tokenGenerator.GenerateLongLivedJwtToken(username, role);
                    return new OkObjectResult(token);
                }
                else
                {
                    return this.Unauthorized();
                }
            }
            else
            {
                return this.BadRequest();
            }
        }

        /// <summary>
        /// Gets the validated user role asynchronous.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        /// <param name="password">The password.</param>
        /// <returns>
        /// The validated actor role, or <see langword="null" /> when authentication fails.
        /// </returns>
        private async Task<string> GetValidatedUserRoleAsync(string userName, string password)
        {
            var applicationUser = await this.appUserManager.FindByNameAsync(userName);
            var employeeUser = await this.empUserManager.FindByNameAsync(userName);

            if (applicationUser != null
                && (applicationUser.Id == password || await this.appUserManager.CheckPasswordAsync(applicationUser, password)))
            {
                return "Customer";
            }

            if (employeeUser != null
                && (employeeUser.Id == password || await this.empUserManager.CheckPasswordAsync(employeeUser, password)))
            {
                return "Employee";
            }

            return null;
        }
    }
}
