# Original employee remembered-cookie compatibility candidate

Auth Program registers the original remembered-client scheme. Its named Cookie options
use an isolated provider; global Data Protection providers and other cookie schemes are
unchanged. No database schema/key adoption/deployment was executed. Native validation
and the exact historical deployment discriminator/certificate/key-adoption/owner grants
remain prerequisites for operational acceptance.

Committed original checkpoint:135e526d0dab85c415b3afdcefd7b70fe2c82e2f. Original
ServiceExtensions persists EF SQL Server DataProtectionKeysEmployeeDbContext without
an explicit application name or certificate. Dockerfile /app is source evidence, not live
historical discriminator proof. The candidate requires exact historical discriminator
configuration rather than substituting the repository or current host's root name.

Identity8.0.28's cookie name/scheme is Identity.TwoFactorRememberMe. Protection purpose
is Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware, scheme,
v2. A remembered ticket binds ClaimTypes.Name to the employee and carries security stamp.
The locked-row password policy checks both before allowing issuance or renewal.

Original14-day persistent lifetime and midpoint renewal are retained. The named handler
suppresses its early automatic renewal; after correct password and authenticated ticket,
the policy renews only if elapsed time exceeds remaining time, retaining original ticket
duration/properties and subject/stamp. Invalid user/stamp/purpose/discriminator/expiry
cannot renew, mint tokens, create refresh state or establish a BFF session. Wrong password
still follows original accounting; invalid credentials keep generic errors.

The separate employee-owned PostgreSQL repository retains original encrypted XML/key IDs,
activation/expiration and revocations. Plain masterKey material, unknown XML and empty
rings fail closed. DTDs, runtime schema creation and automatic key generation are disabled.
Original ring adoption and owner/grants require separate reviewed data-owner evidence.
Certificate/key material is read only from configured protected custody, never committed.
The named provider owns its inner DI provider/certificate and disposes both; key repository
connections are bounded, unpooled and disposed on every operation.

BFF and compatibility host forward only bounded, reassembled remembered-ticket ciphertext
for password login, after current inbound request gates. Caller Cookie headers are removed
on all Auth-client paths; handler cookie jars and redirects are disabled. Only successful
Auth responses can propagate bounded same-cookie-family renewals, with Secure/HttpOnly/
SameSite=Lax/root-path attributes enforced by the browser-facing host. No Boolean trust or
new challenge UI is introduced.

The acceptance/EmployeeRememberedCookie project drives actual BFF Program→typed client→
Auth Program→PostgreSQL provider/identity/session stores. It uses an independently protected
synthetic ring and verifies issuance, renewal and original-purpose/discriminator/user/stamp/
tamper/expiry/chunk/length/credential negatives, unchanged key records and no failed-session
writes. Separate global-provider/customer-flow controls guard isolation. Existing producer/
consumer/browser tests and affected suites remain mandatory. All new C# tests are authored,
not executed; no build or runtime acceptance is claimed.

Original EF8.0.28 DataProtectionKey has nullable FriendlyName and Xml; original repository
ignores null/empty Xml placeholders. The PostgreSQL schema and reader preserve that
behavior without dropping those database rows; a ring with no actual key still fails.
Primary committed framework references:
- https://raw.githubusercontent.com/dotnet/aspnetcore/v8.0.28/src/DataProtection/EntityFrameworkCore/src/DataProtectionKey.cs
- https://raw.githubusercontent.com/dotnet/aspnetcore/v8.0.28/src/DataProtection/EntityFrameworkCore/src/EntityFrameworkCoreXmlRepository.cs
- https://raw.githubusercontent.com/dotnet/aspnetcore/v8.0.28/src/Identity/Core/src/IdentityCookiesBuilderExtensions.cs
- https://raw.githubusercontent.com/dotnet/aspnetcore/v8.0.28/src/Security/Authentication/Cookies/src/PostConfigureCookieAuthenticationOptions.cs
- https://raw.githubusercontent.com/dotnet/aspnetcore/v8.0.28/src/DataProtection/DataProtection/src/Internal/HostingApplicationDiscriminator.cs
