# Legacy.Maliev.AuthService

Temporary .NET 10 compatibility service for MALIEV's unchanged legacy customer and employee identity databases.

The clean service layers depend only on the public `Legacy.Maliev.ServiceDefaults` and
`Legacy.Maliev.CompatibilityContracts` repositories during local, CI, and image builds. Compatibility
namespaces remain unchanged, so this dependency isolation does not alter token, refresh-session,
permission, DTO, or JSON contracts.

The service replaces the unsafe legacy token API with:

- short-lived RS256 access tokens;
- single-use rotating refresh tokens stored only as hashes in an isolated PostgreSQL database;
- token-family revocation and refresh-token replay detection;
- rate-limited `POST /auth/v1/service/login` issuance of short-lived, least-privilege RS256 tokens for configured legacy BFF identities, without machine refresh tokens;
- separate customer and employee identity boundaries;
- trusted-BFF customer registration, single-use email confirmation, and
  password recovery through JSON-only endpoints;
- customer-access-token-authorized email and password changes that verify the
  current password, rotate identity security state, and revoke every refresh
  session;
- employee-authorized JSON administration for customer and employee identities,
  with initial passwords accepted only in request bodies;
- OpenAPI and Scalar documentation through MALIEV service defaults.

The source monorepo stays private. This extracted implementation is public and must contain no production credentials or database data.

Service clients are configured under `ServiceClients:Clients:<client-id>` with a lowercase SHA-256 secret hash and an explicit permission list. The raw client secret is presented only in the JSON login body and is never stored, logged, placed in a URL, or emitted as a JWT claim. Runtime values are projected from the consolidated `maliev-legacy-secrets` secret; source configuration contains no client credential.

Employee Google Identity Services is an optional, fail-closed trusted-BFF flow. The
Intranet BFF calls `POST /auth/v1/exchange/google/nonce` and
`POST /auth/v1/exchange/google` using a service token carrying only
`legacy-auth.google-identity.exchange`. Configure these values at runtime (never in
source or browser code): `GoogleIdentity:Employee:HostedDomain` (for example,
`maliev.com`), `GoogleIdentity:Employee:Audiences:intranet` (the OAuth client ID),
and optionally `GoogleIdentity:NonceLifetimeMinutes` (1-15, default 10). If either
the hosted domain or audience is missing, the exchange returns an unavailable
result and no credential is accepted. The separate BFF client ID configuration
must match the AuthService audience. Nonce hashes are stored in the isolated
`google_identity_nonces` PostgreSQL table and are deleted atomically on use or
expiry; the unchanged identity database remains the source of truth.

## Explicitly retired legacy behavior

- `GET /auth/validate` (credentials in query strings);
- accepting an identity ID as a password;
- non-expiring `POST /auth/token/longlived` tokens;
- symmetric signing keys embedded in application configuration.

The identity tables are PostgreSQL-backed in the migrated service. Their schema is
owned by the PostgreSQL migrations shipped with this repository; the service does not
select an alternate provider at runtime. Customer self-service writes only the identity
row values required for registration, confirmation, password replacement, and
security-stamp rotation. Hashed confirmation and recovery tokens are stored in isolated
PostgreSQL alongside refresh-session state.

Identity administration uses `/auth/v1/customer-identities/{databaseId}` and
`/auth/v1/employee-identities/{databaseId}`. Source-data backup and parity rehearsal
are performed by the separately governed migration runbook before service validation;
this repository contains only the PostgreSQL consumer and its tests.

Trusted BFF customer self-service uses JSON `POST` operations under
`/auth/v1/customer-self-service` and requires
`legacy-auth.customer-self-service`. Raw passwords and action tokens are never
placed in URLs, logs, JWT claims, or PostgreSQL; only SHA-256 token hashes are
stored. Issuing a replacement challenge invalidates the previous challenge.

Customer password-reset links expire after 24 hours and are single-use, bound to
the current identity security stamp and both the current and token-target email.
Successful reset rotates the security stamp and revokes the customer's refresh
sessions. The existing JSON request/response shapes and routes are unchanged.
Tracked in [AuthService issue #77](https://github.com/MALIEV-Co-Ltd/Legacy.Maliev.AuthService/issues/77).
Previously issued unbound password-reset links are intentionally rejected after
this update: customers must request a fresh link through Forgot Password. There
is no fallback to the old unbound hash format. Migrated identities missing a
security stamp receive a persisted stamp before challenge issuance; initialization
conditionally updates only the observed missing value and reloads the persisted
winner, so it does not overwrite a concurrent initialization or stamp rotation.

Token consumption and identity persistence use separate database contexts. If
identity persistence fails after token consumption, the old link remains spent;
request a fresh link rather than retrying the spent token. A reset response lost
after persistence may likewise require a fresh link or login with the new
password. Existing access tokens retain their normal lifetime; refresh-session
revocation does not retract an already-issued access token.

Authenticated `POST /auth/v1/customer-self-service/email/change` and
`POST /auth/v1/customer-self-service/password/change` instead require a customer
access token. The identity ID comes only from its signed `sub` claim; callers
cannot select another account in the body or route. Successful changes rotate
the security stamp and revoke all refresh sessions, requiring a fresh login.
