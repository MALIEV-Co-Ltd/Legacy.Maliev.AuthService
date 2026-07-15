# Legacy.Maliev.AuthService

Temporary .NET 10 compatibility service for MALIEV's unchanged legacy customer and employee identity databases.

The service replaces the unsafe legacy token API with:

- short-lived RS256 access tokens;
- single-use rotating refresh tokens stored only as hashes in an isolated PostgreSQL database;
- token-family revocation and refresh-token replay detection;
- rate-limited `POST /auth/v1/service/login` issuance of short-lived, least-privilege RS256 tokens for configured legacy BFF identities, without machine refresh tokens;
- separate customer and employee identity boundaries;
- employee-authorized JSON administration for customer and employee identities,
  with initial passwords accepted only in request bodies;
- OpenAPI and Scalar documentation through MALIEV service defaults.

The source monorepo stays private. This extracted implementation is public and must contain no production credentials or database data.

Service clients are configured under `ServiceClients:Clients:<client-id>` with a lowercase SHA-256 secret hash and an explicit permission list. The raw client secret is presented only in the JSON login body and is never stored, logged, placed in a URL, or emitted as a JWT claim. Runtime values are projected from the consolidated `maliev-legacy-secrets` secret; source configuration contains no client credential.

## Explicitly retired legacy behavior

- `GET /auth/validate` (credentials in query strings);
- accepting an identity ID as a password;
- non-expiring `POST /auth/token/longlived` tokens;
- symmetric signing keys embedded in application configuration.

The legacy identity tables remain the source of truth during migration and are not migrated or altered by this service.

Identity administration uses `/auth/v1/customer-identities/{databaseId}` and
`/auth/v1/employee-identities/{databaseId}`. Both operate against the unchanged
SQL Server schemas; only refresh-session state uses the isolated PostgreSQL database.
