# Legacy.Maliev.AuthService

Temporary .NET 10 compatibility service for MALIEV's unchanged legacy customer and employee identity databases.

The service replaces the unsafe legacy token API with:

- short-lived RS256 access tokens;
- single-use rotating refresh tokens stored only as hashes in an isolated PostgreSQL database;
- token-family revocation and refresh-token replay detection;
- separate customer and employee identity boundaries;
- employee-authorized JSON administration for customer and employee identities,
  with initial passwords accepted only in request bodies;
- OpenAPI and Scalar documentation through MALIEV service defaults.

The source monorepo stays private. This extracted implementation is public and must contain no production credentials or database data.

## Explicitly retired legacy behavior

- `GET /auth/validate` (credentials in query strings);
- accepting an identity ID as a password;
- non-expiring `POST /auth/token/longlived` tokens;
- symmetric signing keys embedded in application configuration.

The legacy identity tables remain the source of truth during migration and are not migrated or altered by this service.

Identity administration uses `/auth/v1/customer-identities/{databaseId}` and
`/auth/v1/employee-identities/{databaseId}`. Both operate against the unchanged
SQL Server schemas; only refresh-session state uses the isolated PostgreSQL database.
