# Identity business ID and session contract

This bounded test-only characterization uses the normal Auth host, real signed issuer, rotating refresh sessions, and PostgreSQL identity/state stores. It leaves the schema and runtime policies unchanged.

At original source `6c1a4921b3524dd575cab5b1f4aa5774ad9b8997`, `Maliev.Identities/ApplicationUser.cs` and its final customer model snapshot define a non-nullable integer `DatabaseID`. `ApplicationEmployee.cs` defines a nullable integer. Auth main `688fe18` uses one nullable projection and an initial nullable customer PostgreSQL column. Customer null is a current extension requiring separate historical-data/schema correspondence evidence.

The six cases cover customer and employee null, zero, and positive business IDs. Login and refresh must retain the selected identity subject/kind and the available business ID value; an absent value stays absent. Employee JWT `sid` must match its actual persisted session. Customer sessions retain their existing JWT contract. Refresh must rotate the session within the original family without changing either identity store, issuing recovery actions, or rebinding a business profile.

The case deadline is 30 seconds for HTTP and EF operations. Existing owned fixture contexts, pool cleanup and host disposal remain active. Identity/security comparisons use hashes in failure assertions.

Expected candidate inventory is 919 cases, including all 913 accepted predecessor IDs, 97 actor cases, unchanged 162 IAM cases, and six dedicated identity-ID cases. These are forecasts until native retained artifacts pass. Build, formatting, raw coverage and the normal protected merge/fresh-main gates remain required.

This slice provides no schema migration, data rewrite, live IAM mutation, new grant, provider change, compiled consumer join, Identity framework-table/provider closure, or LINE rollout acceptance.
# Fixture resource ownership

The HTTP fixtures retain the exact PostgreSQL pool identities from the production options callbacks, including pools opened by separate credential-validation contexts. Teardown stops the HTTP host first, then clears only those owned pools through unopened connection handles in `finally`; it does not resolve services or open database connections during cleanup. The original connection, pooling, command-timeout, retry, issuer, and permission configuration remains intact.

