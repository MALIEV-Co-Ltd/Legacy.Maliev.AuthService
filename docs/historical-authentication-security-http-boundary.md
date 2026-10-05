# Historical authentication security HTTP boundary

The finite-token cohort has six exact historical SHAs and sixteen runtime path records:

| Source SHA | Changed/classified runtime paths in this cohort |
| --- | --- |
| `5fac706a7983a6d359b39acbd670e6800afe020e` | `Maliev.AuthService.Api/Controllers/AuthController.cs`; `Maliev.AuthService.JwtToken/ITokenGenerator.cs`; `Maliev.AuthService.JwtToken/TokenGenerator.cs`; `Maliev.AuthService.JwtSecurity/MalievJwtSecurityKey.cs` |
| `d2db10813fedaaa5a8852298964962192c0bb5ed` | `Maliev.AuthService.Api/Controllers/AuthController.cs`; `Maliev.AuthService.JwtToken/ITokenGenerator.cs`; `Maliev.AuthService.JwtToken/TokenGenerator.cs` |
| `cbac7d7155da2208c77d56103b6a2cb19196fc83` | `Maliev.AuthService.JwtSecurity/MalievJwtSecurityKey.cs`; `Maliev.AuthService.JwtToken/TokenGenerator.cs` |
| `eb8ed86672bd9afccc6560b547b734d0fcd7363b` | `Maliev.AuthService.JwtSecurity/MalievJwtSecurityKey.cs`; `Maliev.AuthService.JwtToken/TokenGenerator.cs` |
| `a649db99a27bda65274fe1b18866ae226d3c69cf` | `Maliev.AuthService.JwtSecurity/MalievJwtSecurityKey.cs`; `Maliev.AuthService.JwtToken/TokenGenerator.cs` |
| `6c1a4921b3524dd575cab5b1f4aa5774ad9b8997` | `Maliev.AuthService.Api/Controllers/AuthController.cs`; `Maliev.AuthService.JwtToken/ITokenGenerator.cs`; `Maliev.AuthService.JwtToken/TokenGenerator.cs` |

Initial credential validation accepted an identity ID as a password. The later role lookup retains that bypass while adding ordinary and long-lived role metadata. The d2 producer adds non-expiring issuance; cbac changes the embedded key lookup to configuration. Both eb8/a649 merge versions change those crypto paths relative to their first parent and are byte-identical to their second parent, carrying the configuration-based key selection. They are not independent new generator implementations.

Current accepted policy explicitly retires query-string credential validation, identity-ID passwords, non-expiring tokens and embedded symmetric keys. Current password authentication selects the requested identity kind, verifies the real ASP.NET Identity hash, and issues a finite RS256 actor token through normal persisted session state. Source ordinary role responsibility is adapted by the same-value URI/short role claims. Machine credentials and scoped issuers remain separate. The source thirty-minute HS256/Basic transport is not claimed byte-for-byte equivalent to the versioned JSON/RS256 contract.

Four new normal Production Program HTTP cases close a validation-witness gap. Two exercise employee/customer ID-as-password denial with unchanged complete identity snapshots and no refresh/action rows, then prove the real password issues the correct subject/kind/role and hashed refresh binding without identity mutation. Two send legitimate synthetic credentials to the retired GET `/auth/validate` and Basic POST `/auth/token/longlived`, assert 404 without identity/session/action mutation or credential/token echo, then prove the ordinary employee login still succeeds.

These cases reuse the existing real PostgreSQL fixture, Production Program, password reader/hasher, issuer, bearer configuration and session store. The existing fixture controls only Google's external validator, unused by these password/retired-route cases; no password authentication, issuer, session, IAM or policy service is replaced. No production grant, runtime, dependency pin or retired endpoint is added. Dedicated CI runs the four named cases and exports sanitized TRX through the existing evidence exporter. Earlier reader-level and controller-metadata tests remain distinct witnesses.

Build/focused/full/raw generated-inclusive coverage/static acceptance must come from actual hosted Ubuntu runs with zero compiler warnings/errors and observed counts. No local SDK/Docker or knowingly failing tests-only baseline is used. This document does not assert candidate/main acceptance ahead of those results.

This is a bounded security adaptation and validation slice, not a whole source path/SHA retirement. LINE actor/consumer discovery, original Identity data-protection callback compatibility, actual compiled Web/Intranet joins, live source identity schema/data acceptance and other mixed-commit obligations remain separate. No live provider, data, schema, secret, deployment or shared-ledger operation is performed.
