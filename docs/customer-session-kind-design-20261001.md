# Auth #120 — customer refresh revocation identity-kind boundary

Runtime candidate frozen for independent root review. Root approved only the customer-kind predicate after reviewing the genuine RED fixture/design. Issue [Auth #120](https://github.com/MALIEV-Co-Ltd/Legacy.Maliev.AuthService/issues/120); no whole-source, deployment or parent closure.

## Owned baseline and scope

Fresh workspace `B:/maliev-legacy/.worktrees/auth-customer-session-kind-20261001`, branch `codex/auth-customer-session-kind-20261001`, initial base `1cce0ef062ed54ee8dd5257eafa07bfefa457fda` (root independently accepted Auth119 candidate; protected PR121 pending at lane creation). After root approval, safely reparented onto protected merged `92bbb1410cde0c1d527d0cc3469fb57a5f108904` with `git rebase --onto` and a clean tracked-tree prerequisite. Both new files and ignored evidence were preserved without reset/discard. The merged extra injected-clock regression and documentation corrections are retained unchanged; root reported required CI36837380663 successful, exact-main36838071133 running at reparent authorization. Hosted gates remain root-owned, not inferred from local results. No AGENTS.md/CLAUDE.md exists; user protocol and README boundary requirements apply. Authentication/testing/debugging/TDD/verification skills and testing reference read. Other Auth worktrees, including root-owned119, are untouched.

Exact clean private CI clones in owned ignored `TestResults/.private`: Defaults `5c5f9479313710fa576f83d3b396442997a2fcf4`, Contracts `78e48ffc4ee000df0510cba5e7c7a3c4c4d539d7`. Builds use absolute `MalievWorkspaceRoot` and `UseLocalMalievDependencies=true`; all outputs are private Release outputs.

Initial TEST/DESIGN ownership allowed only new `Legacy.Maliev.AuthService.Tests/RefreshSessionIdentityBoundaryHttpTests.cs` and this document. The subsequent approved runtime ownership permits exactly one predicate addition in CustomerSelfService.cs. No existing tests, dependencies, config, models or schema are modified. No provider, persistent database, GitHub write, commit, push or deployment actions.

## Source responsibility versus modern protocol

Read-only source mirror checkpoint `bed10c7d15e0698e0b75f1329d0f312937f5d77f`.

| Full source SHA | Exact source boundary | Disposition |
| --- | --- | --- |
| `5fac706a7983a6d359b39acbd670e6800afe020e` | `Maliev.Identities/ApplicationUser.cs`, `ApplicationEmployee.cs`, `ApplicationUserDbContext.cs`, `ApplicationEmployeeDbContext.cs`: independently owned IdentityUser models and identity contexts. | Source evidence for two identity namespaces, not globally unique IDs or a modern refresh-session specification. |
| `72eb9f1949176392141951d35e6e06f7c30af4c2` | Both identity context/builder files and separate ApplicationUser/ApplicationEmployee migration trees change. | Continued separate database ownership; no new source-owner closure. |
| `bed10c7d15e0698e0b75f1329d0f312937f5d77f` | Latest `Maliev.AuthService.Api/Controllers/AuthController.cs` uses separate UserManagers and legacy token endpoints; no equivalent rotating refresh-session/revocation API. | Current Auth-owned protocol correctness, not claimed direct migration of an original refresh feature. Unsafe legacy credential shortcuts and unrelated source commits are excluded. |

Current README promises separate customer/employee identity boundaries, hashed rotating refresh sessions and family revocation. These existing current security requirements justify the boundary, without inventing global ID uniqueness, modern IAM authority or new employee-generation policy.

## Concrete row keys and observed query

`RefreshSession` carries GUID `Id`, GUID `FamilyId`, string `IdentityId`, explicit enum `IdentityKind` (Customer0/Employee1), nullable captured `SecurityStamp`, unique `TokenHash` and timestamps. RefreshSessionDbContext keys rows by GUID Id and uniquely indexes TokenHash; it does not make IdentityId unique. The identities live in different PostgreSQL databases. A same-ID pair is legal in the current models; no assertion about actual production collision frequency/data is made.

Normal AuthenticationService login creates a fresh session/family and stores the selected identity kind/stamp. PostgresRefreshSessionStore rotation preserves kind and checks the corresponding identity store. Revoke and replay operate on an opaque token's family. Google employee issuance also explicitly stores Employee kind; Google provider behavior is not tested here.

Before this candidate, `CustomerSelfService.RevokeRefreshSessionsAsync` filtered only `IdentityId == identityId && RevokedAt == null`; therefore it included an employee row with the same string ID. It has five callers below. The candidate adds only `IdentityKind == IdentityKind.Customer` to that shared predicate. Relational ExecuteUpdate and the nonrelational loop share it; tests use real PostgreSQL, not an in-memory alternate path.

| Customer operation | Wire request / authorization | Existing successful effect |
| --- | --- | --- |
| `POST /auth/v1/customer-self-service/initial-password/complete` | `{email,token,password}`; trusted BFF permission `legacy-auth.customer-self-service`, existing credential-change rate limit | Replaces bootstrap password, rotates stamp, clears bootstrap/lockout state and revokes sessions. Challenge genuinely issued by customer login409 with `set_initial_password`. |
| `POST .../password-reset/complete` | `{email,token,password}`; same BFF permission; request challenge via `password-reset/request` `{email}` | Replaces password, rotates stamp and revokes sessions. |
| `POST .../email-change/complete` | `{email,token}`; same BFF permission; issuance via customer-authorized `email/change` `{currentPassword,newEmail}` | Changes identity email/username, confirms email, rotates stamp and revokes sessions. Auth119 binding retained. |
| `POST .../password/change` | `{currentPassword,newPassword}`; actual customer bearer, LegacyCustomer policy and rate limit; subject selects identity | Verifies current password, replaces it, rotates stamp and revokes sessions. |
| `POST .../password/create` | `{newPassword}`; actual customer bearer, same policy/rate limit | Adds password only when absent, rotates stamp and revokes sessions. |

Confirmation alone is not a caller of this helper. Registration/administration, issuance, token consumption, expiry, generation binding and refresh concurrency are not repair targets.

Inverse employee password reset finalization already filters Employee kind plus exact ID and prior stamp/explicitNULL, preserving later generations. This existing policy must remain unchanged. Employee email confirmation does not perform that password-reset revocation. No inverse same-ID query defect was found by inspection.

## Producer/consumer and impact

Read-only current Web commit `e25168e76f829b147bb5ad415ffdbf570e19a574`: `Legacy.Maliev.Web.Infrastructure/CustomerAuthenticationClient.cs` sends customer-kind login, customer bearer credential changes, BFF recovery/completion and opaque `auth/v1/refresh`/`revoke` bodies `{refreshToken}`. No employee-ID selector is introduced.

Read-only Intranet commit `40275ec6c5b3547ab6d5363fcb8cc03b82d3f473`: `Legacy.Maliev.Intranet.Server/Auth/LegacyAuthClient.cs` uses the same refresh/revoke wire; EmployeeSessionService keeps employee tokens server-side and distinguishes denied refresh from temporary failure. No consumer edit is proposed. QualificationIntrospectionService additionally denies a revoked exact Employee sid/session; no qualification configuration/grants or cross-service tests are implied.

Unrelated employee logout/failed refresh is the concrete consequence; this is not privilege escalation or instant revocation of every issued access JWT. Ordinary JWT expiry semantics stay unchanged. Token-family IDs generated by the existing producer are not replaced by identity IDs or a new composite wire key.

## New real-boundary fixture

Actual Production Program, normal RS256 middleware, controllers, registered identity reader/session store/services and disposable PostgreSQL18. All customer and employee access/refresh tokens come from actual `/auth/v1/login`; BFF JWT comes from actual `/auth/v1/service/login` with ephemeral fixture signing key and configured fixture grants. No fake authentication handler, IAM success, reflection, Google provider or production capability assertion. The fixture's service subject is `service:legacy-intranet`; granting both existing self-service permissions is disposable test setup, not a production grant proposal.

Seed two independent identities with exactly the same ID but different emails and stamps, plus another customer. Actual customer login establishes two live families and a third family revoked through actual HTTP; employee and unrelated customer also log in normally. Five positive mutations must revoke both active customer families, preserve the previous revocation timestamp and unrelated customer's complete row, leave the employee identity unchanged, reject old customer refresh401, then actually refresh the employee200 and verify two unrevoked Employee session rows with its unchanged stamp.

For initial-password and password-create only, test-local owning-DB state changes construct existing bootstrap/passwordless compatibility conditions after real authenticated sessions exist. They do not fabricate authority or assert that production exposes those fixture transitions. The initial-password challenge still comes from real login, and password-create uses the originally issued real customer JWT.

Ten controls: inverse employee reset plus actual customer refresh; customer and employee family-revoke isolation; anonymous/bad-signature401 and employee/service-kind403 on the customer credential route; wrong-password password/email change400 with full identity/session/action snapshots unchanged; actual registered CustomerSelfService precancelled call propagates OperationCanceledException with snapshots unchanged. Precancellation is service-boundary evidence, not an HTTP in-flight cancellation or cross-DB atomicity claim.

Only the inverse employee control enables existing EmployeeRecovery options inside its disposable host and applies the existing migrations to disposable fixture databases. This is not schema activation elsewhere. Host disposal follows existing EmployeeSessionIssuanceHttpTests: capture actual-DI pools, dispose host, ClearPool only those owned pools. Seed contexts clear only their own pools. No ClearAllPools, config/runtime pool edits, connection-limit increase, retries or skips.

## Historical genuine RED and implemented minimal candidate

Untouched baseline: fresh Release0warnings/0errors, 483PASS0skip (`TestResults/session-kind-baseline/baseline.trx`). The new fixture initially triggered xUnit2031 at build time; replacing filtered Assert.Single with its predicate overload fixed only the new test, without weakening any assertion. Fresh Release0W0E then focused15 = 10PASS/5genuine assertionRED0errors/skips (`TestResults/session-kind-red/red.trx`). After adding stronger credential/email/stamp-effect assertions, another fresh Release0W0E and final focused15 retain exactly10PASS/5genuineRED (`TestResults/session-kind-red-final/red.trx`).

Each failing operation reaches successful204, the expected customer email/confirmed/bootstrap/password-hash/stamp effects, and assertions for both customer revocations, previous timestamp, unrelated row, unchanged employee identity and rejected customer refresh. The actual employee refresh then returns401 instead of expected200. Subsequent employee replacement-row assertions are NOT claimed reached in RED. Controls pass independently; no setup failures or error-masking retries occurred.

Final unfiltered diagnostic:498 executed,493PASS/5genuine assertionRED,0errors/timeouts/aborts/skips (`TestResults/session-kind-full-red/full-red.trx`). Comparing actual TRX names with the untouched baseline shows zero missing and zero failing original483 tests. This is a deliberately failing TEST/DESIGN gate, not repaired product acceptance or a coverage waiver.

Commands executed, all inside this owned workspace:

```text
dotnet build Legacy.Maliev.AuthService.Tests/Legacy.Maliev.AuthService.Tests.csproj -c Release -p:UseLocalMalievDependencies=true -p:MalievWorkspaceRoot=B:/maliev-legacy/.worktrees/auth-customer-session-kind-20261001/TestResults/.private
dotnet test Legacy.Maliev.AuthService.Tests/Legacy.Maliev.AuthService.Tests.csproj -c Release --no-build --filter FullyQualifiedName~RefreshSessionIdentityBoundaryHttpTests --logger 'trx;LogFileName=red.trx' --results-directory TestResults/session-kind-red-final
dotnet test Legacy.Maliev.AuthService.Tests/Legacy.Maliev.AuthService.Tests.csproj -c Release --no-build --logger 'trx;LogFileName=full-red.trx' --results-directory TestResults/session-kind-full-red
```

Whole-solution `dotnet format Legacy.Maliev.AuthService.slnx --verify-no-changes --no-restore` passed using the same private dependency properties as environment variables. `git diff --check`, new-test/docs redacted gitleaks scans and unchanged tracked-tree comparison passed at TEST/DESIGN freeze. Coverage was not collected for that diagnostic phase; test counts were not treated as a coverage waiver.

Implemented sole runtime change after root approval: add `value.IdentityKind == IdentityKind.Customer` to the existing shared customer revocation query in CustomerSelfService.cs. IdentityId/current active predicate and timestamps are preserved; all five callers receive the same existing customer-only semantics. No helper signature/interface, schema/index, employee receipt, generation filter, family logic, DTO, auth policy, permission, rate limit or consumer change. No global ID uniqueness or customer-generation fencing is introduced.

Existing customer tests only seed Customer sessions; existing employee-generation tests only seed Employee sessions. Their assertions remain untouched. Existing API80, original owner/parent parity, distributed stamp/revocation races, customer consume-before-save windows, Aspire/browser/provider/deployment gates remain separate.

## Final candidate acceptance evidence

After reparenting and before runtime change, fresh Release0W0E and the complete merged original baseline484PASS0skip (`TestResults/session-kind-merged-baseline/baseline.trx`, filter excludes only the new owned fixture). The merged extra clock case accounts for the increase from original483. After the one predicate, fresh Release0W0E, focus15PASS0skip (`TestResults/session-kind-green-focus/focus.trx`), and unfiltered499PASS0errors/failures/timeouts/aborts/skips (`TestResults/session-kind-green-full/full.trx`). Actual TRX name comparison retains every merged baseline484 test: zero missing, zero failing. The original pre-repair498=493PASS5RED artifacts remain intact as historical proof, not final acceptance.

All five former RED cases now reach employee refresh200, changed refresh token and two unrevoked Employee rows with the unchanged owning identity/stamp. Every prior mutation/revocation/no-effects assertion remains. No existing test was edited or weakened.

Final full command adds `--collect 'XPlat Code Coverage'` to the unfiltered command above and uses `TestResults/session-kind-green-full`. Unexcluded artifact `TestResults/session-kind-green-full/12e8a300-dbcf-483b-a4e5-11e2782c705c/coverage.cobertura.xml`: raw line rates API53.02%, Application98.13%, Domain100%, Infrastructure94.93%, CompatibilityContracts0%, ServiceDefaults17.61%. API80 is still not met or waived; no threshold, exclusion or denominator changes.

Five bounded boundary audits: API/DTO/routes/policies/perms unchanged and real JWT admission controls pass; Domain/migrations/schema unchanged; messaging contracts/transports unchanged; CI/Docker/private refs unchanged with actionlint passing; security reviewed only the one predicate plus cancellation/kind/family controls and scans. These are slice audits, not whole-service/provider certification. Whole format and diff check passed. Five service projects' transitive NuGet vulnerability audit reports no vulnerable packages against the current source. JWT signing-resource scan and scoped runtime/new-test/docs redacted gitleaks pass.

Whole-tree credential scan exit1 retains seven unchanged synthetic fixture connection-string findings, without suppression: AuthenticationServiceTests.cs:186; CustomerIdentityAuthorizationTests.cs:268,269,270; InvoiceDelegationContractTests.cs:192,193,194. No new fixture findings or allow markers introduced. No secrets or signing keys persisted in resources.

Final changed files: CustomerSelfService.cs, new RefreshSessionIdentityBoundaryHttpTests.cs, this document. No live handles remain; candidate and owned outputs are frozen/released to root for independent acceptance. No commit/push/GitHub writes/provider/activation/persistent schema/data or deployment actions.
