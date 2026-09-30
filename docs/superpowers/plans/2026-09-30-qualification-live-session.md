# Qualification Live Session Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Root review is required before production implementation; no commit or push is authorized.

**Goal:** Provide an opt-in authoritative qualification decision using the existing uniform employee grant policy and exact durable session binding.

**Architecture:** Legacy Auth independently validates an employee JWT supplied by an authenticated, narrowly capable Quotation workload. It reads the exact bound refresh-session row and current employee identity, never signed employee permission claims, alternate sessions, modern IAM admission or invoice delegation. No new employee grants or activation are included.

**Tech Stack:** Actual .NET 10 Production Program, normal RS256 validation, EF Core/Npgsql, PostgreSQL 18 Testcontainers.

**Spec:** This document freezes Auth #112's reviewed contract. Root approved the listed bridge runtime after the fresh 2026-10-01 route RED/design gate. Activation, provisioning and consumer integration remain unapproved and separate.

## Global Constraints

- Current bridge preparation base: 813d4bb6e75bc76c7d27711888c2162ca73b10d5, branch codex/qualification-introspection-bridge-20261001; root observed exact-main CI 36751640791 SUCCESS. Historical preparation base was a1fb10334f8504a4bf441bde5a2420f4fa686d43. Exact Auth CI Defaults 5c5f9479313710fa576f83d3b396442997a2fcf4; Contracts 78e48ffc4ee000df0510cba5e7c7a3c4c4d539d7.
- #113 refresh prerequisite is merged through PR114 at ec0f36b05e2e92a1cbb2284bd5d1e5036c92fc0f; root observed required PR CI 36744850100 and exact-main CI 36745832463 SUCCESS. #112 issuance is merged through PR115 at the current base. Root accepted the fresh RED/design review and released only the listed eight runtime files, new bridge-only tests and this document; no activation or external mutation is authorized.
- No consumer/shared/modern IAM changes, provisioning, persistent DDL/data, deployment, commits or pushes.
- Default disabled; production activation is a separate security/runtime gate. No disabled-mode signed-claim fallback.
- Preserve existing public login/refresh envelopes, customer/service claims, existing employee permission list and all unrelated routes.
- No raw stamp, access/refresh token, email or credential in introspection response/logs. No positive decision cache.

## Review Focus

- Old unbound JWT: deny introspection even if another employee session is active.
- Rotated old session: permit its still-valid access JWT unless its family is revoked; do not substitute the replacement row.
- Stamp change or lockout after earlier allow: next decision denies, without positive-cache reuse.
- Wrong workload or extra/duplicate authority claims: exact capability and immutable caller binding fail closed.
- Refresh prerequisite: separately accepted #113 must merge with exact-main required CI green before fresh #112 binding RED and implementation.

## Frozen Proposed HTTP Contract

POST `/auth/v1/introspection/quotation-qualification` over server-to-server HTTPS. Authentication is the normal Legacy Auth bearer validator, not Testing authentication.

Caller: exactly one `sub=service:legacy-quotation`, exactly one `identity_kind=service`, no conflicting identity aliases, and exactly the dedicated `legacy-auth.quotation-qualification.introspect` capability. Wildcards, invoice capability, customer and employee callers do not satisfy it. The configured current caller entry must retain that capability; removal denies even a still-valid previously issued workload JWT. This new workload capability is code-only and is not provisioned or activated by this change.

Exactly one dedicated signed capability is required; other ordinary configured grants on the same normal workload JWT do not prevent admission and do not become authority for any additional purpose or resource. Duplicate dedicated capability, conflicting identity aliases, wildcard authority or different immutable workload fail closed. The existing service issuer's normal grant deduplication and current configured grant policy remain unchanged. Request-current evaluation concerns the dedicated capability, never an unrelated grant as a qualification entitlement.

Current-capability rule: consult request-current validated service-client configuration for the exact caller, not only its signed capability or startup `IOptions<ServiceClientOptions>`. Removal of the client or dedicated capability must deny the next request with 403 while replaying its otherwise valid previously issued workload token. Invalid/unavailable authoritative configuration must never permit a decision. Prove this through actual configuration reload and normal credential exchange, without replacing authentication or adding grants.

Admission rule: apply a dedicated bounded endpoint limiter only after normal authentication and exact caller/current-capability validation, partitioned by the validated immutable workload subject. Freeze 30 permits per 60-second window, zero queue; validated PermitLimit range 1..30 permits fixture limit 2. Existing Program.cs runs UseRateLimiter before UseAuthentication; a new policy there must not silently partition an unauthenticated context. Use endpoint-local authenticated admission without global middleware reordering or changes to unrelated route limiters. Test missing/wrong callers cannot consume the valid caller's partition, and admitted requests exceed its bound with 429.

Ordering is observable: disabled 404 precedes body binding and authentication challenge. The controller uses an explicit endpoint-local normal Bearer authentication boundary rather than generic Authorize, whose challenge would precede this disabled gate. This special endpoint rationale does not change global middleware or other route authorization. Read current IOptionsMonitor configuration each request: invalid configuration produces generic 503, valid removal of caller/capability produces 403.

Request JSON: `employeeAccessToken` (nonblank compact JWT, maximum 16384 characters), `permission` (exactly `legacy.quotation-requests.read` or `legacy.quotation-requests.update`), `purpose` (exactly `quotation-request-qualification`), `requestId` (positive Int32). Maximum request-body bytes 24 KiB. Never accept a client-provided actor or session override.

Response HTTP 200 JSON has exactly five fields: `allowed` Boolean, `subject` nullable string, `permission` string, `purpose` string, `requestId` Int32. Allowed subject is the validated immutable employee sub. Denial uses `allowed=false, subject=null`, with no reason distinguishing unknown identity, revoked session or bad employee token. Emit `Cache-Control: no-store` and `Pragma: no-cache`.

Errors: 400 invalid shape/limits/permission/purpose/requestId; 401 missing/invalid workload bearer; 403 wrong workload identity/current capability; 404 while disabled; 429 bounded workload admission limit; 503 authoritative-store unavailability; caller cancellation propagated. Never return an allow on exceptions or unsupported input. Error bodies are bounded generic ProblemDetails without supplied tokens/identity details. The absence of enabled code currently produces 404 and is the route RED, not security proof for future denials.

`requestId` constrains bridge purpose, not an invented ownership ACL. Existing qualification grants are global: Defaults currently passes resource `global` because these actions have no resource template. This bridge must not silently enable global/other service permissions or claim a new per-request entitlement policy.

## Employee Trust and Durable Binding

- Normal issuer/key/audience/RS256/lifetime validation independently of caller. Exactly one nonblank `sub` <=256, not `service:`; one exact `identity_kind=employee`; conflicting `user_id`/NameIdentifier aliases deny.
- Exactly one canonical nonempty Guid `sid` binds the JWT to an existing `RefreshSessions.Id`. Never infer session from sub/iat/jti or choose another active row.
- Exact row must match employee kind and sub; be unrevoked/unexpired; have a nonblank stamp matching the freshly read EmployeeIdentity row.
- Introspection-only expiry rule: preserve ordinary JWT validation's existing 30-second ClockSkew for all routes, but after the authoritative session/identity reads obtain a fresh TimeProvider.GetUtcNow(). Deny when that instant is greater than or equal to either the validated employee JWT's explicit exp UTC instant or the exact session row's ExpiresAt. Missing/invalid explicit expiry cannot allow. The earlier JWT-validation timestamp or its skew allowance must not extend a bridge decision beyond either expiry; no global JWT policy change.
- Fresh identity must exist, have confirmed email and satisfy existing lockout rules. No new active-employment, role, customer or per-employee grant interpretation.
- Current source uniform RequestsRead/Update policy is evaluated as code-owned policy. Signed employee `permissions` are not live authority.
- `RotatedAt` alone does not invalidate the old access JWT; JWT expiry remains enforced. Conservatively deny when any row in the exact bound row's FamilyId has RevokedAt set, including historical partially revoked families; do not require the bound row itself to have been revoked.
- Password login, Google exchange and refresh must emit the actual just-persisted row ID. Customer/service issuance does not emit employee sid. Old tokens remain usable on unaffected routes but deny this bridge until refresh/re-authentication issues a bound token.
- Empty stamps deny the bridge; readiness must establish affected migrated employee rows support this policy, without silently changing data.

No schema extension is proposed: existing session fields suffice. Additive JWT metadata is not deployment activation. Auth's existing issuer uses the Legacy audience; do not introduce the incompatible modern exchange helper/global trust settings.

## Issuance Files Already Merged (Excluded from Bridge Runtime)

- Application/AuthenticationAbstractions.cs: session-aware employee token issuance interface while preserving customer behavior.
- Application/AuthenticationService.cs and GoogleAuthenticationService.cs: pass actual persisted session row ID on every employee issuance path.
- Infrastructure/RsaAccessTokenIssuer.cs: single sid emission for bound employee issuance, existing grants unchanged.
- Existing issuer test doubles and direct issuer tests have already been adapted and independently accepted; no further changes are proposed here.
- Infrastructure/PostgresRefreshSessionStore.cs belongs to the separately accepted #113 prerequisite and is excluded from both #112 logical commits.

## Reviewed Bridge Runtime Files and Interfaces

- New Application/QualificationIntrospectionContracts.cs defines QualificationIntrospectionRequest(string EmployeeAccessToken, string Permission, string Purpose, int RequestId), constructor-parameter validation metadata, and QualificationIntrospectionResponse(bool Allowed, string? Subject, string Permission, string Purpose, int RequestId). Define IQualificationIntrospectionService.EvaluateAsync(QualificationIntrospectionRequest request, CancellationToken cancellationToken) returning Task<QualificationIntrospectionResponse>. Define IQualificationCallerAuthorizer.Authorize(ClaimsPrincipal caller) returning QualificationCallerAuthorization (Allowed/Denied/Unavailable plus validated immutable workload subject only on Allowed).
- New Infrastructure/QualificationIntrospectionService.cs implements independent normal RS256 validation using normal Bearer TokenValidationParameters and unmapped claims. Null request is an explicit ArgumentNullException; unsupported permission/purpose/nonpositive resource and blank/overlong token deny before JWT or authority reads even if called independently from MVC. Read exact RefreshSessionDbContext row AsNoTracking, fresh ILegacyIdentityReader.FindActiveAsync, family AnyRevoked, then final fresh TimeProvider time. No store API extension, alternate-session lookup, positive cache or signed employee grant authority. Caller authorizer in this cohesive file uses request-current IOptionsMonitor<ServiceClientOptions>, existing validator, exact signed caller/capability and exact current client/capability. Invalid options => Unavailable; valid removal => Denied.
- New Infrastructure/QualificationIntrospectionOptions.cs defines Enabled=false, PermitLimit=30 validated 1..30, fixed 60-second window and zero queue. No configurable caller allowlist.
- Infrastructure/ServiceCollectionExtensions.cs registers ordinary options binding/validation and service interfaces. Preserve existing JWT, identity reader, data sources/options/interceptors, retry policy and refresh store registrations.
- New Api/Controllers/QualificationIntrospectionController.cs exposes only the frozen POST route, explicit AllowAnonymous with documented endpoint-local authentication, and read-only EvaluateAsync; no actor header or session override.
- New Api/Security/QualificationIntrospectionBoundaryFilter.cs implements IAsyncResourceFilter plus IActionFilter ordered -3000, ahead of ModelStateInvalidFilter (-2000). Set no-store/no-cache first; disabled =>404; normal AuthenticateAsync(Bearer) =>401 on invalid; caller authorizer =>403/503; authenticated admission =>429; cap body at 24576 bytes before MVC binding, using ContentLength fast rejection and capped incremental reads for unknown length; rewind bounded content. After these checks write a request-local HttpContext.Items proof using a private object key, and remove it in finally. Action filter without this proof =>generic401 even with a normally validated principal; no client header can supply the proof. Invalid model state => bounded generic400, without echoing supplied values. Semantic permission/purpose/requestId validation precedes authoritative reads. No global challenge/filter/middleware changes.
- New Api/Security/QualificationIntrospectionRateLimiter.cs is a singleton TimeProvider-backed fixed-window limiter for the one validated immutable workload partition. AttemptAcquire(string validatedSubject) is called only after successful caller/current-capability validation; no attacker-controlled partition dictionary, queue or positive decision cache.
- Api/Program.cs adds only local filter/limiter registration; existing UseRateLimiter/UseAuthentication/UseAuthorization order stays unchanged.
- New Legacy.Maliev.AuthService.Tests/QualificationIntrospectionHttpTests.cs is the intended commit-ready bridge-only suite. Preserve historical QualificationLiveSessionHttpTests preparation and exclude its duplicate issuance cases from the bridge commit; do not silently delete unrelated evidence. All runtime file additions remain subject to root review.

## Tasks and Evidence

### Task 1: Historical Baseline and RED Contract Preparation

- [x] Read instructions and authentication/testing/TDD/planning skills; confirm clean exact base.
- [x] Clone exact dependency objects privately under ignored `TestResults/.qualification-dependencies`; no source fetch/write.
- [x] `dotnet build Legacy.Maliev.AuthService.slnx -c Release -p:UseLocalMalievDependencies=true -p:MalievWorkspaceRoot=<absolute private root>`: 0 warnings/errors.
- [x] Same pinned full `dotnet test ... -c Release --no-build --no-restore --logger trx --results-directory TestResults/qualification-baseline`: 301 passed, 0 failed, 0 skipped.
- [x] Add owned QualificationLiveSessionHttpTests: actual Production Program/normal issuer/PG18 password and refresh HTTP; Google real application/nonce/store/issuer with only external Google credential validator controlled; actual workload credential exchange plus proposed introspection HTTP.
- [x] Password and Google assertions reach JWT missing sid; enabled introspection reaches 404. Refresh reaches HTTP400 before the intended sid assertion; do not label this a binding RED.
- [x] Final focused RED: five failed, zero passed/skipped. Normal-DI direct refresh reveals `NpgsqlRetryingExecutionStrategy` rejecting user-initiated transactions in PostgresRefreshSessionStore.RotateAsync:30. Artifact: `TestResults/qualification-red-final/natth_MALIEV-31USFIV_2026-09-30_22_33_42_net10.0.trx`.
- [ ] Root reviews final RED and this contract before implementation. No current negative test outcome establishes future endpoint admission.

An initial new-test build failed for a missing TestHost import, then compiled cleanly. An initial Production fixture failed its required CORS bootstrap; fixed using fixture configuration only. These are setup failures, not feature RED.

### Task 2: Session Binding (Completed Independently through PR115)

Root accepted issuance commit 7b105ccf55a5048999935864f4a02d147bfbbb39: Release zero warnings/errors, focus20, full324 zero skips, scoped format/security/static checks. PR115 merged at current base; do not repeat or broaden its runtime. The unchecked steps below record the historical sequence, not remaining bridge work.

- [ ] Verify PR114 merged and exact-main required CI green; root assigns the next isolated writer before runtime. Rebaseline the prepared five cases: direct refresh is expected GREEN after #113, while password/refresh/Google binding and the absent endpoint require fresh independent RED evidence. Do not reuse the historical five-failure result as current acceptance.
- [ ] Approve independently buildable interface/issuer/application changes; keep other wire shapes and grants identical.
- [ ] Observe password, refresh and Google binding RED independently, then implement minimal row-ID propagation.
- [ ] Add customer/service no-employee-binding regression and issuance/storage failure evidence. Never return an access token if its row was not persisted; do not mask existing refresh rotation errors.
- [ ] Run Release build, focused issuance tests, full suite, applicable format/static checks before handoff; no commits without root acceptance.
- [ ] Logical commit 1, only after explicit root acceptance/commit authority: employee persisted-session issuance plus its tests/docs. Exclude the still-unimplemented bridge and its intentionally failing tests. Preserve existing employee grants, customer/service claims and all public token envelopes.

### Task 3: Read-Only Bridge, After Fresh RED/Design Approval

- [ ] Extend actual HTTP tests first: default-off, exact/wrong caller/capability, signature/issuer/audience/expiry/algorithm, duplicate aliases/sid, old token, wrong session owner/kind, expiry/revocation/stamp/lockout/email-confirmation/user deletion, unknown permission/purpose/resource and body bounds.
- [ ] Observe expiry RED before repair: test immediately before and exactly at each explicit JWT/session expiry, a token inside ordinary 30-second skew but past explicit exp, and expiry during a controlled authoritative-store read. Ordinary unrelated JWT routes retain their existing skew behavior.
- [ ] Observe admission RED before repair: prove the dedicated partition uses the authenticated exact workload, unrelated/missing callers cannot consume it, and its bound yields 429. Do not globally reorder middleware or weaken existing route limiter tests.
- [ ] Observe current-capability RED before repair: issue through normal service credential exchange, reload configuration removing the dedicated capability or exact client, then replay the still-valid token and require 403. Startup options or signed capability alone cannot satisfy this test; no permission-provider replacement or grant mutation.
- [ ] Exercise rotated old row then family revocation; another valid session must not rescue the old token. Previous allow followed by stamp/revocation changes must deny immediately on next request.
- [ ] Test store errors/cancellation, generic bounded response and no-store headers; assert bridge never changes users, session rows or recovery effects on allows, denials and failures.
- [ ] Characterize TOCTOU using controlled pauses after authoritative reads: commit an identity stamp/lockout change or family revocation, then resume the in-flight check. Document that a change after its corresponding read may still allow that in-flight decision; the next fresh request must deny. This is limitation evidence, not a claim of atomic revocation enforcement or a reason to weaken pre-read denial tests.
- [ ] Implement only approved files. No modern IAM/client substitution, new employee grant, invoice capability reuse or activation.
- [ ] Build/focused/full/unchanged coverage/static/security checks against private outputs.
- [ ] Logical commit 2, only after independent root acceptance/commit authority: default-off bridge, bounded admission/current capability/expiry enforcement and its tests/docs. No new employee grants, activation or consumer integration is included.

### Refresh Prerequisite Gate

Historical preparation found that normal Npgsql retries rejected RotateAsync's manual transaction and HTTP refresh returned 400. This is owned separately by #113 / commit 71da667 / PR114, independently accepted locally with Release zero warnings/errors, eleven focused regressions and the 312-case prerequisite suite passing with zero skips. Its required PR CI and exact-main merge/CI gates are now satisfied. Do not include another refresh-store repair in either #112 logical commit, disable retry, replace the production context or weaken the fixture.

### Current Test/Design Gate: 2026-10-01

- [x] Verified worktree HEAD 813d4bb6e75bc76c7d27711888c2162ca73b10d5; only preserved future test/plan untracked before this update.
- [x] Fresh exact-private-pin Release build: zero warnings/errors. Existing focus filter FullyQualifiedName~EmployeeSessionIssuanceHttpTests|FullyQualifiedName~JwtAccessTokenContractTests: 20 passed, zero failed/skipped. Artifact TestResults/qualification-bridge-baseline-focus/natth_MALIEV-31USFIV_2026-10-01_00_39_31_net10.0.trx.
- [x] Prepared five-case filter FullyQualifiedName~QualificationLiveSessionHttpTests: four passed, one intended failure, zero skipped. EnabledQualificationIntrospection_ValidEmployeeAndExactWorkload_ReturnsBoundedAllowDecision fails expected OK versus actual NotFound at line96 after both normal HTTP logins succeed. Artifact TestResults/qualification-bridge-route-red/natth_MALIEV-31USFIV_2026-10-01_00_40_05_net10.0.trx. This demonstrates only the absent route, not implemented denial security.
- [x] Root reviewed this plan and granted the bounded runtime/new independent test stage. No full baseline rerun: root explicitly accepted324 on identical runtime tree; preparation gate was Release/focus20/routeRED only.

### Bridge Test-First Sequence and Public Injection Points

Every group first builds and records its genuine failing regression, then receives only the minimal approved runtime repair; no changing expectations to match missing behavior. Final suite must be green before candidate handoff. Tests run actual Production Program, normal RSA issuance/validation/credential exchange, disposable PostgreSQL18 and normal DI. Only configured EF interceptors, fixture TimeProvider and reloadable configuration transport are controlled; no auth/identity-reader/store replacement or signed permission fallback.

1. Route/wire: positive normal employee and exact workload for both existing permissions, exact five response fields, explicit null subject on denial, no-store/no-cache, bounded errors and zero mutations. Establish bridge-only positive RED404; add disabled malformed/unauthenticated/oversized404 test but do not count its absent-route pass as security evidence. Build DTO constructor validation rather than suppressing MVC validation.
2. Boundary admission: missing/invalid outer JWT401; valid employee/customer/other workload403; invoice/wildcard/duplicate/conflicting authority cannot admit. Fixture limit2: wrong callers do not consume partition, two valid requests admitted, third429, advance60sec resets. Test known/unknown body length >24576, token >16384, malformed JSON, unsupported content/permission/purpose/id => generic400 without echo. Local resource/action filter ordering is the repair, never global middleware reordering.
3. Current capability: issue via normal service login, replace the whole fixture configuration dictionary and invoke OnReload. Remove client or permission keys completely so resulting configuration is valid =>403; invalid entry/options =>503. Do not represent valid removal by assigning a null array element (that may instead be invalid configuration). Continue replaying the earlier still-valid token; no old options snapshot allowed.
4. Live employee/session: actual login/refresh prove old consumed but unrevoked bound JWT still eligible, then actual normal registered RevokeFamilyAsync denies old/new. Wrong owner/kind/stamp, empty stamp, missing sid/duplicate/alias/issuer/audience/algorithm/signature, deleted/unconfirmed/locked identity, expired/revoked row =>200 false/null. Another active family never rescues invalid binding. A revoked sibling in exact family denies even when exact bound row remains unrevoked. Negative malformed signed fixtures are not positive admission proof.
5. Strict expiry: normal initially valid token; controlled DbCommandInterceptor pause during exact session, identity or final family read; advance fixture TimeProvider to equality/past explicit exp or row ExpiresAt; resume =>deny. Test before/equal each bound, ordinary30sec-skew acceptance followed by strict bridge denial, missing/invalid exp. Normal unrelated JWT policy unchanged; final decision clock is fresh, not captured before I/O.
6. Failure/cancellation: configured normal context interceptors inject actual known provider failures and mark injection reached =>generic503/no allow/no mutations; caller cancellation propagates, never synthesized allow or unrelated retry. Capture no credentials/token/PII in response/log. Dispose normal providers/contexts, then clear only exact fixture-owned pools (raw and normally configured connection strings); no ClearAllPools or readiness/timeout relaxation.
7. TOCTOU characterization: pause after final authority read using ReaderExecutedAsync, commit identity change or family revocation, resume. In-flight result may still allow when change happened after its corresponding read; next uncached request must deny. This pins the limitation, not an atomic cross-database guarantee. Any revocation-before-Quotation-commit veto requires a separately reviewed fencing/transaction/outbox design.

Verification commands use the same private dependency root, sequential outputs: dotnet build Legacy.Maliev.AuthService.slnx -c Release -p:UseLocalMalievDependencies=true -p:MalievWorkspaceRoot=<private root>; dotnet test Legacy.Maliev.AuthService.Tests/Legacy.Maliev.AuthService.Tests.csproj -c Release --no-build --no-restore with focused filter then full candidate suite, excluding only preserved historical future-prep class explicitly. Run scoped dotnet format --verify-no-changes --no-restore, vulnerable package audit, owned-content gitleaks and exact CI-pinned JWT resource scanner. No new coverage checker is invented where Auth CI has none. Root independently reviews/revalidates and owns any logical bridge commit/PR; worker commits remain prohibited.

### Observed Bridge Regression Cycles

- Boundary group: Release0W0E, ten intended failures against absent route, then ten passes. Includes disabled-before-binding/challenge cache headers and local malformed/caller/body boundaries. Artifacts under TestResults/qualification-bridge-boundary-red and qualification-bridge-boundary-green.
- Authority group: nineteen cases, fourteen intended false-versus-true failures and five existing guards passing; fresh repair build0W0E and all twenty-nine accumulated bridge cases passing. Artifacts qualification-bridge-authority-red and qualification-bridge-authority-green-serial. Exact owner/kind/canonical sid/stamp/current identity/family checks are read-only; real normal refresh and family revoke are exercised.
- Admission group: seven intended failures, then six passing plus one mistaken test assumption. Normal outer bearer handler independently returns IsValid=false with exact System.ArgumentException for duplicate sub and HTTP401 before caller authorization. Root approved exact401 expectation; independent inner employee duplicate sub yields false200. No auth handler was replaced. Current valid config removal403, invalid options503, alias/wildcard403 and two-permit/third429 authenticated partition are exercised.
- Expiry/failure corrected RED: nine cases, three intended failures (explicit JWT equality/past expiry allowed and provider failure500), six existing checks/characterizations passing. Strict final fresh expiry and generic known-provider503 repair followed. Initial interceptor matched CLR RefreshSessions rather than mapped refresh_sessions, so its timeout run is fixture setup failure, not feature RED. Both artifacts retained under qualification-bridge-expiry-fault-red and qualification-bridge-expiry-fault-red-corrected.
- Shape RED: seven cases, unknown actor field incorrectly200 and unsupported content type415; five existing validation/body-cap checks passed. Scoped request JsonUnmappedMemberHandling.Disallow and local JSON content check repair only. Oversized body now contains otherwise-valid JSON with padding and application/json for known/unknown-length transport, so malformed content cannot conceal a missing cap.
- Accumulated pre-final focus49 passed, zero failures/skips. Added actual normal customer/other workload/invoice-only denials and blank/overlong token checks before final acceptance. No new grants, production configuration or shared identity/session behavior changed.
- Intermediate Release0W0E/focus54/full378 passed with zero skips before root's defense-in-depth review. Root requested direct service unsupported/null request and direct action-filter missing-proof regressions: six focused cases, five intended failures (three unsupported requests allowed, null request NullReferenceException, missing proof did not deny) and one ordinary additional configured grant admission passing. Minimal service guard and private request-local proof followed. Artifact qualification-bridge-defense-red/natth_MALIEV-31USFIV_2026-10-01_01_32_20_net10.0.trx. This earlier full378 is not the final expanded candidate suite.
- One scheduling error launched tests before a yielded build completed; it produced testhost DLL locks (MSB3026/MSB3027) and stale-binary failures. That build/test attempt is explicitly invalid acceptance evidence; artifacts remain under qualification-bridge-authority-green. No timeout, retry, readiness or output-path policy was changed to hide it. Subsequent build/focus gates ran terminally and serially.

Runtime holds no positive authority cache. The single fixed-window caller admission counter is not a permission cache. No raw tokens, identity stamps, email or provider details are explicitly logged by the new bridge code. Normal framework logging configuration is unchanged; generic responses never expose those values. The current source uniform employee RequestsRead/Update policy is preserved, not expanded into a per-employee DB permission resolver.

### Final Expanded Candidate Acceptance (Worker, Pending Independent Root Review)

- Fresh formatted exact-private-pin Release build: 0 warnings, 0 errors, exit0.
- Focus filter FullyQualifiedName~QualificationIntrospectionHttpTests: 67 passed, zero failed/skipped. TestResults/qualification-bridge-final-focus-expanded/natth_MALIEV-31USFIV_2026-10-01_01_37_49_net10.0.trx.
- Full filter FullyQualifiedName!~QualificationLiveSessionHttpTests: 391 passed (accepted324 baseline plus67 new), zero failed/skipped. TestResults/qualification-bridge-final-full-expanded/natth_MALIEV-31USFIV_2026-10-01_01_38_58_net10.0.trx. Only the preserved historical untracked future-preparation class is excluded; no existing accepted test is excluded. That preparation file is not part of this bridge candidate.
- Scoped dotnet format --verify-no-changes --no-restore over the eight runtime files and new bridge-only test file: exit0. No broad unrelated formatting.
- Owned runtime/test/plan content gitleaks stdin --redact: no leaks; exact CI-pinned Workflows b856eb3dc57fe6597c7a491ecbf65b2938c330a1 JwtSigningResourceScanner function over tracked files plus all new candidate files: PASS. No different current scanner was substituted.
- dotnet list Legacy.Maliev.AuthService.slnx package --vulnerable --include-transitive --no-restore, private dependency environment: all five Auth projects report no vulnerable packages, exit0, current NuGet source. git diff --check passes; direct untracked-file whitespace/readback verification follows final document update.
- Normal Production Program/RS256/PG18 is exercised, with configured EF read faults/pauses, fixture clock and reload transport only. No external IAM, real Google, deployed HTTPS, provisioned workload capability or physical migrated-data readiness acceptance is claimed.

No commit, push, GitHub change, deployment, grant/config activation, live data mutation, schema/store modification or consumer implementation was performed. Root independently reviews and validates the candidate before integration. Default-off code readiness does not establish the employee-token forwarding or producer live-permission chain; Quotation #70 and consumer/runtime readiness remain separately open. In-flight identity/session/config checks and later Quotation writes remain point-of-check boundaries, not an atomic distributed revocation veto.

### Rollout and Rollback

Code-only merge leaves Enabled=false and no caller capability provisioned. Observe all session issuance paths, schema/data readiness, exact workload capability and transport trust before any activation request. New token sid is additive; rollback disables the bridge but does not authorize claim fallback. Existing old unbound tokens require refresh/re-authentication before bridge access. No DDL is authorized or required by this proposal.

Authorization is observed at the live check; revocation and Quotation commit are not a shared distributed transaction. A revoke between allow and producer commit remains a documented race. Consumer forwarding and producer adapter integration are separately owned and #70 remains open.

The employee identity database, refresh-session database and Quotation write are separate transaction boundaries. Fresh uncached reads deny invalid state committed before the corresponding authoritative read; they do not form a simultaneous cross-database snapshot. The #113 family fence serializes refresh/whole-family revocation, not employee identity edits or a later Quotation commit. An identity change after its read or a revoke after Auth's allow can therefore precede a still-successful producer commit. Re-reading, strict expiry and no positive cache reduce exposure but do not prove atomic denial. Any requirement that revocation before Quotation commit forbids that write needs a separately reviewed transaction/fencing/outbox policy and cross-service tests; it is not silently included in #112.
