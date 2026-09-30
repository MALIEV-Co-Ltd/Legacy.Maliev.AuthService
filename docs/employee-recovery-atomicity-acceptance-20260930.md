# Employee recovery atomicity candidate — 2026-09-30

## Current implementation gate

Root approved the bounded runtime/additive-schema implementation after the read-only design gate. The candidate is isolated in `B:/maliev-legacy/.worktrees/employee-recovery-atomicity-20260930` from exact Auth main `7a03f023c1c91759994507347b170b91c21f69c0`. The writer's original no-commit handoff is superseded by root integration after independent acceptance; protected PR and exact-head/post-main CI remain mandatory. Persistent DDL, deployment, notifications and other-repository source edits are not authorized by this code slice. The historical RED-only section below describes the initial lane, not current runtime authorization.

The candidate adds `EmployeeRecoveryEffects` in EmployeeIdentity and employee-only binding/finalization columns in Auth-state `identity_action_tokens`. `AspNetUsers` is unchanged. An identity transaction atomically saves the effect and immutable receipt. Auth then atomically consumes/finalizes and revokes only the receipt's before-epoch employee refresh sessions plus explicit NULL-stamp legacy sessions. New/later epochs remain untouched. Confirmation retains its existing explicit revocation policy. Existing access JWTs are not instantly revoked.

The receipt binds action ID, original opaque-token SHA-256, exact authenticated caller JWT subject, purpose, target identity, normalized email and before epoch. Reset payload verification uses the salted ASP.NET Identity PasswordHasher hash stored with the applied effect; no plaintext token/password or unsalted password digest is persisted. Matching pending requests finalize only; terminal replays and wrong payload/owner/email/purpose return generic 400. Transient incomplete work is generic 503. A failed unapplied identity save rolls back without burning the challenge.

Every Auth transaction attempt uses fresh contexts; every employee mutation attempt takes `FOR UPDATE` and freshly probes its receipt before applying an effect. Thus configured Auth retry cannot blindly reapply a cross-database identity mutation, including uncertain commit outcomes. Different employee actions share one identity-scoped Auth coordinator. Admin update/delete acquire the employee identity lock before reading employee-local outstanding receipts; unresolved delivery maps intentionally to generic 503. They never acquire Auth locks while holding identity locks. Worker reads committed receipts only, performs exact action/receipt binding checks and Auth finalization, then acknowledges delivery separately. It never applies credentials or holds an identity-row lock while acquiring Auth state. Issuance reconciles committed effects before supersession.

### Coordinated rollout prerequisites — not executed

`EmployeeRecovery:Enabled` defaults to false. Recovery, employee update/delete, worker and readiness fail closed until the explicit opt-in and reviewed physical schemas are present. Readiness checks column types/nullability, primary keys, exact reviewed PostgreSQL constraint expressions and valid/ready nonpartial unique/index structures, not just migration history. Unknown catalog renderings fail closed and require review.

1. Drain/disable old recovery and employee-identity writers, including any writer bypassing the new locking protocol. Additive schema compatibility does not make mixed old/new mutation writers safe.
2. Through a separately authorized migration process, apply the EmployeeIdentity receipt migration and Auth binding migration. No startup migration, `EnsureCreated`, automatic DDL or legacy unsafe fallback exists.
3. Coordinate both trusted Intranet callers on stable JWT subject `service:legacy-intranet`; never substitute a browser employee subject or fallback owner. Intranet source changes are outside this owned Auth candidate and remain a rollout dependency.
4. Enable new writers/worker only after physical readiness succeeds. Pre-upgrade employee challenges without versioned binding are rejected; issue fresh links.
5. Rollback requires another writer drain. Retain receipt/action evidence and use a forward fix after effects exist; generated Down migrations are not authorization to delete receipts or restore unsafe old recovery. Do not purge pending receipts. Any retention policy is a separate reviewed action.

Auth issue #108 remains open for trusted-BFF end-to-end and production-derived Aspire acceptance. Auth #97 invoice delegation is an independent contract and is not completed by this recovery slice. Target-extension/schema preservation must be reviewed through the designated data owner before physical rollout. This is code plus an additive rollout candidate, not a production activation.

### Runtime validation checkpoint

- Fresh exact-pin baseline: Release 0 warnings/0 errors; original focused RED 23 passed/5 failed, saved at `TestResults/design-gate-red/design-gate-red.trx`.
- Missing-owner controller RED: 1 failed; physical weakened-constraint RED: 5 passed/1 failed; partial-index RED: 6 passed/1 failed; PostgreSQL NULL/check-invariant RED: 3 failed. These proved the reviewed safety gates before their corresponding repairs.
- Focused runtime/HTTP/admin verification: 63 passed/0 failed/0 skipped at `TestResults/recovery-focused-final/recovery-focused-final.trx`; preceding exact-pin Release build 0 warnings/0 errors.
- Real HTTP/JWT cases preserve existing early-denial semantics: missing/empty subject 403, duplicate JWT subject 401, missing permission 403, invalid signature/expired JWT 401; correctly authenticated wrong owner 400. No fake authentication scheme or fabricated HTTP principal is used. Direct-controller owned principals remain only in pre-existing service-boundary tests.
- PostgreSQL 18 tests cover the original five Atomicity cases without weakening their state assertions, pending retry/replay, worker fault/cancellation/nonapplication, held-identity-lock finalization, before/NULL/new/later refresh epochs, admin pending 503, issuance reconciliation, both uncertain committed-transaction outcomes, feature opt-in and physical schema drift despite applied migrations.
- Actual hosted-worker lifecycle additions: 3 passed/0 failed/0 skipped at `TestResults/hosted-worker-final/hosted-worker-final.trx` (delivery, cancellation during finalization, disabled opt-in).
- Final exact-pin Release build: 0 warnings/0 errors. Full affected Auth suite after all source/test changes: 296 passed/0 failed/0 skipped at `TestResults/recovery-complete-final/recovery-complete-final.trx`; collected coverage at `TestResults/recovery-complete-final/bebe4e31-4715-4846-8157-ae9b1addb62a/coverage.cobertura.xml`.
- Auth service modules aggregate line coverage: 3176/3766 = 84.33%; Infrastructure 92.10%, Application 97.15%, Domain 95.24%. API-wide 46.94% is a residual broad-suite coverage gap; the aggregate service floor is met, but no per-module 80% claim is made. Shared dependency assemblies are not counted as this service's coverage.
- Scoped `dotnet format --no-restore --verify-no-changes`, `git diff --check`, read-only `dotnet ef migrations has-pending-model-changes --context RefreshSessionDbContext`, and redacted gitleaks scan of complete tracked/untracked candidate source all pass. The EF tool emits an older-tool notice (10.0.5 versus runtime 10.0.12); its model check returns no changes and exit 0. No tool installation was performed.
- All database DDL exercised by this lane is confined to disposable PostgreSQL 18 Testcontainer-owned databases. Owned Defaults and Contracts clones remain clean at the exact pins above. No persistent schema rollout or BFF/Aspire activation is claimed.

### Root-review expiry correction

Root review identified a real expiry window: the preliminary action check occurred before waiting on employee `FOR UPDATE`. A valid unapplied action could expire during that wait and still mutate credentials. Deterministic PostgreSQL tests hold the real identity row lock, observe the recovery lock-read boundary, advance the controlled clock 25 hours, then release the lock. No timing sleep or lifetime extension is used.

The pre-fix expiry filter records 3 passed/2 failed at `TestResults/expiry-under-lock-red/expiry-under-lock-red.trx`: reset and confirmation wrongly applied after the wait; committed-after-expiry receipt finalization and fresh-clock rollback retry controls passed. The minimal repair freshly checks expiry under the identity lock after awaited receipt reads and immediately before a new credential effect. The existing receipt path remains first and may finalize after original expiry without rehashing or rotating stamps again. No schema change is involved.

Post-fix exact-pin Release is 0 warnings/0 errors. Expanded focused runtime/HTTP/admin tests record 71 passed/0 failed/0 skipped at `TestResults/expiry-focused-green/expiry-focused-green.trx`. Final affected Auth suite records 301 passed/0 failed/0 skipped (1 minute 5 seconds) at `TestResults/expiry-full-green/expiry-full-green.trx`, including all 296 prior cases and five new expiry cases. Coverage is collected at `TestResults/expiry-full-green/7681bac6-53a8-4da4-84f7-1b51b73c9638/coverage.cobertura.xml`. Scoped formatting verification, `git diff --check`, clean exact-pin dependency readback and redacted complete-candidate gitleaks scanning pass. This supersedes the earlier 296-case checkpoint; independent root acceptance and operational rollout remain pending.

### Independent root acceptance of the final candidate

Root repeated the exact-pin Release build (zero warnings/errors), focused recovery/HTTP/admin suite (71 passed, zero failures/skips), and complete affected solution (301 passed, zero failures/skips; 54 seconds). Evidence is retained in ignored `TestResults/root-recovery-focused/root-recovery-focused.trx` and `TestResults/root-recovery-full/root-recovery-full.trx`. Whole-solution formatting, diff checks, the Auth-state EF pending-model check and all five projects' transitive vulnerability audit passed. EF reported an older installed tool (10.0.5 versus runtime 10.0.12), but returned exit zero with no pending model change; no tool installation or persistent migration was performed. Required hosted exact-head and post-merge validation, physical schema readiness, coordinated old-writer drain, trusted-BFF and Aspire acceptance remain separate gates.

## Historical initial RED-only lane

Auth issue #108; test-only candidate on `codex/employee-recovery-atomicity-20260930`, exact protected main `7a03f023c1c91759994507347b170b91c21f69c0`. Live remote main matches; CI - Main `36705975045` is completed/success at that SHA. Only `EmployeeSelfServiceTests.cs` and this note are owned. No runtime/schema/source-history/canonical/other-worktree source changes, commits, pushes, deployment, notification or persistent data actions are authorized. Root owns saga/public-contract/rollout decisions.

## Real execution and isolation

Tests use the existing `PostgresFixture` PostgreSQL 18-alpine Testcontainer and existing private fixture. Each case has separately migrated, uniquely named employee-identity and refresh/action-state databases. Recovery and admin use distinct EF contexts; final assertions use `AsNoTracking`. No SQLite, InMemory provider, SQL fallback, production hooks, fake recovery service or fabricated principal is used.

The initial default build succeeded 0W0E but resolved the default sibling shared dependency outputs; it is not authoritative exact-pin evidence. Before any test, the candidate switched to owned ignored `TestResults/.dependencies` local no-fetch clones: Defaults `5c5f9479313710fa576f83d3b396442997a2fcf4`, Contracts `78e48ffc4ee000df0510cba5e7c7a3c4c4d539d7`, both exact and clean. All subsequent builds/tests use these outputs. No shared dependency source was edited.

Build command:

`dotnet build Legacy.Maliev.AuthService.slnx -c Release --nologo -p:UseLocalMalievDependencies=true -p:MalievWorkspaceRoot=B:/maliev-legacy/.worktrees/employee-recovery-atomicity-20260930/TestResults/.dependencies`

Focused command:

`dotnet test Legacy.Maliev.AuthService.Tests/Legacy.Maliev.AuthService.Tests.csproj -c Release --no-build --no-restore --filter FullyQualifiedName~EmployeeSelfServiceTests --results-directory TestResults/employee-recovery-final-red --logger 'trx;LogFileName=employee-recovery-final-red.trx'`

## Desired acceptance and observed RED

| New test | Deterministic boundary | Desired behavior | Actual first RED |
| --- | --- | --- | --- |
| `Atomicity_AdminAfterRecoveryRead_PreventsStaleIdentityMutation(false)` | State command interceptor before first `UPDATE identity_action_tokens`, after recovery reload/hash construction; real admin update commits through another employee context before allowing consume. | Generic invalid-action result; preserve winning admin password/stamps/confirmation and do not revoke sessions for rejected action; replay remains 400. | Recovery returns 204, overwrites both admin stamps/password, and revokes the session. |
| Same test `(true)` | Same barrier, email confirmation purpose. | Preserve admin's unconfirmed state/stamps; invalid-action result. | Recovery returns 204, replaces both stamps and confirms email. |
| `Atomicity_IdentitySaveFailure_UnappliedChallengeCanRetryThenRejectReplay(false)` | Existing test-only `FailSaveInterceptor` throws before identity save, after action-state consume. | Unapplied valid action is not terminally consumed; unchanged endpoint retries successfully after removing fault, revokes sessions, then terminal replay 400. | Identity remains unchanged but action is consumed; matching retry returns 400, no password/stamp change or session revocation. |
| Same test `(true)` | Same identity-save failure, confirmation purpose. | Same retryability; confirm exactly once, retain confirmation's unchanged session policy, terminal replay 400. | Consumed action, matching retry 400, unconfirmed identity remains unchanged. |
| `Atomicity_RevocationFailure_RetryFinalizesWithoutReapplyingIdentityEffect` | State interceptor throws only before first `UPDATE refresh_sessions`, after employee save committed. | Matching original owner/email/purpose/password retries finalization only, without changing password hash/stamps again; terminal replay 400. Wrong password/email/purpose remains 400. | Password effect commits while session stays active. Matching retry returns 400 and session remains active; mismatched requests and terminal replay are rejected. |

Barriers are one-shot per recovery context. The competing admin callback is bounded by `WaitAsync(10 seconds, cancellationToken)`; every new completion/query path has a 30-second cancellation deadline. No timing sleeps or parallel shared-context writes are used. The state interception is attached only after initial challenge issuance, so superseding/seed writes cannot accidentally trigger it. The failure interceptor exposes `Triggered` solely to prove the injected boundary was reached; existing burn/fresh-request test assertions remain unchanged.

`Assert.Multiple` records every independent state/result mismatch rather than stopping after the first failure. All passwords/emails/stamps/hashes in fixtures/results are synthetic; generated TRX/database/output artifacts remain ignored and noncommittable.

These tests invoke real public controller methods and real recovery/admin services with PostgreSQL. They preserve the controller request/result shape, but do **not** exercise HTTP model binding, JWT authorization or shared exception middleware. A first transient failure must ultimately map generic 503, not false 204 or invalid-action 400; no HTTP 503 acceptance is claimed by this slice. Owner-subject binding across trusted BFF callers also needs real HTTP/JWT coverage when runtime is assigned.

The existing `CompletePasswordReset_IdentitySaveFailureIsNotSuccessAndFreshRequestCanRecover` remains untouched: it characterizes today's terminal burn/fresh-link behavior. Its conflicting expectation needs a reviewed replacement with the runtime saga, not an ad-hoc weakening in this RED candidate.

## Minimum coherent repair proposal — not implemented

1. Guard employee mutation against the exact observed identity ID/security stamp/normalized email, including admin updates after recovery read. A last read alone still races. Preserve the existing `AspNetUsers` schema and use atomic conditional mutation or reviewed concurrency enforcement.
2. Replace terminal consume-before-effect with a durable action operation: original owner, purpose, identity epoch and protected canonical payload binding; explicit claimed/pending/applied/finalized/terminal states and bounded leases. An unapplied transient failure must remain retryable, not terminally consume the challenge.
3. Persist an identity-side operation receipt atomically with the identity effect in the employee database. Auth-state phase alone cannot distinguish crash-after-identity-commit from crash-before-commit. Matching retry uses that receipt to avoid a second password hash/stamp rotation and resumes required refresh revocation only.
4. Finish revocation and durable finalization before returning 204; retries for already terminal operations return existing generic 400. Transient incomplete work maps generic 503 through the unchanged endpoint. Never allow wrong payload/owner/purpose to take over pending work.
5. Add bounded worker recovery for interrupted phases. Any worker-capable credential intent needs an owner-reviewed protected, expiring representation; never persist plaintext password/token or emit them in logs. Do not prematurely choose new tables, encryption/key policy or deployment ordering in this test-only lane.

A stamp-only fix is insufficient for the two-database failure windows. A state-only saga is insufficient without an atomic identity-side effect receipt. Fresh-link recovery does not finalize an already committed password effect whose refresh sessions remain active. Root must approve the complete durability/security/schema/rollout slice before runtime edits.

## Validation checkpoint

- Exact-pin baseline Release: 0 warnings/0 errors; existing focused tests 23 passed/0 failed/0 skipped.
- First candidate Release: 0 warnings/0 errors; focused RED 23 passed/5 failed/0 skipped (28 total, 9 seconds). Artifact: `TestResults/employee-recovery-red/employee-recovery-red.trx`.
- Final candidate Release: 0 warnings/0 errors (2.31 seconds). Final focused RED rerun: 23 passed/5 failed/0 skipped (28 total, 8 seconds); preserved at `TestResults/employee-recovery-final-red/employee-recovery-final-red.trx`.
- Affected full Auth suite: 257 passed/5 failed/0 skipped (262 total, 1m34s); preserved at `TestResults/employee-recovery-full-red/employee-recovery-full-red.trx`. Only the five new `Atomicity_*` cases fail; all existing tests pass.
- `dotnet format Legacy.Maliev.AuthService.slnx --no-restore --verify-no-changes --include Legacy.Maliev.AuthService.Tests/EmployeeSelfServiceTests.cs`, `git diff --check`, and redacted gitleaks stdin scan of both complete candidate files pass. Final source/evidence readback confirms only the two allowed paths are changed.
- This is deliberately failing acceptance evidence, not a completed runtime repair or committable green slice. No production/persistent/cloud/original-source execution is involved.
