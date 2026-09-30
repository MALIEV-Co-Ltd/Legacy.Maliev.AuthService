# Refresh Rotation Retry Prerequisite Design

Status: approved isolated Auth #113 implementation; independent validation recorded below. Exact base a1fb10334f8504a4bf441bde5a2420f4fa686d43. Auth #112 future issuance/introspection remains separate. No DDL, provisioning, grant changes, modern IAM changes, commits or activation.

## Observed Boundary

Actual Production Program and normal registered AuthenticationService/RefreshSessionDbContext fail refresh before rotation: NpgsqlRetryingExecutionStrategy does not support the manual transaction in PostgresRefreshSessionStore.RotateAsync:30. Infrastructure registration enables retries (five attempts, maximum delay ten seconds); keep those exact settings.

Existing behavior to preserve:

- Serializable transaction around original-token lookup, fresh identity/stamp check, replacement insert and original RotatedAt/ReplacedById update.
- Unknown, expired or revoked original returns Invalid.
- A distinct reuse of an already rotated original revokes every row in its family and returns Reused; Auth refuses to issue tokens. Concurrent requests therefore may produce one rotation followed by family revocation, not two surviving sessions.
- Current inactive identity/stamp mismatch revokes the family and returns Invalid.
- Replacement Id/TokenHash/CreatedAt/ExpiresAt are generated once by AuthenticationService before entering the store; successful rotation copies original owner/kind/family/stamp into that replacement.
- Public refresh wire and current grant policy remain unchanged. Existing session fields are sufficient for reconciliation.

The repair retains Serializable rotation and adds a transaction-local PostgreSQL advisory family fence shared with public revocation. Each attempt first selects the family, acquires its fence and re-reads the authoritative original. Public revocation uses ReadCommitted so its update snapshot is established after waiting for a preceding rotation. The key is PostgreSQL hashtextextended of the canonical family GUID, not token material. Hash collisions only serialize unrelated families. A Serializable snapshot taken before waiting can still require a serialization retry; the fence does not remove that need.

The public revocation race was demonstrated before the fence repair: rotation paused after real saved rows, public revoke was observed waiting on an actual PostgreSQL lock, then rotation committed. Revocation missed one new replacement (focused 8 passed/1 failed/0 skipped). Artifact: `TestResults/refresh-family-fence-red/natth_MALIEV-31USFIV_2026-09-30_22_59_15_net10.0.trx`. Root approved coordinating both operations. After the shared fence all nine store regressions passed: `TestResults/refresh-family-fence-green/natth_MALIEV-31USFIV_2026-09-30_23_00_47_net10.0.trx`.

## Proposed Attempt Lifetime

The only runtime file is Infrastructure/PostgresRefreshSessionStore.cs. Both operations create the strategy from the normally configured scoped context, then call ExecuteAsync with the caller cancellation token. Each delegate invocation creates a NEW RefreshSessionDbContext using the exact registered DbContextOptions obtained from the scoped context; no hand-built UseNpgsql, retry override, data-source substitution or interceptor loss.

Each rotation attempt opens its own Serializable transaction, acquires its advisory fence with cancellation, and reads the original token row using SELECT FOR UPDATE. This forces a serialization retry if a waiting attempt's snapshot predates logout, even in read-only receipt reconciliation. Its FamilyId must equal the pre-fence family selection; mismatch denies without writes or acquiring another family. All state writes, receipt reads and family revocation use this explicit attempt context. Do not depend on the original context's tracked replacement/original state. Read-only ILegacyIdentityReader remains the current normal implementation with AsNoTracking queries; no identity cache or replacement with a permissive reader.

Build a new replacement entity per attempt from immutable invocation input. Never attach the same mutable entity across contexts or blindly repeat SaveChanges on prior tracked state. Preserve the supplied replacement Id/TokenHash/CreatedAt/ExpiresAt across retries and only derive owner/kind/family/stamp from the authoritative original.

The transaction contains exactly the original update and replacement insert (or family revocation for reuse/inactive state). Failure before commit disposes/rolls back that attempt before the next begins. Nonretryable errors remain errors. No broad catch, retry-policy relaxation, local claims fallback or disabling Npgsql retries.

## Unknown Commit Reconciliation

After a lost commit acknowledgement, the configured strategy invokes a fresh attempt. Before treating RotatedAt as external reuse, check the existing durable linkage:

1. Original ReplacedById must equal this invocation's stable replacement Id.
2. Replacement row must exist with the exact family, owner, identity kind and security stamp, the expected replacement-token hash, and normalized persisted immutable timestamps expected from the original and invocation.
3. Original and replacement must not be revoked/expired, and freshly read identity/stamp must still be valid.
4. Only then return Succeeded for THIS invocation without a second replacement or family revocation.

Do not infer success from replacement Id alone, existence of any active session, or a token-hash match owned by another family. Distinct invocation input on a rotated original remains genuine reuse and revokes its family. A simultaneous logout/stamp change/reuse can override reconciliation: fail closed, never return success merely because a first attempt committed earlier.

For lost acknowledgement after a deliberate Invalid/Reused family revocation, root explicitly approved returning Invalid after fresh authoritative readback observes the original revoked. This is safe failure, not exact Reused enum parity. A fresh external invocation against an already revoked original retains current Invalid behavior.

This repair handles retryable uncertainty DURING one store invocation. It does not create HTTP refresh idempotency: if the entire successful HTTP response is lost and the client presents the old token again in a new request, normal reuse revokes the family. Do not add a client replay escape hatch.

## Cancellation and Rollback

- Precancelled request throws cancellation without writing.
- Cancellation after SaveChanges but before commit rolls back both original/replacement changes and propagates caller cancellation, without retrying.
- Cancellation after an actual database commit cannot undo that durable rotation. Do not manufacture rollback evidence or issue a token after cancellation; a subsequent external request retains normal reuse rules.
- Known nonretryable failure after SaveChanges leaves original active and no replacement.
- Known retryable failure after SaveChanges rolls back, retries with a different ContextId and persists one replacement.
- Unknown commit persists one replacement and reconciles instead of revoking it; another actual reuse afterward still revokes both rows.

## Owned Test Evidence and Remaining Cases

Legacy.Maliev.AuthService.Tests/RefreshRotationRetryTests.cs uses PostgreSQL 18 and ordinary AddLegacyAuthInfrastructure registration. Faults are added only as context interceptors, preserving registered retries/options. No core reader/store or execution strategy is replaced.

Six bounded cases: two concurrent rotations; known nonretryable saved-row rollback; retryable saved-row rollback with distinct attempt ContextIds; actual database commit followed by synthetic lost acknowledgement; saved-row caller cancellation; precancelled request. Fault tests require Injected=true so an unrelated failure cannot count as fault evidence. Existing pre-fix strategy failure is a prerequisite RED, NOT evidence that those faults have yet been exercised successfully.

Observed exact-pin Release build: zero warnings/errors. Focused RED: five failed, one passed (precancelled caller), zero skipped. Every noncancelled case is blocked by the existing Npgsql transaction/strategy incompatibility before fault injection. Artifact: `TestResults/refresh-prerequisite-red/natth_MALIEV-31USFIV_2026-09-30_22_44_41_net10.0.trx`. Do not claim rollback/unknown-commit/concurrency behavior passed from this RED.

After runtime approval, extend test-first: replacement identity/hash mismatch; revoke/stamp change during lost acknowledgement; unknown acknowledgement on the reuse/inactive revocation paths; inactive/deleted/unconfirmed/locked identity; unknown/expired original; no replacement on terminal denial. Run each RED before implementing its reconciliation branch.

The deterministic public-revocation race and unknown-commit interleavings with actual logout or actual employee stamp update are now covered. Both interleavings deny reconciliation and revoke the family. A separate actual Production Program HTTP regression verifies login -> refresh -> distinct old-token request; the distinct request still revokes the family rather than gaining an HTTP idempotency exemption.

Release build, focused retry/HTTP tests, full suite and applicable format/static checks precede completion. Baseline before owned tests was 301 passed/zero skipped. Do not describe intentionally red preparation as an accepted implementation.

### Additional observed evidence

- Stale receipt snapshot RED: actual committed rotation loses acknowledgement; public logout pauses before its commit holding the shared family fence; reconciliation is observed waiting on PostgreSQL lock, then logout commits. Without original FOR UPDATE, reconciliation incorrectly returns Succeeded. `TestResults/refresh-receipt-snapshot-red/natth_MALIEV-31USFIV_2026-09-30_23_08_51_net10.0.trx` (one failed). After repair, eleven refresh cases plus all seven original recovery caller cases pass (18/18, zero skipped): `TestResults/refresh-receipt-and-recovery-focus/natth_MALIEV-31USFIV_2026-09-30_23_09_47_net10.0.trx`.
- Preserve failed initial expanded-suite evidence: `TestResults/refresh-prerequisite-full/natth_MALIEV-31USFIV_2026-09-30_23_04_02_net10.0.trx`, 235 passed/76 failed/zero skipped of 311. Cascading PostgreSQL 53300 `too many clients already` after recovery initiation returned 503. Fresh isolated rerun of the original seven recovery cases passes without readiness or timeout changes. Root approved clearing only the eleven new fixtures' exact owned idle Npgsql pools after provider/context disposal; no global ClearAllPools, container limit or production setting changed. Final expanded suite has 312 cases (baseline301 plus eleven #113 regressions), excluding five separate #112 preparation cases.
- First cleanup captured only raw migration fixture pools: expanded-suite v2 improved to 308 passed/4 failed/zero skipped, still PostgreSQL 53300 in existing customer-admin migrations (`TestResults/refresh-prerequisite-full-v2/natth_MALIEV-31USFIV_2026-09-30_23_12_04_net10.0.trx`). Normal infrastructure adjusts connection-string pool parameters, creating separate pools. Final owned cleanup captures both raw pools and actual normal registered context connections, then clears these exact six owned pools after disposal. No production parameters changed. Final focus v3: 11/11 passed, zero skipped (`TestResults/refresh-prerequisite-final-focus-v3/natth_MALIEV-31USFIV_2026-09-30_23_14_14_net10.0.trx`).
- Final exact-pin Release build: zero warnings/errors. Final independent full suite: 312 passed, zero failed/skipped (`TestResults/refresh-prerequisite-full-v3/natth_MALIEV-31USFIV_2026-09-30_23_15_06_net10.0.trx`), excluding only five separate #112 preparation tests. The existing 301-case baseline and all eleven owned regressions are included. No live IAM/consumer/deployment or cross-service persistent acceptance is claimed.
- Static acceptance: scoped `dotnet format ... --verify-no-changes --no-restore --include PostgresRefreshSessionStore.cs RefreshRotationRetryTests.cs` exits zero; `git diff --check` clean; gitleaks stdin over the three owned files reports no leaks after rewording a false-positive prose field list (no suppression added); `dotnet list Legacy.Maliev.AuthService.slnx package --vulnerable --include-transitive --no-restore` reports no vulnerable packages in all five projects against current NuGet source.

Fresh identity/stamp reads and refresh-store commit are in separate databases; this repair does not claim an atomic cross-database identity-change fence. It closes the demonstrated refresh-family and unknown-commit reconciliation races, preserves the current fresh-reader policy, and leaves the explicit cross-service state-check/commit race for the separate #112 architecture/runtime acceptance gate.

## Gate and Commit Boundaries

### Root independent acceptance

Root reviewed the final runtime, all eleven regressions and design. Release
build using the absolute private pinned dependency root passed with zero
warnings/errors. Focused tests passed 11/11; the full prerequisite suite passed
312/312 with zero skips (`TestResults/root-refresh-focused` and
`TestResults/root-refresh-full`). Only the five unrelated uncommitted #112
preparation cases were excluded; they will not be present in this PR tree.
Scoped format verification passed. An initial root command used an incorrectly
relative dependency path and failed with one warning/61 errors; correcting the
command, without source changes, restored the clean build. This is bounded
refresh-family acceptance, not a claim that #112 or the entire migration is done.

Root approved this transaction/receipt design and observed focused RED. This prerequisite alone restores ordinary refresh HTTP success; independently validate before changing employee sid issuance. No commits/push until root acceptance. The prerequisite slice includes only PostgresRefreshSessionStore.cs, RefreshRotationRetryTests.cs and this document. Exclude QualificationLiveSessionHttpTests.cs and its separate #112 plan from its eventual commit. This gate does not activate Auth #112 or complete Quotation #70 consumer/runtime integration.
