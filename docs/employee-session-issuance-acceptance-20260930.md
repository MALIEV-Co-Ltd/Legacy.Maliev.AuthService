# Employee Session Issuance Acceptance — Auth #112 Slice 1

Code-only issuance candidate on `codex/qualification-live-authority-20260930`, base `ec0f36b05e2e92a1cbb2284bd5d1e5036c92fc0f` after Auth #113 / PR114. Root reported required PR CI `36744850100` and exact-main CI `36745832463` successful, publish skipped. This slice does not implement or activate introspection, forward employee tokens, change grants or complete Quotation #70.

## Internal Contract and Boundaries

`IAccessTokenIssuer.Issue(LegacyIdentity identity, DateTimeOffset now, Guid? employeeSessionId)` has a required third argument, without a default. Employee issuance rejects null/empty IDs and emits one canonical lowercase Guid `sid`; customer issuance requires explicit null and emits no employee sid. `IssueService` is unchanged. The issuer does not look up a session or grant: the application passes the row ID only after successful persistence.

- Password login passes the persisted first session's ID.
- Refresh passes the newly persisted replacement ID, after normal rotation and fresh identity/stamp validation; it never binds to the consumed original row.
- Google exchange passes its persisted employee session ID after actual nonce consumption, external validation and fresh identity lookup.
- Existing employee permission list, token audience/issuer/RS256/lifetime, customer/service claims and public token envelopes remain unchanged. Employee sid is additive JWT metadata, not a new permission or authorization fallback.
- No refresh-store, API controller, middleware, configuration, migration/schema, consumer, modern IAM or production data changes are included.

`EmployeeSessionIssuanceHttpTests.cs` uses actual Production Program, PostgreSQL 18 and ordinary infrastructure/issuer/store registration. Returned JWTs are cryptographically validated with the normal registered bearer validation parameters. Only Google's external credential validator is controlled; its test exercises the real Google application service/nonce/identity/store/issuer, not an external Google acceptance or full Google HTTP flow. Synthetic service credentials exist only in the isolated test fixture; no runtime provisioning is performed.

## Test-first Evidence

Exact private dependencies: Defaults `5c5f9479313710fa576f83d3b396442997a2fcf4`, Contracts `78e48ffc4ee000df0510cba5e7c7a3c4c4d539d7`, under ignored `TestResults/.qualification-dependencies`.

- Fresh exact-pin Release baseline: zero warnings/errors. Existing accepted suite: 312 passed, zero failed/skipped (`TestResults/qualification-post113-baseline/natth_MALIEV-31USFIV_2026-09-30_23_47_14_net10.0.trx`).
- Prepared future-class rebaseline: four failed/one passed/zero skipped, correctly separating three missing-sid issuance failures, absent introspection endpoint 404 and working refresh operation (`TestResults/qualification-post113-rebaseline/natth_MALIEV-31USFIV_2026-09-30_23_45_15_net10.0.trx`). Historical pre-#113 refresh failures are not current issuance evidence.
- Commit-ready issuance tests, before runtime: three missing-sid failures and six existing compatibility/storage-failure passes, zero skipped. JWT-validation-enhanced RED retained at `TestResults/employee-session-issuance-validated-red/natth_MALIEV-31USFIV_2026-09-30_23_54_44_net10.0.trx`.
- Unbound employee issuance guard RED: no exception before repair (`TestResults/employee-session-issuer-unbound-red/natth_MALIEV-31USFIV_2026-09-30_23_55_28_net10.0.trx`). Empty employee ID and customer-supplied employee ID guard REDs: both returned tokens before repair (`TestResults/employee-session-issuer-guards-red/natth_MALIEV-31USFIV_2026-09-30_23_58_03_net10.0.trx`).
- Minimal runtime plus guards: fresh exact-pin Release zero warnings/errors; focused issuance and existing JWT contract cases passed 20/20, zero skipped (`TestResults/employee-session-focus-green/natth_MALIEV-31USFIV_2026-09-30_23_58_33_net10.0.trx`).
- Final acceptance after test-fixture whitespace correction: Release zero warnings/errors; focused 20/20 passed, zero skipped (`TestResults/employee-session-final-focus/natth_MALIEV-31USFIV_2026-10-01_00_03_07_net10.0.trx`); full candidate suite 324/324 passed, zero skipped (`TestResults/employee-session-final-full/natth_MALIEV-31USFIV_2026-10-01_00_03_47_net10.0.trx`). This is the existing 312-case accepted suite plus nine new issuance cases and three issuer guards, excluding only the separately uncommitted five-case future preparation class.
- Static checks: scoped `dotnet format Legacy.Maliev.AuthService.slnx --verify-no-changes --no-restore --include <owned C# files>` exits zero; git diff check clean; gitleaks stdin over owned candidate files reports no leaks; vulnerable/transitive package audit reports no vulnerable packages across all five projects against current NuGet sources. The unchanged JWT signing-resource scanner function from the CI-pinned Workflows revision `b856eb3dc57fe6597c7a491ecbf65b2938c330a1` was executed against tracked Auth files and passed; no canonical scanner was edited or fetched. Formatting initially reported only a compact test-fixture initializer, corrected without expectation changes before the final fresh build/focus/full run.

The new HTTP regressions assert exact persisted session owner/kind/stamp/refresh-token hash; replacement linkage/family; canonical single sid; unchanged five-field login/refresh and three-field service envelopes; customer/service no sid and unchanged grants. Actual configured save interceptors reject new RefreshSession persistence and require injection observed. Password/refresh HTTP must produce no successful access-token response or new session; Google application must throw before returning an issued result. Refresh failure preserves original active state. These are known pre-commit failure tests, not new unknown-commit or production failure evidence; #113 owns refresh retry/unknown-commit coverage.

An initial new-test build hit xUnit2029 for Assert.Empty over a filtered permissions collection. Corrected to equivalent Assert.DoesNotContain and rebuilt zero warnings/errors before feature RED. This setup/analyzer failure is not feature evidence. Fixture disposal clears only exact owned normal-DI and migration database pools after disposal, preserving production connection/retry settings and the shared test container.

## Candidate Boundary and Remaining Gates

This issuance-only candidate includes four runtime files, exact signature-only adaptations in four test doubles and existing direct issuer fixtures, three issuer guard tests, new issuance regressions and this document. No existing expectations are weakened. The separately uncommitted `QualificationLiveSessionHttpTests.cs` and `docs/superpowers/plans/2026-09-30-qualification-live-session.md` remain future bridge preparation and must not enter the issuance logical commit. Candidate-suite acceptance excludes only that future test class explicitly.

No introspection route/client/capability activation is present. Old already-issued unbound JWTs remain unchanged; later bridge policy will deny them until bound re-authentication/refresh. Current ordinary permissions are not made session-live by sid issuance alone. Session, employee identity and Quotation commit remain separate transaction boundaries; this slice makes no atomic revocation or cross-service TOCTOU claim.

Root independently reviewed the complete four-file runtime and fixture boundaries,
then rebuilt the exact private graph in Release (zero warnings/errors). Focused
issuance/JWT contracts passed 20/20 and the complete commit-ready suite passed
324/324, zero skips, in 1m5s; only the separately uncommitted future preparation
class was excluded. Evidence: `TestResults/root-issuance-focus/root-issuance-focus.trx`
and `TestResults/root-issuance-full/root-issuance-full.trx`. Complete formatting,
transitive vulnerability audit, diff and candidate secret checks passed. Private
dependency outputs remain under the owned `TestResults/.qualification-dependencies`.

Root owns protected PR and exact-head/post-main CI acceptance. No deployment,
provisioning, persistent DDL/data or bridge activation occurred. Auth #112 remains
open until its separately reviewed default-off bridge and consumer gates pass.
