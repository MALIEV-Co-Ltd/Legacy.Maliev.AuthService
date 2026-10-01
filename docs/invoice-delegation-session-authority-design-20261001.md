# Auth126 invoice-delegation current-session authority

## Current scope and status

This is the bounded current-session admission repair for [Auth126](https://github.com/MALIEV-Co-Ltd/Legacy.Maliev.AuthService/issues/126). Owned base is `924c2679f2150f705cb3680a70cca7c701dc1ce3`. Root independently reproduced the initial31=5PASS/26FAIL and then authorized only existing service/controller async current authority admission plus the precise old positive fixture's real identity/session preparation. That runtime phase supersedes retained TEST/DESIGN-only statements below. Project files, DI registrations, workflows and schema are untouched. No new completion mandate, scope, IAM grant, producer activation or whole-source-owner disposition is authorized.

Local final candidate now passes fresh Release0W0E, focused40 and unfiltered546 with zero skips. Scoped acceptance awaits root independent verification; raw API coverage53.33% remains below80 and the unchanged synthetic credential findings remain disclosed. The admission rule is stronger than the original documented bounded-expiry exchange policy: possession of an otherwise valid employee access JWT must not authorize a NEW invoice-create delegation after its exact durable employee session/family or identity becomes invalid. It does not retrospectively revoke an already issued delegation, globally revoke ordinary access JWTs or add quotation-decision authority.

## Actual boundaries

`InvoiceDelegationController.Exchange` is the existing normal HTTP endpoint `POST /auth/v1/exchange/invoice-create`. It retains the LegacyService policy, exact `service:legacy-intranet` caller, permission `legacy-auth.invoice-delegation.issue`, existing rate limit and canonical positive quotation/nonempty lower D workflow UUID checks.

At the original base, `InvoiceDelegationService.Issue` validates the independently supplied employee JWT using the configured RS256 issuer/key, ordinary access audience and lifetime. It requires exactly one employee subject/kind, one issued-at claim and the signed historical `legacy.accounting.create` claim. It does not read RefreshSessionDbContext or ILegacyIdentityReader; missing/revoked/expired sid, revoked family, changed stamp and inactive identity remain eligible for new issuance. This describes the retained RED, not the subsequent authorized runtime. Signed permissions are still not a current IAM decision.

Existing delegation output remains RS256 with configured issuer/key, `aud=legacy-accounting:invoice-create`, employee `sub`, `azp=service:legacy-intranet`, `scope=legacy.accounting.create`, quotation/workflow binding, fresh jti and 120-second lifetime. No sid, employee JWT, email or permission list is added to that output.

The original source employee acceptance semantics in `6c1a4921b3524dd575cab5b1f4aa5774ad9b8997` (parent `73f045c0f950953bc1ef9b8397e1a16d05dbe543`) and invoice linking in `c821605b7ecde5f79d01966888b116defb10650d` (parent `92e8ad50c5d33f7458e86bf9cd33eabbdb1eb220`) do not define this new modern session admission. Their Auth/Intranet/Quotation owners remain separate; this prerequisite cannot complete those whole records.

## New real boundary tests

The new fixture runs Production Program, ordinary configured RS256 handlers, registered application/infrastructure services and real PostgreSQL18 identity/session repositories. It uses the existing PostgresFixture, which creates uniquely named disposable databases and applies repository migrations only there. No auth handler, identity reader or session store is replaced. Employee and service credentials originate from actual `/auth/v1/login` and `/auth/v1/service/login`; signing keys and client secret are synthetic test-only values never persisted or logged by this fixture.

1. Active acknowledged login lineage issues the unchanged exact Accounting token and leaves session state unchanged.
2. First successful exchange, then actual durable revoked/expired/wrong owner/wrong kind/missing session, stamp rotation/empty stamp, deleted/unconfirmed/locked identity, or revoked family denies a new delegation. Another active family cannot rescue the signed exact sid. Mutations are adversarial disposable storage writes, not legitimate runtime operations.
3. Signed adversarial missing/wrong/duplicate/noncanonical/empty sid, conflicting user_id/NameIdentifier aliases, customer or duplicate kind deny. These tokens are signed by the configured fixture key, not an authentication replacement. Current kind guards can already pass; missing lineage/alias guards are expected new REDs.
4. Actual refresh rotation preserves both bound access tokens while the family is live; actual IRefreshSessionStore.RevokeFamilyAsync then denies both. Rotation by itself is not revocation.
5. Known session-read failure has fixed generic503/no credential disclosure/no new delegation. Until the runtime reads authority, this test fails its explicit FaultReached assertion: that is a missing read-boundary RED, not executed provider-failure proof.
6. Request cancellation must reach an actual session reader, cancel its observed caller token and throw OperationCanceledException. The test races the read signal against completed HTTP and asserts actual read arrival before cancellation; no TimeoutException is accepted as cancellation proof. Until the read exists, the completed200 path is honestly categorized as unreached cancellation instrumentation.

## Reviewed minimal runtime repair (implemented after independent RED)

- Change the existing scoped InvoiceDelegationService to an async `IssueAsync(..., CancellationToken)` using already registered RefreshSessionDbContext and ILegacyIdentityReader; retain issuer, validation options and TimeProvider. No DbContext factory, new database, new DI lifetime, permission framework or schema is needed.
- Preserve current input/service/JWT/permission checks before database effects. Require one canonical nonempty sid and consistent unique non-service employee subject/kind across sub/user_id/NameIdentifier. A missing binding denies rather than choosing any session by employee ID.
- AsNoTracking read exact session: matching employee identity/kind, not revoked, nonempty stamp. Read current active employee through existing authoritative reader; require equal nonblank stamps. Reject any revoked member of the bound family. Preserve live rotated sessions until actual family revocation.
- After authority reads, check fresh TimeProvider time against both validated JWT expiration and session ExpiresAt with strict equality denial. Honor caller cancellation before reads, after awaits and immediately before signing. No positive authority cache.
- Consistent user_id/NameIdentifier aliases remain accepted, matching existing Qualification ExactSubject; any conflicting alias, including a conflicting repeated alias, denies. Do not require aliases absent or deny duplicates whose values are all consistent.
- Controller remains the same Exchange method/route but awaits the service and passes HttpContext.RequestAborted. Existing denial stays generic401. Only identified authority-unavailability errors become fixed redacted503; arbitrary exceptions are not converted to permission allow or generic bad input. Provider exceptions are not rewritten or logged here; never expose token/exception details containing private authority data. Root reviewed and authorized the exact known-error filter before implementation.
- A concurrent change occurring after the corresponding authority read is point-in-time admission, not global transactional revocation. Subsequent exchanges must reread and deny; no assertion of distributed atomicity across identity/session databases.

The implemented service now exposes IssueAsync with the existing scoped session context and authoritative identity reader as constructor dependencies. Existing scoped DI resolves them without registration or lifetime changes. Exchange remains the exact action name, route, policies/caller/rate/output and input400/denial401 categories; it awaits using RequestAborted. Only the reviewed four known authority categories map to fixed ProblemDetails503; there is no arbitrary catch, retry wrapper, signing-resource or public token expansion.

Root's existing qualification controller provides the narrow unavailable-category precedent: NpgsqlException, RetryLimitExceededException, TimeoutException and OptionsValidationException, with caller cancellation checked before returning fixed503 and no provider/token logging. Arbitrary failures do not become allow or a blanket unavailable classification. Root independently reproduced RED and authorized this exact filter; final candidate acceptance remains root-owned.

## Existing positive fixture compatibility requiring separate review

`InvoiceDelegationContractTests.AuthApiFactory.IssueEmployee` already embeds fixed sid `3700f80a-311f-4844-b1c8-96cf737ef9cb`, but configures three unused PostgreSQL strings and creates no current identity/session lineage. Its successful tests will need a genuine disposable row matching that sid/subject/stamp, or normal login tokens with corresponding seeded identities. Preserve every existing output, caller, invalid-token, operation and actor assertion; do not add a runtime fallback for these fixtures. The two-employee positive test requires two distinct valid session bindings. Existing private factories in Accounting delegation-chain tests must be inspected independently when integration scope is approved.

Root independently inspected Accounting.Tests/Fixtures/InvoiceDelegationChainFixture.cs: its old exact-pinned Auth subprocess receives three identical InvoiceDB strings, while handwritten Ordinary(employee...) has no sid or real identity/session seed. Updating that immutable Auth dependency requires genuine employee/session lineage fixture preparation in a separately owned Accounting slice. Passing that existing pinned chain is NOT acceptance of this current-session admission. No Accounting files are edited here.

## Evidence

Exact private CI dependencies live only under this owned `TestResults/.dependencies`: Defaults `5c5f9479313710fa576f83d3b396442997a2fcf4`, Contracts `78e48ffc4ee000df0510cba5e7c7a3c4c4d539d7`, detached fresh clones. No sibling/canonical outputs are used.

Baseline Release command: `dotnet build Legacy.Maliev.AuthService.slnx -c Release --nologo -p:UseLocalMalievDependencies=true -p:MalievWorkspaceRoot=B:/maliev-legacy/.worktrees/auth-invoice-session-revocation-20261001/TestResults/.dependencies`; `TestResults/baseline-release.log` confirms zero warnings/errors.

Baseline full command: `dotnet test Legacy.Maliev.AuthService.slnx -c Release --no-build --no-restore --logger 'trx;LogFileName=baseline-full.trx' --results-directory TestResults/baseline-full` with the same private properties. Terminal baseline is **515PASS/0FAIL/0skip** (`TestResults/baseline-full/baseline-full.trx`).

### Terminal initial RED and fixture-resource diagnostic

Fresh authored-test Release has zero warnings/errors (`TestResults/session-authority-final-release.log`). Focus is **24 executed: 3PASS/21FAIL/0errors/0skip** (`TestResults/session-authority-final-focus/session-authority-final-focus.trx`). Nineteen actual issuance REDs observe HTTP200 where current-lineage denial401 is expected: eleven stored authority mutations, seven signed sid/alias cases and actual family revocation. Active-lineage output and the two already-enforced kind controls pass. The other two failures explicitly prove no authority read occurred: session failure and cancellation instrumentation remain unreached, not executed fault-handling proof.

Unfiltered full diagnostic is **539 executed:407PASS/132FAIL/0skip** (`TestResults/session-authority-full-red/session-authority-full-red.trx`). All new24 retain the same3PASS/21FAIL. Of111 old failures,108 explicitly report PostgreSQL53300 too-many-clients; three old HTTP category failures occur during that exhaustion and are not counted as product defects. This full is not accepted. The new fixture cleared only the original Stores pools, but normal registered infrastructure normalizes MaxPoolSize to20 and therefore uses different pools. Root reviewed and authorized only the existing qualification-fixture cleanup pattern: collect the actual DI-context connections, dispose host, then clear exactly those pools. Server configuration, timeout, production pooling and every test assertion remain unchanged. No broad full retry is performed in this stage; after the bounded correction, root independently reproduces focused RED before runtime approval.

The approved actual DI-pool cleanup was applied only to the NEW Factory, matching existing Qualification Factory.DisposeAsync. Fresh Release0W0E and new24 focus3PASS/21FAIL/0errors/0skip are retained in `TestResults/session-authority-pool-cleanup-release.log` and `session-authority-pool-cleanup-focus/session-authority-pool-cleanup-focus.trx`.

### Additional root-requested expiry and alias controls

The new file additionally contains two exact-boundary tests. Actual normal JWT validation runs at real time; only after an authority-read signal does a controlled injected TimeProvider advance to persisted exact session expiry or the JWT UTC expiration. The pending read is then released and issuance must deny. No validator clock skew, options or timeouts are relaxed. Before a runtime authority read exists, explicit unreached assertions preserve honest missing-boundary RED rather than falsely proving a post-read expiry failure. A second caller-abort case pauses after the final family EXISTS read and checks observed caller cancellation before signing; it too remains unreached until runtime exists. Two consistent alias controls preserve allowed unambiguous subject aliases; two conflicting repeated-alias cases deny. Actual rotated-family proof and all original24 assertions remain intact.

Final frozen stage: `TestResults/session-authority-expanded-release.log` has zero warnings/errors. `session-authority-expanded-focus/session-authority-expanded-focus.trx` has **31 executed:5PASS/26FAIL/0errors/0skip**. Twenty-one actual issuance REDs are eleven durable invalid states, nine signed sid/alias conflicts and actual family revocation. Five are explicit missing-read/unreached scenarios (known store fault, two caller-abort schedules, two post-read exact-expiry schedules), NOT executed fault/expiry handling proof. Active lineage, two current kind guards and two consistent-alias controls pass. This intentionally RED stage is not commit-ready or full-suite accepted.

Commands use the same absolute private workspace root, Release and no-build/no-restore. Expanded focused filter is `FullyQualifiedName~InvoiceDelegationCurrentSessionHttpTests`; logger is `trx;LogFileName=session-authority-expanded-focus.trx`, results directory `TestResults/session-authority-expanded-focus`. Scoped format verification of the new file and both scoped redacted gitleaks scans pass with no suppressions. Baseline515, initial24 and exhausted539 diagnostic artifacts are retained. All processes are terminal; outputs are released to root for independent RED reproduction. No runtime implementation is authorized or present in this stage.

### Subsequent authorized runtime evidence

Root independently built0W0E and reproduced31=5PASS26FAIL. Minimal runtime and exactly reviewed old positive fixture adaptation followed. AuthApiFactory now uses actual disposable identity/session contexts, with seeded active employee7/8 rows and distinct sid7/8 matching the unchanged signed output tests; all old assertion bodies and invalid JWT generation remain unchanged. Normal registered pools are captured and cleared at host teardown, with original context pools also cleared before the disposable container is removed. No fallback or shared/persistent database is used.

First runtime Release0W0E (`TestResults/session-authority-runtime-release.log`); combined new31 plus existing9 focus **40PASS/0FAIL/0skip** (`session-authority-runtime-focus/session-authority-runtime-focus.trx`). Former unavailable/cancellation/expiry probes now reach their exact authority interception before asserting503/OCE/401. This proves controlled database-read faults/schedules, not a real wire outage or distributed revocation transaction. Raw coverage and final unfiltered546/static evidence are pending the serial final gate; no commit-ready/full acceptance claim is made yet.

## Final local candidate and output release

Fresh post-format Release (`TestResults/session-authority-final-runtime-release.log`) is0 warnings/0 errors. Focus40PASS/0skip is in `session-authority-final-runtime-focus/session-authority-final-runtime-focus.trx`. Unfiltered **546PASS/0FAIL/0errors/0skip** is in `session-authority-final-full/session-authority-final-full.trx`; comparing actual TRX names against baseline retains every original515 test with0 missing/changed names and0 old failures. The initial exhausted539 diagnostic and every RED artifact remain intact, not relabeled as passing. Approved pool cleanup eliminates the exhaustion in this final full.

Full command: `dotnet test Legacy.Maliev.AuthService.slnx -c Release --no-build --no-restore --collect 'XPlat Code Coverage' --logger 'trx;LogFileName=session-authority-final-full.trx' --results-directory TestResults/session-authority-final-full`, with environment `MalievWorkspaceRoot=B:/maliev-legacy/.worktrees/auth-invoice-session-revocation-20261001/TestResults/.dependencies`. Fresh build uses the same root and `-p:UseLocalMalievDependencies=true`. No dependency ref/package/config change occurs; both private clones remain clean/detached at exact CI pins.

Unexcluded coverage artifact is `TestResults/session-authority-final-full/a3d4344e-0942-4add-b99e-177ccc23bb4d/coverage.cobertura.xml`. Raw line rates: API53.33%, Application98.13%, Domain100%, Infrastructure95.07%, CompatibilityContracts0%, ServiceDefaults15.68%. API80 remains unmet/unwaived; no generated-code exclusion, coverage filter or denominator edit was added.

Static terminal gates:

- Whole solution `dotnet format Legacy.Maliev.AuthService.slnx --verify-no-changes --no-restore` with exact private environment:exit0 (`session-authority-final-format.log`). `git diff --check` and explicit untracked-file whitespace checks show no errors. Line-ending normalization warnings are not suppressed or presented as whitespace errors.
- `C:/Users/natth/go/bin/actionlint.exe` on explicit `.github/workflows/*.yml` array:exit0 (`session-authority-final-actionlint.log`); workflows are unchanged.
- `dotnet list <project> package --vulnerable --include-transitive --no-restore` for Api/Application/Domain/Infrastructure/Tests:all exit0/no vulnerable package findings (`session-authority-audit-*.log`). These audit the actual private dependency graph, not deployment authority.
- Read-only reviewed `B:/maliev-legacy/Legacy.Maliev.Workflows/scripts/Invoke-JwtSigningResourceScan.ps1 -RepositoryPath <owned-worktree>`:exit0 (`session-authority-final-signing-scan.log`). No signing resources or keys are written.
- The corresponding current-tree credential scanner exits1 with4 unchanged synthetic connection-string fixture findings: AuthenticationServiceTests.cs186 and CustomerIdentityAuthorizationTests.cs268-270. Values remain redacted. The three old delegation fixture literal unused connection strings were replaced only because root authorized real disposable contexts, not to evade the scanner. Whole-tree scan is NOT clean or waived (`session-authority-final-tree-secrets.log`). New/changed runtime, old adapted fixture, new test and owned doc receive separate scoped redacted gitleaks scans without suppressions.

Bounded audits: route/policies/caller/400/401/current output and all old9 contract tests preserved; only known503 declaration is added. Domain/schema/migrations and messaging transports unchanged. JWT signing/claims/scope/audience/lifetime unchanged; current exact session/identity reads are point-in-time, with cancellation/expiry and known storage errors covered. Workflow/Docker/dependency pins unchanged. Accounting/Intranet consumers and modern IAM authority remain separately gated: this cannot claim joined chain, new quotation completion authority or parent source-owner completion.

Five files changed: existing InvoiceDelegationService and InvoiceDelegationController, exact approved InvoiceDelegationContractTests fixture only, new current-session test file and this doc. All handles are terminal; candidate/output ownership is released to root. No commit/push/GitHub edits, new grants, Accounting edits, persistentDDL/data, provider or deployment actions occurred.

No commits/push, external messages, provider calls, credentials/grants, source writes, deployment or persistent data/schema writes occur. Disposable synthetic evidence is not production or full invoice acceptance.

Root independently reviewed the complete runtime diff, all new authority/expiry/
cancellation cases and the precise old positive-fixture adaptation. Fresh Release
passed with zero warnings/errors; combined40 and unfiltered546 passed with zero
skips. Root full TRX `TestResults/root-full546/root-full546.trx` SHA256:
`F59A433DCCBDF5742D7682FE59A00B28A1EF0ACEAE07662AD62229604157568C`.
Whole formatting verification passed. Actual API-coverage follow-up issue122 is
OPEN; the numeric80 above denotes the threshold, not issue80 (which is unrelated).
Exact-head protected CI and post-main acceptance remain pending at commit time.
