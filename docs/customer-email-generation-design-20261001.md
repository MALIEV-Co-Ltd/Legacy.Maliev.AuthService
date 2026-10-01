# Auth #119 — customer email-action generation binding

Runtime candidate for independent root review. Root approved the bounded repair after the final genuine RED design gate; only CustomerSelfService.cs has changed. No commit, rollout or deployment is authorized by this document.

## Ownership and baseline

Bounded issue [Auth #119](https://github.com/MALIEV-Co-Ltd/Legacy.Maliev.AuthService/issues/119). Main/live origin observed clean at `f1c007b838dcba45a4fd7351c2a2d94e30370225`. Owned workspace `B:/maliev-legacy/.worktrees/auth-customer-email-generation-20261001`, branch `codex/auth-customer-email-generation-20261001`. No AGENTS.md/CLAUDE.md exists in this repository; user execution protocol and README ownership boundaries apply. Auth/testing/debugging/documentation skills were read; Context7 is unavailable, so versioned official source was used.

Exact clean private CI clones at `TestResults/.private`: Defaults `5c5f9479313710fa576f83d3b396442997a2fcf4`, Contracts `78e48ffc4ee000df0510cba5e7c7a3c4c4d539d7`. Each service/dependency output is an owned Release output. Other Auth worktrees, source, Notification and released Customer/Catalog outputs are untouched.

## Source traceability, not blanket resolution

Read-only source mirror checkpoint `bed10c7d15e0698e0b75f1329d0f312937f5d77f`. Local MigrationTracking ledger at `7a1b95c2d6bfdd2bec8384152d58121a61886220` inventories source paths at that checkpoint, but its Auth target is older `8cdb634b`; this inventory is not current implementation acceptance. No ledger modification or owner closure occurs.

| Full source SHA | Owner/path evidence | Disposition in this slice |
| --- | --- | --- |
| `5fac706a7983a6d359b39acbd670e6800afe020e` | Auth-owned `Maliev.Identities/ApplicationUser.cs` inherits IdentityUser; Web-owned `Maliev.Web/ServiceExtensions.cs` registers EF identity stores and AddDefaultTokenProviders. Web confirmation and change-email pages generate/consume UserManager tokens. | Pending email-action security-state validation is the selected source-compatible responsibility now owned by Auth. Initial commit contains many unrelated owners/features; not resolved as a whole. |
| `72eb9f1949176392141951d35e6e06f7c30af4c2` | Auth-owned identity context/migration updates; Web registration continues AddDefaultTokenProviders with the IdentityUser-backed customer context. | Confirms continued identity/token generation boundary; no schema, lockout or whole-commit acceptance. |
| `b2201588a8886a9f5befc3cf80ad279415b14d1c` | Web callback round-trip repair includes `Pages/Account/EmailConfirmation.cshtml.cs` and `ChangeEmailConfirmation.cshtml.cs`; ledger does not assign an Auth owner to this record. | Consumer compatibility context only; this producer test does not close Web ownership or callback/browser delivery acceptance. |
| `5e2030b7339d4d9bd699fd8c3f406b71706b377d` | Auth-owned shared `Maliev.Identities/IdentityEmailTokenCodec.cs`; removes the duplicate Web codec. Current committed callbacks decode candidates then call UserManager confirmation/change-email. | Encoding is distinct from generation authority. Opaque existing JSON/link tokens remain unchanged; shared codec/source owner is not blanket-completed. |

Source Web package references include Microsoft.AspNetCore.Identity.EntityFrameworkCore 8.0.3. The [official v8.0.3 DataProtectorTokenProvider](https://github.com/dotnet/aspnetcore/blob/v8.0.3/src/Identity/Core/src/DataProtectorTokenProvider.cs) writes the identity ID, action purpose and security stamp into a protected token, then validates them against the current identity. This proves the stamp dependency for normal non-null source stamps. It does NOT prove source acceptance of NULL stamps: generation substitutes an empty string, while validation compares to the current stamp. Migrated null/empty support below is an explicit compatibility adaptation, not an original-provider guarantee.

## Historical observed defect and unchanged actual wire chain

Before this candidate, `CustomerSelfService.CreateChallengeForIdentityAsync` persisted only an unbound token hash for `email-confirmation` and `email-change`. Pending `FindActionAsync` and `FindEmailChangeActionAsync` did not compare current security generation. Password reset, initial-password and resend recovery already have separate stamp-bound mechanisms and are excluded.

| Boundary | Existing contract preserved |
| --- | --- |
| `POST /auth/v1/customer-self-service/email-confirmation/request` | Authenticated trusted-BFF `legacy-auth.customer-self-service`; body `{email}`; internal `{accepted,token}`. Unknown account remains accepted with no token/state. This is not a browser enumeration-safe envelope by itself; Web masks it. |
| `POST .../email-confirmation/complete` | `{email,token}`; success204, invalid/expired400 generic ProblemDetails. |
| `POST .../email/change` | Customer Bearer subject, current-password validation, existing credential-change rate limit; `{currentPassword,newEmail}` returns internal challenge. No identity selector supplied by browser. |
| `POST .../email-change/validate` | BFF permission and `{email,token}`; existing `{databaseId,currentEmail,newEmail,completed}` or generic400. |
| `POST .../email-change/complete` | BFF permission and `{email,token}`; success204, terminal replay400. |

Current Web observed at `e25168e76f829b147bb5ad415ffdbf570e19a574`: `Legacy.Maliev.Web.Infrastructure/CustomerAuthenticationClient.cs` uses these exact Auth JSON routes and server service token. `Legacy.Maliev.Web/Pages/Account/ChangeEmailConfirmation.cshtml.cs` receives `email`/`token` link parameters, applies no-store/no-referrer, and calls `CustomerEmailChangeWorkflow`. That workflow validates FIRST, updates the Customer profile, then completes the Auth identity. Its existing `Completed` branch can reconcile a profile, and an unavailable completion probes that branch. Therefore the consumed projection is NOT merely read-only and MUST remain compatible; this slice neither changes nor establishes atomicity for that cross-service chain.

## Implemented bounded candidate

Only runtime file: `Legacy.Maliev.AuthService.Infrastructure/CustomerSelfService.cs`. No domain/model/migration/controller/DTO/client/auth-policy/permission/config changes.

Use the existing nullable `IdentityActionToken.BoundSecurityStamp` PostgreSQL text column for a purpose-local, explicitly tagged generation digest. Customer action `RecoveryVersion` stays NULL; no employee recovery fields/protocol are populated or modified. The existing employee check constraints restrict non-null RecoveryVersion to employee purposes, so the new customer representation must not reuse that version. Do not use BoundNormalizedEmail's 256-character column for customer email (request limit320); normalized emails belong inside the digest frame, without truncation.

Exact implemented encoding:

```text
frame = UTF8(System.Text.Json serialization with default options of:
  ["legacy-auth/customer-email-generation", 1,
   purpose, identity.Id,
   identity.Email.Trim().ToUpperInvariant(),
   targetEmail.Trim().ToUpperInvariant(),
   identity.SecurityStamp])
binding = "ceg1:" + lowercaseHex(SHA256(frame))
```

The typed array has seven ordered entries, with JSON number1 and JSON null distinct from empty-string `""`. Only exactly `email-confirmation` or `email-change` may use this helper. Frame fields are persisted identity/action values, not raw passwords or refresh/access/action tokens. Standard JSON framing prevents delimiter ambiguity; ordinal typed stamp state is not trimmed, normalized or silently initialized. The existing request identity/email contracts and lengths remain unchanged. Case-insensitive email semantics are preserved. Format is exactly69 characters, `ceg1:` plus64 lowercase hexadecimal characters. Unknown version, malformed/noncanonical digest or NULL binding fails closed before consumption.

Private signatures:

```csharp
private static string CreateCustomerEmailGenerationBinding(
    string purpose, LegacyIdentityRow identity, string targetEmail);
private static bool CustomerEmailGenerationMatches(
    IdentityActionToken action, LegacyIdentityRow currentIdentity);
```

Comparison: verify exact prefix/length/canonical hex first, decode exactly32 bytes and compare to freshly recomputed SHA256 using `CryptographicOperations.FixedTimeEquals`. Never log the frame, token, email, password, stamp or binding. No custom signature/identity acceptance cryptography is introduced; this is stored action generation binding only.

Issuance loads a fresh `AsNoTracking` customer snapshot from the owning PostgreSQL identity store and persists the binding with the existing raw-token hash/action purpose/target. It must not initialize a blank stamp. Pending confirmation lookup, pending email-change validation and completion load current identity state from PostgreSQL (not previously tracked stale state) and require a matching binding before consuming. All old ordinary token/hash/target/purpose/expiry and row-update checks remain. No generic whole-two-database retry is proposed.

Consumed email-change validation retains the existing current-email/target/Completed branch; a success rotates the stamp as before. A pending generation mismatch returns the existing generic400, never a valid pending profile-mutation projection. Expiry is not extended; issuance still supersedes the previous action of that purpose. This does not eliminate an administrator/security mutation AFTER the pending snapshot read, nor the existing consume-before-identity-save failure window.

## Compatibility and rollout matrix

| State | Candidate result | Historical RED and final GREEN evidence |
| --- | --- | --- |
| Same nonblank stamp, same normalized email/target, restart | Pending validation/one completion succeeds; replay400 | 2 HTTP controls pass. |
| Password change or administrator stamp rotation before lookup | Pending validate/complete400; no consumption or identity mutation | 6 genuine HTTP RED cases (old200/204), now GREEN including persisted no-effects assertions. |
| Original identity email changes without stamp rotation | Old change-email token400 | 1 genuine HTTP RED (old204), now GREEN. |
| Stamp NULL or empty, unchanged after issuance | New typed binding allows existing migrated behavior; issuance leaves stamp unchanged, completion rotates it | 4 compatibility controls pass; explicitly not original provider NULL parity. |
| Stamp NULL→empty | Typed generations differ;400/no consumption | 2 genuine HTTP RED (old204), now GREEN. |
| Historical pending row with BoundSecurityStamp NULL |400/no unbound fallback; request a new link through normal flow | 2 genuine HTTP RED (old204), now GREEN. |
| Malformed, unknown-version or uppercase persisted binding |400/no consumption, identity unchanged | 6 genuine HTTP RED (old204), now GREEN. |
| Independently literal persisted digest for each purpose | Exact69-character ceg1 binding, RecoveryVersionNULL, normal completion | 2 genuine RED (oldNULL binding), now GREEN; literals derive from fixed JSON frame, not a production helper. |
| Old consumed change-email row with current identity email equal target | Existing Completed projection/profile reconciliation remains | Restart/consumed projection control passes; no new distributed receipt guarantee. |
| Expired, wrong email/purpose, anonymous, bad signature, missing permission | Existing generic400/401/403, no writes | 9 HTTP controls pass. |
| Reissue after rotation | Previous token rejected, new token completes current generation | 2 HTTP controls pass. |
| Unknown confirmation account | Internal Accepted=true/token=null; no state; Web masks account knowledge | 1 HTTP control passes. |

No new migration is proposed; the existing employee recovery additive migration already supplies the column and is part of current runtime's mapped schema. This does NOT authorize applying that migration anywhere. An older writer/reader ignores or omits binding: mixed-version completion is unsafe. Before any future rollout, operators must coordinate/drain old issuance AND completion readers/writers, then deploy matching code and reissue outstanding unbound pending links through existing flows. No fallback, lifetime extension, persistent backfill, activation, grants, email delivery or deployment is authorized by this design. Null/blank migrated rows need no silent stamp data repair.

## Executed evidence and limits

New file `Legacy.Maliev.AuthService.Tests/CustomerEmailGenerationHttpTests.cs`: actual Production host, ordinary RS256 middleware and signed fixture JWTs, real controllers/registered services, isolated PostgreSQL18. No fake auth handler, IAM success or provider request. Synthetic signed fixture authority is not a claim about production service grants. Existing Postgres fixture is reused without edits; each new host clears only its actual-DI pools after disposal, and each new seed fixture clears only its own pools. No ClearAllPools/configuration/connection-limit change.

| Phase | Outcome | Artifact |
| --- | --- | --- |
| Clean baseline after Release0W0E |446PASS,0fail/skip | `TestResults/email-generation-baseline/baseline.trx` |
| Initial focused proof |12PASS/6genuineRED | `TestResults/email-generation-red/red.trx` |
| Added null/blank controls |16PASS/6genuineRED | `TestResults/email-generation-red-final/red.trx` |
| First combined run |450PASS/14 NEW setup errors (Npgsql53300), all446 old tests passed | `TestResults/email-generation-full-red/full-red.trx`; excluded as product proof |
| Incomplete pool repair combined run |454PASS/14 NEW setup/admission500 failures, all446 old tests passed | `TestResults/email-generation-full-red-final/full-red.trx`; excluded as product proof |
| Actual-DI lifecycle repaired, expanded focused proof |18PASS/11genuine assertion RED,0errors/skips | `TestResults/email-generation-red-review/red.trx` |
| Final unfiltered diagnostic |464PASS/11genuine assertion RED,0errors/skips; all446 original tests retained | `TestResults/email-generation-full-red-review/full-red.trx` |
| Additional binding contract proof before runtime |8genuine assertion RED,0errors/skips | `TestResults/email-generation-binding-red/binding-red.trx` |
| Fresh candidate Release build |0warnings/0errors with exact private pins | Direct Tests csproj command below |
| Final candidate focused |37PASS,0fail/skip | `TestResults/email-generation-green-focus/focus.trx` |
| Final candidate unfiltered |483PASS,0fail/error/skip; all446 original names retained/passing | `TestResults/email-generation-green-full/full.trx` |

On historical RED, four stale completion tests reached actual204 rather than expected400; two stale validation tests reached actual200 rather than400; five binding-generation cases reached actual204 rather than400. The first expected-status assertion failed, so subsequent no-consumption assertions were NOT claimed reached in those diagnostic runs. Final GREEN reaches those assertions. Passing controls independently assert persisted state and normal response contracts. Candidate acceptance remains with root, not a production/provider claim.

Commands: direct Tests csproj Release build with `-p:UseLocalMalievDependencies=true -p:MalievWorkspaceRoot=B:/maliev-legacy/.worktrees/auth-customer-email-generation-20261001/TestResults/.private`; `dotnet test` same csproj `-c Release --no-build`, focused `--filter FullyQualifiedName~CustomerEmailGenerationHttpTests`, final unfiltered, unique `--logger trx` and artifact directories above. Whole-solution `dotnet format Legacy.Maliev.AuthService.slnx --verify-no-changes --no-restore` passed with those same private dependency environment properties; `git diff --check` and redacted gitleaks scans of the new test and docs passed. Final TRX comparison retained every original baseline test name: zero missing and zero original failures. No old tests changed or waived. API80/coverage, full production-derived Aspire/browser/provider delivery, stamped races, distributed identity/action atomicity, and discovered cross-kind refresh revocation remain separate gates. Auth90/97/108/112 remain open.

Unexcluded coverage artifact: `TestResults/email-generation-green-full/d3c10cd2-8b7a-4a59-a6cd-246d736489ba/coverage.cobertura.xml`. Raw line rates: API52.63%, Application98.13%, Domain100%, Infrastructure94.93%, CompatibilityContracts0%, ServiceDefaults17.61%. The API80 gate is not met or waived. No exclusions or denominator changes were introduced.

Static boundaries: API/DTO/routes/permissions unchanged; Domain/migrations/schema unchanged; no message contracts or transport changes; .github/Docker/config unchanged; exact private dependency commits remain clean. Whole-solution formatting and diff check passed. Five service projects' transitive NuGet vulnerability audit reports no vulnerable packages from the current source. JWT signing-resource scan and changed-runtime/new-test/docs redacted gitleaks scans passed. Whole-tree credential scan reports seven unchanged synthetic connection-string fixture findings: AuthenticationServiceTests.cs:186; CustomerIdentityAuthorizationTests.cs:268,269,270; InvoiceDelegationContractTests.cs:192,193,194. These are disclosed baseline findings, not silently suppressed or modified.

Owned changed files at candidate freeze: CustomerSelfService.cs, the new HTTP fixture and this document only. Root independently reviews the exact runtime/RED/GREEN evidence before integration. No live output handles remain at handoff. No commits, pushes, GitHub writes, persistent DDL/data, credentials, deployment or original-source changes occurred.

## Independent root acceptance

Root independently inspected the three-file candidate, current producers/consumers,
fresh PostgreSQL query paths, historical RED TRX counters and typed generation grammar.
Independent SHA256 of the two literal JSON frames reproduced both golden digests without
calling the production helper. Direct test-project Release compilation including exact
private dependencies passed zero warnings/errors with warnings-as-errors. Focus37 and
unfiltered483 tests passed zero failures/skips (`TestResults/root-email-focus/root-focus.trx`,
`TestResults/root-email-full/root-full.trx`); all446 original tests are unchanged.
Raw unexcluded coverage is
`TestResults/root-email-full/a46bfad8-efca-411a-b326-b124e3ae398e/coverage.cobertura.xml`:
API52.63%, Application98.13%, Domain100%, Infrastructure94.93%. API80 remains open,
not waived. Whole-solution formatting, actionlint, five transitive package vulnerability
audits, whitespace and three-file redacted scan passed (73,767 bytes/no findings).
Ignored owned artifacts are retained for review, not staged. Existing synthetic baseline
scanner findings above are disclosed and untouched. Publicationfalse was independently
observed. Protected exact-head/main CI and root integration are still required; no
production-derived data, real browser/provider, deployment or distributed-atomicity
acceptance is claimed. Cross-kind session revocation is separately tracked by Auth120.

## Required-CI clock regression and deterministic correction

Initial protected-head CI36835675932 failed one existing qualification expiry case
(482 passed/1 failed/zero skips). That fixture constructed expiration from wall time
but the service used its frozen injected clock: after slow setup, walltime-minus-one
second can still be in the service clock's future. Root read both implementations and
independently reproduced the same rejection-assertion failure without sleeps using a
five-second controlled-clock lag (`TestResults/root-clock-red/clock-red.trx`, one RED).
This is a fixture defect, not proof that runtime expiry checks accept expired sessions.

Only that existing qualification test is corrected: expiration is relative to the
injected clock, a fresh PostgreSQL read asserts expiration precedes that clock, and a
delayed-setup case is retained. Existing deny/no-alternate-session/no-cache assertions
are not weakened, skipped or retried. No qualification runtime code changed. Fresh
direct Release0W0E, focused48 and full484 passed zero failures/skips, followed by whole
format/diff checks (`TestResults/root-clock-green/root-clock-green.trx`,
`TestResults/root-clock-full/root-full.trx`). All446 original cases remain and pass;
one fixture now uses the correct clock, the other445 existing test cases are unchanged.
Prior unexcluded483 coverage remains identified as historical evidence, not a new484
coverage measurement. API80 remains explicitly tracked in Auth122. Corrected document
permission is the exact existing `legacy-auth.customer-self-service` constant, not a
new `.use` capability. Final exact-head/main CI must pass before integration.
