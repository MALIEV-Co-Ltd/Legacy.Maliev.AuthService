# Google Auth 1.77 dependency and audience guard - frozen candidate

Bounded child 117; dependency PR 110 may be superseded only after root acceptance
and protected-main validation. Current status: writer gates complete, frozen for
root independent acceptance. No provider credentials or Google/cloud
requests, schema activation, persistent data, GitHub writes or commits.

## Immutable graph and scope

- Auth base `8cdb634b3b0abdf18b9b826a0948dbfd98c66ea0`; recovery and qualification
  producer additions are preserved. Old bot head
  `3d29b0a55c1780d778b7b032113e8d61b670657f` was not reused.
- Private clean CI dependencies under this worktree's absolute
  `TestResults/.private`: Defaults `5c5f9479313710fa576f83d3b396442997a2fcf4`,
  Contracts `78e48ffc4ee000df0510cba5e7c7a3c4c4d539d7`.
- Sole package edit: Infrastructure `Google.Apis.Auth` 1.76.0 -> 1.77.0.
  Restored assets and actual test `.deps.json` resolve Auth, Google.Apis and
  Google.Apis.Core all at 1.77.0. Installed package metadata identifies upstream
  commit `a7d25ddf34d6e8db8a106e93dfd7baf0347d4f61`.
- Auth parents 90/97/108/112 remain open. No shared seven-field identity-claims
  record, controller, nonce/replay/domain policy, key, session, configuration,
  migration or deployment changes.

No AGENTS.md/CLAUDE.md was present in the owned Auth repository or its immediate
workspace parents; the user MALIEV protocol applies. Authentication and testing
skills guided the trust-boundary controls and real SDK verification. Documentation
skill's Context7 tools were unavailable, so official tagged source/release and
primary OIDC documentation were consulted directly.

## Official dependency evidence and boundary

[Official 1.77 release](https://github.com/googleapis/google-api-dotnet-client/releases/tag/v1.77.0)
identifies path-parameter hardening. The Auth source subtree is identical across
1.76/1.77 (`60a47a2ad02ddba6457a3480277c06939c907360`); Google.Apis is also
identical (`5a747df0f9ea446557a40cde9b40c74110f3dbdd`). Core differs:
`eaa4c0010ce9f7d6eb85632a4e1420773b0601ee` ->
`6622699444800840863461dbf8df1265e4c4af55`. This is not an upstream fix for the
audience diagnostic below.

File main `71adaa55be48dd7be655da0f12643ae1b1aa41e1` SDK URI/signing tests were
read-only reference evidence, not executed here and not Auth ID-token acceptance.
No unrelated RequestBuilder test was added to this Auth slice.

The Google-specific production SDK method has no public local-certificate cache
or transport injection seam. Its production adapter remains unchanged apart from
the approved reject-only precondition. Positive cryptographic controls use the
SDK's public `JsonWebSignature.VerifySignedTokenAsync<GoogleJsonWebSignature.Payload>`
with ephemeral RSA and an owned loopback JWKS HTTP endpoint, explicit two Google
issuers and the current per-application audience. This is real SDK signature,
issuer and lifetime verification plus real existing consumer claim validation;
it is not live Google certificate-fetch, account, ADC/WIF or production sign-in
proof. No reflection, global cache mutation, fake signature verdict or persisted
RSA material is used.

## Genuine pre-existing diagnostic

- Baseline 1.76 Release: zero warnings/errors; existing Google focus 15 passed;
  unfiltered original suite 391 passed, zero skips.
- New 1.76 SDK controls: 17 passed / 1 failed (additional untrusted audience).
- New 1.77 controls: 17 passed / 3 failed (missing audience, only-untrusted
  audience array, additional untrusted audience). Zero errors/timeouts/skips.
- Unfiltered 1.77 pre-repair diagnostic: 408 passed / 3 failed out of 411;
  all 391 original controls passed.

Retained TRXs: `TestResults/baseline-google-focus/baseline-google-focus.trx`,
`baseline-full/baseline-full.trx`, `sdk-176-control/sdk-176-control.trx`,
`sdk-177-diagnostic/sdk-177-diagnostic.trx`,
`sdk-177-full-diagnostic/sdk-177-full-diagnostic.trx` (all relative to TestResults).

The tagged SDK [`AudienceAsList` implementation](https://github.com/googleapis/google-api-dotnet-client/blob/v1.77.0/Src/Support/Google.Apis.Auth/JsonWebToken.cs)
only recognizes a string or `List<string>`, not the deserialized JSON array;
missing audience also yields an empty list. The SDK's audience comparison can
therefore compare an empty list. The production Google-specific wrapper delegates
to the same underlying verification code, but acceptance of a signed token on
the actual Google transport has NOT been executed or claimed.

[OIDC Core 3.1.3.7(3)](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
requires the configured client to be present and additional audiences to be
trusted. This application has exactly one configured trusted client per operation.
None of the three RED assertions was removed or weakened. The existing scalar
wrong-audience control passed, distinguishing the problematic shapes.

## Approved narrow helper design

`GoogleIdentityTokenVerifier` calls `GoogleIdentityTokenAudienceGuard.EnsureMatches`
BEFORE invoking the unchanged Google SDK. Passing the guard never authorizes
identity or bypasses signature, trusted issuer, lifetime or Google certificates.
The same pure public/documented implementation is invoked by the local SDK test
seam so it cannot silently emulate a different repaired policy.

- JWT length <=10,000 characters (Google-specific SDK's existing limit); decoded
  payload <=7,500 bytes; JSON maximum depth 16. Bounded data also bounds property
  and array iteration and parser allocations.
- Exactly three nonempty JWT segments; payload must use canonical, unpadded
  standard base64url. Only the payload is decoded by the guard.
- Root JSON object with exactly one decoded, case-sensitive `aud` property.
  Escaped-name duplicates are also rejected.
- A nonempty scalar string must exactly equal the configured client, or a
  nonempty array must contain only strings equal to that same client. No trim,
  case-folding, unknown types, missing/null/empty values or additional trust.
- All format/JSON failures become opaque `InvalidJwtException` with no original
  parser exception or token material. Existing consumer generic-error mapping
  and cancellation behavior remain unchanged.

## Early candidate proof for root review

Fresh private Release after helper/test edits: zero warnings/errors. Actual
Google/SDK focus: 61 passed, zero failures/errors/skips in
`TestResults/guard-review-focus/guard-review-focus.trx` (46 new controls + 15 old).

New controls retain all SDK signature/issuer/audience/iat/exp negatives, nonce,
subject/email requirements and generic errors. They add a valid trusted array,
bad-signature trusted array, actual production-adapter rejection of missing,
wrong, empty, duplicate/escaped-duplicate and non-string audience shapes before
provider invocation, plus size/depth/encoding rejection. Thai profile projection
and both allowed Google issuer forms remain positive controls.

The section above records the historical early review. Root subsequently read and
approved the complete helper and new test diff, then requested direct malformed
segments, canonical base64 and escaped sole audience-name controls. The runtime
helper was not changed after that review.

## Final writer gates and handoff

Executed from the owned worktree with the exact private graph:

```powershell
dotnet build Legacy.Maliev.AuthService.Tests/Legacy.Maliev.AuthService.Tests.csproj -c Release -p:UseLocalMalievDependencies=true -p:MalievWorkspaceRoot=B:/maliev-legacy/.worktrees/auth-google-177-acceptance-20261001/TestResults/.private --no-restore --nologo
dotnet test Legacy.Maliev.AuthService.Tests/Legacy.Maliev.AuthService.Tests.csproj -c Release --no-build --no-restore --filter 'FullyQualifiedName~GoogleSdk177AcceptanceTests|FullyQualifiedName~GoogleIdentityTokenValidatorTests|FullyQualifiedName~GoogleIdentityContractTests|FullyQualifiedName~GoogleAuthenticationServiceTests|FullyQualifiedName~GoogleIdentityNonceServiceTests'
dotnet test Legacy.Maliev.AuthService.Tests/Legacy.Maliev.AuthService.Tests.csproj -c Release --no-build --no-restore
```

- Fresh final Release: zero warnings/errors, all private dependencies also Release.
- Final focus: 70/70 passed, zero errors/skips, in
  `TestResults/google-177-final-focus-2/google-177-final-focus.trx`.
- Final unfiltered suite: 446/446 passed (391 original +55 new), zero failures,
  errors, timeouts, aborted or skipped tests, in
  `TestResults/google-177-final-full/google-177-final-full.trx`.
- Baseline/final TRX name comparison: zero original test names missing. No old
  test file or assertion was edited.
- The first final-focus attempt retained 69 passes/one test-setup exception in
  `TestResults/google-177-final-focus/google-177-final-focus.trx`: the equivalence
  check used IdentityModel's strict decoder, which already rejects noncanonical
  unused bits. The proof now uses standard `Convert.FromBase64String` to establish
  equivalent raw bytes; the unchanged guard-rejection assertion passes. This was
  not classified as a product RED. Earlier compile-only StringValues assertion
  diagnostics were also corrected without suppressions.
- Whole `dotnet format Legacy.Maliev.AuthService.slnx --verify-no-changes
  --no-restore`, with `UseLocalMalievDependencies=true` / the private
  `MalievWorkspaceRoot` environment: exit 0.
- `git diff --check`: exit 0. Signing-resource scan from accepted Workflows
  `503e8846390a597c267d2889b33a9c26863389b3`: exit 0.
- Gitleaks scoped Infrastructure, Tests and documentation scans: no leaks;
  history scan: 116 commits, no leaks. All scans redact values; no allow markers
  or persisted ephemeral keys were added.
- `dotnet list Legacy.Maliev.AuthService.slnx package --vulnerable
  --include-transitive`: no vulnerable packages across all five projects under
  the current package feed.

Five scoped audit dispositions: API/authorization routes and wire records are
unchanged (only invalid-token audience rejection is tightened); messaging and
migrations are untouched; Actions/CI permissions and immutable CI references are
unchanged; performance review confirms the new reject-only guard adds bounded
in-memory parsing/iteration and no I/O or database query. These are scoped code
reviews, not production performance benchmarks or new provider integration proof.

Final candidate files: Infrastructure package project, production verifier's
one-line precondition, new `GoogleIdentityTokenAudienceGuard.cs`, new
`GoogleSdk177AcceptanceTests.cs`, and this document. Outputs/clones remain private
and preserved. No live handles, commits, pushes or external mutations remain.
Root owns independent acceptance and integration. No API coverage exemption,
whole-source closure or production/Aspire/live-Google sign-in acceptance is implied.

## Independent integration review

Root read the complete runtime guard, production adapter, new tests and evidence.
Independent Release solution build passed with zero warnings/errors; its existing
solution configuration maps the two private shared dependencies to Debug, unlike
the writer's test-project Release graph. No build configuration was changed.
Root's combined SDK/validator focus passed 62 tests and the unfiltered suite passed
446 tests, zero failures/skips. TRXs are in `TestResults/root-google-177-focus`
and `TestResults/root-google-177-full`. Whole-solution formatting, five-project
vulnerability audit, scoped secret scan and whitespace checks passed. The actual
Google certificate transport positive path remains unexecuted; this limitation
is not waived by owned loopback JWKS evidence.
