# Employee challenge security-state acceptance

Baseline: Auth protected main `82c8d63dd08677a7f8ccd107c05dd6c9badbfd79`.
Source checkpoint: `4198baa6b0e7903f2b9b6e3d5d68f9d2c2b5b0db`.
Source employee callbacks: `5e2030b7339d4d9bd699fd8c3f406b71706b377d`;
initial Identity baseline: `5fac706a7983a6d359b39acbd670e6800afe020e`.
Auth issue #107 owns this bounded repair. This hardens the employee recovery
boundary implemented in Auth issue #49;
it does not reimplement the original ASP.NET Identity token decoder or resolve
other source owners. Auth #105 confirmed-email eligibility remains unchanged.

New opaque challenges retain the existing JSON routes, purposes, 24-hour expiry,
hash-only storage and atomic single-use consumption. Their digest additionally
binds the persisted security stamp and normalized employee email. A later state
change rejects the old link without consuming it. Previously issued unbound
links are rejected: request a new link. No legacy-token fallback is accepted.

Migrated null/empty/whitespace stamps are conditionally initialized against the
exact observed stamp and normalized email. A concurrent initializer or admin
change wins; the losing request returns the existing enumeration-safe accepted
response without a challenge. Retrying can issue a fresh challenge. Existing
tracked identities are reloaded before issuance/completion so an earlier tracked
snapshot cannot conceal a committed admin change.

Disposable PostgreSQL regressions cover reset/confirmation stamp and email drift,
real admin updates through another context, fresh-link/replay behavior, migrated
missing stamps, concurrent initializer/admin writes, old unbound links,
concurrent reset completion and identity-save failure/fresh-link recovery.

## Explicit limits

Identity and action/session state use separate databases. Existing completion
consumes a challenge before saving the identity, and session revocation follows
identity persistence. This change does not introduce a distributed transaction,
saga, outbox, or rollback guarantee. A failed identity save must not report
success; the consumed link stays unusable and a fresh request can recover.

Digest binding and fresh reads do not serialize an admin change that commits
after the completion read but before its identity write. Atomic security-state
comparison at the identity mutation boundary and cross-database recovery remain
pending in Auth issue #108. No claim is made about cross-database atomicity, application/browser
acceptance, production data, deployment or cutover.

No customer workflow, DTO, route, schema, lockout type/write, shared ledger or
runtime grant is changed. Auth #90, #97 and Intranet #229 remain separate gates.

## Local review evidence (2026-09-30)

Final validation used private no-fetch committed-object dependency clones at
ServiceDefaults `5c5f9479313710fa576f83d3b396442997a2fcf4` and
CompatibilityContracts `78e48ffc4ee000df0510cba5e7c7a3c4c4d539d7`, matching Auth CI.
`MalievWorkspaceRoot` pointed to this worktree's ignored `.dependencies` directory;
MSBuild project-reference readback confirmed that routing. Dependency source trees
were clean. Initial exploratory validation used newer canonical dependency trees
and is not the exact-pinned acceptance evidence.

With that environment:

- `dotnet build Legacy.Maliev.AuthService.slnx -c Release --nologo`: 0 warnings/errors,
  with project references enabled and freshly rebuilt.
- `dotnet test Legacy.Maliev.AuthService.Tests/Legacy.Maliev.AuthService.Tests.csproj -c Release --no-build --no-restore --filter 'FullyQualifiedName~EmployeeSelfServiceTests|FullyQualifiedName~EmployeeIdentityAdminTests'`: 27 passed, no failures/skips.
- The same project test command without the filter, with `--collect 'XPlat Code Coverage'`:
  257 passed, no failures/skips. Auth-owned line coverage: 2,604/3,178 = 81.94%.
- Full-solution `dotnet format --verify-no-changes --no-restore`, vulnerable-package
  audit including transitive packages, three changed-path Gitleaks scans, JWT
  signing-resource scan and `git diff --check`: passed.

Durable TRX and coverage artifacts are outside Git in
`B:/maliev-legacy/.artifacts/auth-employee-challenge-state-20260930`.
RED evidence: `red-state-drift.trx` (4 failures), `red-admin-drift.trx`
(2 failures / 4 passes), `red-bootstrap.trx` (5 failures), and
`mutation-cas-red.trx` (2 failures after temporarily removing the exact observed-stamp
predicate; restored before final validation). The original 240-test baseline passed.
The earlier expanded full run `full.trx` is retained: four later customer cases hit
disposable PostgreSQL's connection ceiling. Scoped fixture disposal now releases
only its two uniquely owned database pools; `pinned-full.trx` is the final passing run.

Root independently reviewed the runtime, all regression tests and this evidence.
With the same exact-pinned dependency environment, root Release build passed with
zero warnings/errors, focused recovery/admin tests passed 27/27 and the complete
suite passed 257/257 with zero failures/skips. Root TRXs are `root-focused.trx`
and `root-full.trx` in the artifact directory above. Protected-main integration
is still required; this is not deployment or whole Auth completion. Auth #108
remains open.
