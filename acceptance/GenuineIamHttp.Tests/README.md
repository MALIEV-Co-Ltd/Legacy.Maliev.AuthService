# Genuine Auth to IAM HTTP acceptance

This separate suite contains eleven HTTP cases plus 17 cleanup/output fault controls,
and preserves the existing 935-case Auth suite and
761-case Defaults suite. It exercises actual Auth HTTP issuance, the dedicated
Defaults exchange/handler, and the original IAM production Program, JWT bearer,
permission authorization, live-check guard, and scoped persisted resolver.

Original IAM, Aspire, messaging and accepted Auth/Defaults/Contracts sources are extracted from exact Git objects
into a fresh ignored build copy by `eng/Prepare-GenuineIamHttpSource.ps1`.
Their runtime sources and schemas are not transformed. Independent process build
graphs separate original IAM/Aspire MassTransit 8.x from accepted Auth/Defaults 9.x.
The genuine IAM host serves actual loopback Kestrel HTTP. No original repository is
edited. The isolated accepted Defaults checkout must be exactly
`7b3099bf67d0f17e56cfdb3dcf36541304abaac2`.

The isolated PostgreSQL 18 container receives the original IAM migrations and
one synthetic principal/direct binding. Redis is disabled through supported
configuration; bypassCache requests must report fromCache=false. Only background
registration, seeding and message transport workers are omitted in the fixture;
HTTP authentication and permission-resolution services are retained. This does
not prove Redis refresh behavior, live enrollment, deployments or the full
financial join. The caller-bearer case uses an untrusted incoming bearer marker,
not a real interactive session.

Refresh checks submit the Auth-issued service JWT to Auth refresh (400 from its
maximum-length validation), a valid-shaped unknown token to Auth's real
PostgreSQL refresh store (401), and the service JWT to genuine IAM's token
refresh endpoint (401 through the supported memory cache). A separate disposable
`auth_refresh` database holds the real Auth context. No refresh session or IAM
authority may change. These checks do not establish Redis refresh behavior.

The normal Auth delivery graph retains its existing Defaults revision. This
separate acceptance graph uses committed Auth `88e4309` with Defaults `7b3099b`
in an isolated source copy; it does not implicitly repin a production image.

After resource admission, set MalievWorkspaceRoot to the absolute
`.genuine-iam-source` directory and build before testing:

```powershell
./eng/Prepare-GenuineIamHttpSource.ps1 -CommittedSourceRoot <exact-checkouts-root>
dotnet build acceptance/GenuineIamHost/GenuineIamHost.csproj -c Release -p:GITHUB_ACTIONS=false -p:UseLocalMalievDependencies=true
dotnet build acceptance/GenuineIamHttp.Tests/GenuineIamHttp.Tests.csproj -c Release -p:GITHUB_ACTIONS=false -p:UseLocalMalievDependencies=true
dotnet test acceptance/GenuineIamHttp.Tests/GenuineIamHttp.Tests.csproj -c Release --no-build --no-restore -p:GITHUB_ACTIONS=false -p:UseLocalMalievDependencies=true --logger "trx;LogFileName=genuine-iam-http.trx"
# Set GITHUB_ACTIONS=false and UseLocalMalievDependencies=true in the process
# environment before running format against the test source.
dotnet format acceptance/GenuineIamHttp.Tests/GenuineIamHttp.Tests.csproj --verify-no-changes --no-restore --include acceptance/GenuineIamHttp.Tests/GenuineIamHttpTests.cs
```

The fixture serializes its cases, caps PostgreSQL at 512 MiB/one CPU, binds its
published port to loopback, labels ownership/run/15-minute lease, records actual
container start state, and disposes hosts before removing the exact container.
Storage acceptance requires the exact Engine tmpfs map and an independent
`/proc/self/mountinfo` observation of writable tmpfs at `/var/lib/postgresql`
with a 128-MiB limit, both at startup and before removal. The observed image ID
must remain unchanged. The stock image's sole volume declaration at that path
is accepted only when masked by this observed tmpfs; unknown declarations and
actual bind, named-volume or other persistent mounts fail acceptance.
Nested mounts below the PostgreSQL target also fail the kernel attestation.
Only the sanitized matching kernel record is retained. A storage policy failure
fails the suite independently of successful exact-container removal; container
absence alone does not prove non-persistent storage.
Docker helpers have owned handles, 64-K-character caps per output stream,
15-second command deadlines (two seconds for kernel observations) and bounded
reaping. Cleanup attempts every resource independently and records unfinished
ownership on failure. A helper cleanup or receipt failure propagates independently,
retains its process/readers/deadline handles and blocks further Docker commands.
Only bounded independent exit/readers verification releases quarantine; recovery
preserves the original failure and cannot accept the suite. Shared-path fault
controls verify blocked stop/remove and safe cleanup after a policy mismatch.
Three native process controls exercise birth metadata, reader setup/reap and
kill failures through the same production lifecycle. Every acquired stream,
deadline and process handle closes explicitly after its operations settle;
final receipts record actual disposition. IAM stdin writes and flushes remain
owned until settled, and PostgreSQL removal requires IAM quiescence.
Only an exact daemon report for the owned ID proves
container absence; daemon/CLI errors do not. Retained
resource receipts contain container IDs/state only, never connection strings,
credentials, JWTs or customer data. A finite runner/test timeout is also required.

The standard Ubuntu hosted workflow builds each graph with warnings as errors,
runs the eleven HTTP focus cases and 28 dedicated-suite cases, and verifies
scoped formatting. The original normal Auth coverage/security gates remain.
Expected counts describe discovery only; hosted results are required before
acceptance. Keys/credentials/connection strings/JWTs never enter process receipts.
