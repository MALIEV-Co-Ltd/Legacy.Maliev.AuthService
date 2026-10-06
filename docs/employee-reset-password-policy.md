# Employee reset password validation

Original checkpoint `135e526d0dab85c415b3afdcefd7b70fe2c82e2f` uses
`UserManager<ApplicationEmployee>.ResetPasswordAsync` in
`Maliev.Intranet/Pages/Employees/ResetPassword.cshtml.cs` (source SHA256
`af20fc807a595933ae95b72e469f9e149351f444473952254f0e9d2ea2a96024`).
Its Intranet `ServiceExtensions.cs` (SHA256
`d754801bb5251d0761c730c3db0a0c2adad75fcee0dc206f73b8ff33eb817536`)
sets minimum length six and six distinct UTF-16 characters, with composition
requirements disabled. Web has a separate eight-character/one-distinct policy.

The new-effect branch of `EmployeeSelfService.ApplyIdentityEffectAsync` checks
that policy under the identity row lock, before hashing or changing any fields.
It retains the existing request maximum of 1024. Rejection rolls back the Auth
reservation and preserves the identity, challenge, receipts and sessions. A
valid password can still use the same unconsumed challenge. Successful reset
retains the existing hash, stamp rotation, accounting reset and old-session
revocation behavior.

An existing committed effect is inspected before new-write validation. Its
owned token, purpose, email, identity and before-stamp binding plus password
payload proof remain mandatory. Thus an independently seeded, already committed
weak-password receipt can finalize without rewriting its hash or stamps. A
different password is denied; terminal replay remains denied. No blanket DTO
attribute or entry-point guard prevents recovery of these committed effects.

The inspected Intranet consumer at
`3be71d0fe00da8bb998ea86729061722aa1f51f0` posts Email, Token, Password and
ConfirmPassword to `/bff/employee-recovery/password-reset/complete`. Its BFF
validates confirmation and forwards only Email, Token and Password to
`/auth/v1/employee-self-service/password-reset/complete` with its existing
service authentication. Auth returns 204 or generic 400, which the BFF maps to
its existing result. No consumer, DTO, route, permission, schema or dependency
pin changes are included.

Four new Production HTTP/PostgreSQL cases cover rejected low-distinct, short,
empty, null and 1025-character inputs with complete before/after snapshots;
six-character, 1024-character and surrogate-pair UTF-16 boundaries; one-time
effect/session revocation; and an independently constructed Identity V2 weak
receipt. Real RS256 middleware validates the fixture service principal. The
existing separately tested background worker is disabled in this fixture to
keep pending-receipt windows deterministic. This does not claim token-provider
interchangeability, complete UserManager parity, live data acceptance or worker
deployment readiness.

This slice depends on the administrative password-policy producer. Publication
waits for its acceptance and normal current-main integration, followed by hosted
build, focused reset tests, affected suite, static checks and boundary evidence.
