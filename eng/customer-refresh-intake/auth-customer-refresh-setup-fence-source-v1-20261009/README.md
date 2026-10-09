# Customer refresh initial-password setup fence

Source preparation only, based on Auth85a00d4. Ten authored regression cases are
unbuilt and unrun; three are predicted to fail before the fix. No native RED or
GREEN evidence is claimed. No commit/push, data, deployment or external changes.

The existing login setup gate could be bypassed by a current customer refresh
family after PasswordSetupRequired became true without a stamp change. The
reader now denies that customer before rotation; the application independently
denies a setup-required customer returned after rotation and revokes its family
before token issuance. Employee and other-family behavior are retained.

Original e25c833 Web login, temporary credential marker and initial-password
tests prove the setup-before-sign-in behavior. They are Web-owned evidence.
Original Auth checkpoint135e Basic token producer lacks a refresh contract;
this adaptation does not close its historical LINE consumer obligation.
manifest.json records exact SHA, parents, paths, blobs and consumer byte pins.

Source review and git diff --check passed. The next validation must build the
affected Auth projects with zero warnings/errors, run CustomerRefreshAdmissionTests,
LegacyIdentityReaderTests and RefreshSessionIdentityBoundaryHttpTests, then the
Auth suite, format/static checks and required exact-head hosted validation.
PostgreSQL/resource authority and current4GiB admission are prerequisites.
The candidate remains uncommitted pending that evidence; prior hosted exceptions
were already consumed by their explicitly approved corrections.
